from collections import defaultdict

from ryu.base import app_manager
from ryu.controller import handler, ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.lib.packet import ether_types, ethernet, packet
from ryu.ofproto import ofproto_v1_3
from ryu.topology import event
from ryu.topology.api import get_link, get_switch


class MSTSpanningTree(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MSTSpanningTree, self).__init__(*args, **kwargs)
        self.mac_to_port = {}  # {dpid: {mac: port}}
        self.datapaths = {}  # {dpid: datapath}
        self.adj = defaultdict(set)  # adjacency list {dpid: set(neighbor_dpid)}
        self.mst = defaultdict(set)  # MST adjacency list {dpid: set(neighbor_dpid)}
        print("Controller Initialized.")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Install table-miss and ARP flow entries for new switches."""
        datapath = ev.msg.datapath
        dpid = datapath.id
        self.datapaths[dpid] = datapath

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Install table-miss flow entry
        match = parser.OFPMatch()
        actions = [
            parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)
        ]
        self.add_flow(datapath, 0, match, actions)
        print(f"Switch {dpid} connected and table-miss flow installed.")

        # Install flow to handle ARP packets proactively
        match_arp = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP)
        actions_arp = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        self.add_flow(datapath, 1, match_arp, actions_arp)
        print(f"ARP flow added on switch {dpid}")

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        """Helper function to add a flow entry."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id and buffer_id != ofproto.OFP_NO_BUFFER:
            mod = parser.OFPFlowMod(
                datapath=datapath,
                buffer_id=buffer_id,
                priority=priority,
                match=match,
                instructions=inst,
            )
        else:
            mod = parser.OFPFlowMod(
                datapath=datapath, priority=priority, match=match, instructions=inst
            )
        datapath.send_msg(mod)
        print(f"Flow added on switch {datapath.id}: match={match}, actions={actions}")

    @set_ev_cls(
        [
            event.EventSwitchEnter,
            event.EventSwitchLeave,
            event.EventLinkAdd,
            event.EventLinkDelete,
        ]
    )
    def topology_change_handler(self, ev):
        """Handle topology changes and recompute the MST."""
        if isinstance(ev, event.EventSwitchEnter):
            print(f"Switch Enter: {ev.switch.dp.id}")
        elif isinstance(ev, event.EventSwitchLeave):
            print(f"Switch Leave: {ev.switch.dp.id}")
        elif isinstance(ev, event.EventLinkAdd):
            print(f"Link Add: {ev.link.src.dpid} -> {ev.link.dst.dpid}")
        elif isinstance(ev, event.EventLinkDelete):
            print(f"Link Delete: {ev.link.src.dpid} -> {ev.link.dst.dpid}")

        self.update_topology()

    def update_topology(self):
        """Update the network topology and compute the MST."""
        self.get_topology_data()
        self.compute_mst()
        self.print_mst()

    def get_topology_data(self):
        """Retrieve switches and links, build adjacency list."""
        switch_list = get_switch(self, None)
        self.adj = defaultdict(set)
        link_list = get_link(self, None)
        for link in link_list:
            src = link.src.dpid
            dst = link.dst.dpid
            self.adj[src].add(dst)
            self.adj[dst].add(src)  # Undirected graph

        print(f"Adjacency List Updated: {dict(self.adj)}")

    def compute_mst(self):
        """Compute MST using Kruskal's algorithm."""
        parent = {}
        rank = {}

        def find(u):
            """Find the root of the set in which element u is."""
            while parent[u] != u:
                parent[u] = parent[parent[u]]  # Path compression
                u = parent[u]
            return u

        def union(u, v):
            """Union of two sets."""
            u_root = find(u)
            v_root = find(v)
            if u_root == v_root:
                return False  # Already in the same set
            # Union by rank
            if rank[u_root] < rank[v_root]:
                parent[u_root] = v_root
            else:
                parent[v_root] = u_root
                if rank[u_root] == rank[v_root]:
                    rank[u_root] += 1
            return True

        # Initialize disjoint sets
        for node in self.adj:
            parent[node] = node
            rank[node] = 0

        # Collect all edges (src, dst)
        edges = []
        for src in self.adj:
            for dst in self.adj[src]:
                if src < dst:  # Avoid duplicate edges
                    edges.append((src, dst))

        # Sort edges - not necessary for unweighted graphs, but kept for clarity
        edges.sort()

        # Reset MST
        self.mst = defaultdict(set)

        # Kruskal's algorithm
        for u, v in edges:
            if union(u, v):
                self.mst[u].add(v)
                self.mst[v].add(u)

        print(f"MST Adjacency List: {dict(self.mst)}")

    def print_mst(self):
        """Print the MST."""
        print("Spanning Tree:")
        printed = set()
        for u in self.mst:
            for v in self.mst[u]:
                if (u, v) not in printed and (v, u) not in printed:
                    print(f"  Switch {u} <--> Switch {v}")
                    printed.add((u, v))

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """Handle incoming packets."""
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)
        if not eth:
            return
        eth = eth[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # Ignore LLDP packets to prevent interference with topology discovery
            return

        if eth.ethertype == ether_types.ETH_TYPE_IPV6:
            # Ignore IPv6 packets (optional, depending on your needs)
            return

        dst = eth.dst
        src = eth.src

        self.mac_to_port.setdefault(dpid, {})

        # Learn the source MAC address to avoid flooding next time
        self.mac_to_port[dpid][src] = in_port

        print(f"Packet in on switch {dpid}: src={src}, dst={dst}, in_port={in_port}")

        if dst in self.mac_to_port[dpid]:
            # Unicast packet: forward to the known destination port
            out_port = self.mac_to_port[dpid][dst]
            actions = [parser.OFPActionOutput(out_port)]
            match = parser.OFPMatch(eth_dst=dst)
            # Install a flow entry to handle future packets
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, buffer_id=msg.buffer_id)
                print(
                    f"Unicast packet from {src} to {dst} on switch {dpid}, port {out_port}"
                )
                return
            else:
                self.add_flow(datapath, 1, match, actions)
                data = msg.data
                out = parser.OFPPacketOut(
                    datapath=datapath,
                    buffer_id=ofproto.OFP_NO_BUFFER,
                    in_port=in_port,
                    actions=actions,
                    data=data,
                )
                datapath.send_msg(out)
                print(
                    f"Unicast packet from {src} to {dst} on switch {dpid}, port {out_port}"
                )
        else:
            # Broadcast packet: forward to host ports and along MST edges, excluding in_port
            actions = []

            # Get all ports on the switch
            switch_ports = set(self.get_switch_ports(dpid))

            # Get ports connected to neighboring switches in the MST
            mst_ports = set()
            if dpid in self.mst:
                for neighbor in self.mst[dpid]:
                    port = self.get_port(dpid, neighbor)
                    if port:
                        mst_ports.add(port)

            # Determine host ports (ports not connected to other switches)
            host_ports = switch_ports - self.get_all_link_ports(dpid)

            # Exclude the incoming port when forwarding to host ports
            for port in host_ports:
                if port != in_port:
                    actions.append(parser.OFPActionOutput(port))

            # Forward along MST ports, excluding the incoming port
            for port in mst_ports:
                if port != in_port:
                    actions.append(parser.OFPActionOutput(port))

            # Remove duplicate ports
            unique_ports = set()
            final_actions = []
            for action in actions:
                if action.port not in unique_ports:
                    final_actions.append(action)
                    unique_ports.add(action.port)
            actions = final_actions

            if actions:
                print(
                    f"Broadcast packet from {src} on switch {dpid}, ports {[action.port for action in actions]}"
                )
            else:
                print(
                    f"No actions to perform for broadcast packet from {src} on switch {dpid}"
                )

            # Send the packet out
            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=msg.buffer_id,
                in_port=in_port,
                actions=actions,
                data=data,
            )
            datapath.send_msg(out)

    def get_port(self, src_dpid, dst_dpid):
        """Find the port number on src_dpid that connects to dst_dpid."""
        link_list = get_link(self, None)
        for link in link_list:
            if link.src.dpid == src_dpid and link.dst.dpid == dst_dpid:
                return link.src.port_no
        return None

    def get_switch_ports(self, dpid):
        """Retrieve all ports for the given switch."""
        switch_list = get_switch(self, None)
        for switch in switch_list:
            if switch.dp.id == dpid:
                ports = [port.port_no for port in switch.ports]
                print(f"Switch {dpid} ports: {ports}")
                return ports
        return []

    def get_all_link_ports(self, dpid):
        """Retrieve all ports on the switch that are connected to other switches."""
        ports = set()
        link_list = get_link(self, None)
        for link in link_list:
            if link.src.dpid == dpid:
                ports.add(link.src.port_no)
            elif link.dst.dpid == dpid:
                ports.add(link.dst.port_no)
        print(f"Switch {dpid} link ports: {ports}")
        return ports
