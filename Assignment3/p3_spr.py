import time
from collections import defaultdict

from ryu.base import app_manager
from ryu.controller import handler, ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.lib.packet import ether_types, ethernet, lldp, packet
from ryu.ofproto import ofproto_v1_3
from ryu.topology import event
from ryu.topology.api import get_link, get_switch


class MSTSpanningTree(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MSTSpanningTree, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.adj = defaultdict(set)
        self.mst = defaultdict(set)
        self.link_delays = {}
        self.previous_switch = {}
        print("Controller Initialized.")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        dpid = datapath.id
        self.datapaths[dpid] = datapath

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [
            parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)
        ]
        self.add_flow(datapath, 0, match, actions)
        print(f"Switch {dpid} connected and table-miss flow installed.")

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
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
        self.get_topology_data()
        self.get_all_pair_shortest_path()
        self.compute_mst()
        self.print_mst()

    def get_topology_data(self):
        switch_list = get_switch(self, None)
        self.adj = defaultdict(set)
        link_list = get_link(self, None)

        for s1 in switch_list:
            for s2 in switch_list:
                if s1 == s2:
                    self.link_delays.setdefault(s1, {})[s2] = 0
                else:
                    self.link_delays.setdefault(s1, {})[s2] = -1

        for link in link_list:
            src = link.src.dpid
            dst = link.dst.dpid
            self.adj[src].add(dst)
            self.adj[dst].add(src)
            port = self.get_port(src, dst)
            self.send_lldp_packet(src, port)
            print(f"Send LLDP Packet : from {src} to {dst}  using {port} of {src}")
        print(f"Adjacency List Updated: {dict(self.adj)}")

    def send_lldp_packet(self, datapath, port_no):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        timestamp = time.time()

        pkt = packet.Packet()
        eth = ethernet.ethernet(
            dst=lldp.LLDP_MAC_NEAREST_BRIDGE,
            src=datapath.ports[port_no].hw_addr,
            ethertype=ether_types.ETH_TYPE_LLDP,
        )

        lldp_pkt = lldp.lldp(
            tlv_list=[
                lldp.ChassisID(
                    subtype=lldp.ChassisID.SUB_LOCALLY_ASSIGNED,
                    chassis_id=str(datapath.id),
                ),
                lldp.PortID(
                    subtype=lldp.PortID.SUB_PORT_COMPONENT, port_id=str(port_no)
                ),
                lldp.TTL(ttl=120),
            ]
        )

        pkt.add_protocol(eth)
        pkt.add_protocol(lldp_pkt)
        pkt.add_protocol(packet.Packet(raw=str(timestamp)))

        pkt.serialize()

        actions = [parser.OFPActionOutput(port_no)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=pkt.data,
        )
        datapath.send_msg(out)

        self.logger.info(
            f"LLDP packet with timestamp {timestamp} sent on port {port_no}"
        )

    def get_all_pair_shortest_path(self):
        switch_list = get_switch(self, None)
        for intermidiate in switch_list:
            for src in switch_list:
                for dst in switch_list:
                    self.link_delays[src][dst] = min(
                        self.link_delays[src][dst],
                        self.link_delays[src][intermidiate],
                        self.link_delays[intermidiate][dst],
                    )
        for src in switch_list:
            for dst in switch_list:
                print(self.link_delays[src][dst] + 100 * "-")

    def compute_mst(self):
        """Compute MST using Kruskal's algorithm."""
        parent = {}
        rank = {}

        def find(u):
            while parent[u] != u:
                parent[u] = parent[parent[u]]
                u = parent[u]
            return u

        def union(u, v):
            u_root = find(u)
            v_root = find(v)
            if u_root == v_root:
                return False
            if rank[u_root] < rank[v_root]:
                parent[u_root] = v_root
            else:
                parent[v_root] = u_root
                if rank[u_root] == rank[v_root]:
                    rank[u_root] += 1
            return True

        for node in self.adj:
            parent[node] = node
            rank[node] = 0

        edges = []
        for src in self.adj:
            for dst in self.adj[src]:
                if src < dst:
                    edges.append((src, dst))

        edges.sort()

        self.mst = defaultdict(set)

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
            lldp_pkt = pkt.get_protocol(lldp.lldp)
            if lldp_pkt:
                current_time = time.time()
                if pkt.haslayer(packet.Packet):
                    sent_timestamp = float(pkt[packet.Packet].load.decode())
                    delay = (current_time - sent_timestamp) * 1000
                    dst = eth.dst
                    src = eth.src
                    self.link_delays[src][dst] = delay
                    self.link_delays[dst][src] = delay
                    self.logger.info(f"Link delay: {delay:.2f} ms")
                return

        if eth.ethertype == ether_types.ETH_TYPE_IPV6:
            return

        dst = eth.dst
        src = eth.src

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        print(f"Packet in on switch {dpid}: src={src}, dst={dst}, in_port={in_port}")

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
            actions = [parser.OFPActionOutput(out_port)]
            match = parser.OFPMatch(eth_dst=dst)
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
            actions = []

            switch_ports = set(self.get_switch_ports(dpid))

            mst_ports = set()
            if dpid in self.mst:
                for neighbor in self.mst[dpid]:
                    port = self.get_port(dpid, neighbor)
                    if port:
                        mst_ports.add(port)

            host_ports = switch_ports - self.get_all_link_ports(dpid)

            for port in host_ports:
                if port != in_port:
                    actions.append(parser.OFPActionOutput(port))

            for port in mst_ports:
                if port != in_port:
                    actions.append(parser.OFPActionOutput(port))

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
        link_list = get_link(self, None)
        for link in link_list:
            if link.src.dpid == src_dpid and link.dst.dpid == dst_dpid:
                return link.src.port_no
        return None

    def get_switch_ports(self, dpid):
        switch_list = get_switch(self, None)
        for switch in switch_list:
            if switch.dp.id == dpid:
                ports = [port.port_no for port in switch.ports]
                print(f"Switch {dpid} ports: {ports}")
                return ports
        return []

    def get_all_link_ports(self, dpid):
        ports = set()
        link_list = get_link(self, None)
        for link in link_list:
            if link.src.dpid == dpid:
                ports.add(link.src.port_no)
            elif link.dst.dpid == dpid:
                ports.add(link.dst.port_no)
        print(f"Switch {dpid} link ports: {ports}")
        return ports
