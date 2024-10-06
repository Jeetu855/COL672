from ryu.base import app_manager
from ryu.controller import handler, ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.lib.packet import ether_types, ethernet, packet
from ryu.ofproto import ofproto_v1_3
from collections import defaultdict
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
        print("Controller Initialized.")

    def log_switch_connection(self, datapath):
        print(f"Switch {datapath.id} connected and table-miss flow installed.")

    def print_mac_table(self):
        print("MAC Address Table:")
        for dpid in self.mac_to_port:
            print(f"Switch {dpid}:")
            for mac, port in self.mac_to_port[dpid].items():
                print(f"  MAC {mac} -> Port {port}")

    def print_topology(self):
        print("Current Topology Adjacency List:")
        for src in self.adj:
            print(f"  Switch {src}: {self.adj[src]}")

    def print_mst(self):
        print("Minimum Spanning Tree (MST) Adjacency List:")
        for src in self.mst:
            print(f"  Switch {src}: {self.mst[src]}")

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
        self.log_switch_connection(datapath)

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
        event_handler = {
            event.EventSwitchEnter: self.handle_switch_enter,
            event.EventSwitchLeave: self.handle_switch_leave,
            event.EventLinkAdd: self.handle_link_add,
            event.EventLinkDelete: self.handle_link_delete,
        }
        handler = event_handler.get(type(ev))
        if handler:
            handler(ev)
        else:
            print("Unknown topology event.")

        self.update_topology()

    def handle_switch_enter(self, ev):
        print(f"Switch Enter: {ev.switch.dp.id}")

    def handle_switch_leave(self, ev):
        print(f"Switch Leave: {ev.switch.dp.id}")

    def handle_link_add(self, ev):
        print(f"Link Add: {ev.link.src.dpid} -> {ev.link.dst.dpid}")

    def handle_link_delete(self, ev):
        print(f"Link Delete: {ev.link.src.dpid} -> {ev.link.dst.dpid}")

    def update_topology(self):
        self.get_topology_data()
        self.compute_mst()
        self.print_mst()

    def get_topology_data(self):
        switch_list = get_switch(self, None)
        self.adj = defaultdict(set)
        link_list = get_link(self, None)
        for link in link_list:
            src = link.src.dpid
            dst = link.dst.dpid
            self.adj[src].add(dst)
            self.adj[dst].add(src)
        self.print_topology()

    def compute_mst(self):
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

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
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

        if eth.ethertype in [ether_types.ETH_TYPE_LLDP, ether_types.ETH_TYPE_IPV6]:
            return

        dst = eth.dst
        src = eth.src

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        print(f"Packet in on switch {dpid}: src={src}, dst={dst}, in_port={in_port}")
        self.print_mac_table()

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