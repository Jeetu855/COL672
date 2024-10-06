from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.lib.dpid import dpid_to_str
from ryu.lib.packet import ether_types, ethernet, packet
from ryu.ofproto import ofproto_v1_3


class LearningSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LearningSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = (
            {}
        )  

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id

        print(f"Switch connected: {dpid_to_str(dpid)}")

        
        if dpid not in self.mac_to_port:
            self.mac_to_port[dpid] = {}

        match = parser.OFPMatch()
        actions = [
            parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)
        ]
        self.add_flow(datapath, 0, match, actions)
        print(f"Table-miss flow entry installed for {dpid_to_str(dpid)}")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        src = eth.src
        dst = eth.dst

        print(
            f"Packet in: src={src} dst={dst} dpid={dpid_to_str(dpid)} in_port={in_port}"
        )

        
        if dpid not in self.mac_to_port:
            self.mac_to_port[dpid] = {}

        
        self.mac_to_port[dpid][src] = in_port
        print(f"Learned MAC {src} on port {in_port} for switch {dpid_to_str(dpid)}")

        
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
            print(
                f"Found destination MAC {dst} on port {out_port} for switch {dpid_to_str(dpid)}"
            )
        else:
            
            out_port = ofproto.OFPP_FLOOD
            print(
                f"Destination MAC {dst} unknown, flooding on switch {dpid_to_str(dpid)}"
            )

        actions = [parser.OFPActionOutput(out_port)]

        
        if out_port != ofproto.OFPP_FLOOD:
            
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
      
            priority = 1
            self.add_flow(datapath, priority, match, actions)
            print(
                f"Installed flow for src={src} dst={dst} on switch {dpid_to_str(dpid)}"
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
        if out_port != ofproto.OFPP_FLOOD:
            print(f"Sent packet out on port {out_port} for switch {dpid_to_str(dpid)}")
            print(100 * "*")
        else:
            print(f"Flooded packet out for switch {dpid_to_str(dpid)}")

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath, priority=priority, match=match, instructions=inst
        )
        datapath.send_msg(mod)
        print(f"Flow added: priority={priority} match={match} actions={actions}")