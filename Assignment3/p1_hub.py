from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet

class SimpleHub(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleHub, self).__init__(*args, **kwargs)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):

        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        print(f"Switch connected: {datapath.id}")

        match = parser.OFPMatch()


        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]


        self.add_flow(datapath, priority=0, match=match, actions=actions)
        print(f"Installed table-miss flow on Switch {datapath.id} to send packets to controller.")

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser


        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]


        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath,
                                    buffer_id=buffer_id,
                                    priority=priority,
                                    match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath,
                                    priority=priority,
                                    match=match,
                                    instructions=inst)


        datapath.send_msg(mod)
        print(f"Added flow: Priority={priority}, Match={match}, Actions={actions}")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):

        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser


        in_port = msg.match['in_port']


        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth is None:
            print(f"Received a non-Ethernet packet on Switch {datapath.id}, In Port {in_port}")
            return

        src_mac = eth.src
        dst_mac = eth.dst

        print(f"Packet-In on Switch {datapath.id}: In Port {in_port}, Src MAC {src_mac}, Dst MAC {dst_mac}")


        match = parser.OFPMatch(eth_dst=dst_mac)


        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]


        priority = 1


        self.add_flow(datapath, priority, match, actions, buffer_id=msg.buffer_id)


        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        else:
            data = None


        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=msg.buffer_id,
                                  in_port=in_port,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)
        print(f"Sent Packet-Out on Switch {datapath.id}: In Port {in_port}, Action=FLOOD")