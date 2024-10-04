from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet

class SimpleHub(app_manager.RyuApp):
    # Specify the OpenFlow version
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleHub, self).__init__(*args, **kwargs)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        Handle switch features event to set the initial table-miss flow entry.
        This flow sends all unmatched packets to the controller.
        """
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        print(f"Switch connected: {datapath.id}")

        # Match all packets
        match = parser.OFPMatch()

        # Action to send packets to the controller
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]

        # Install the table-miss flow entry
        self.add_flow(datapath, priority=0, match=match, actions=actions)
        print(f"Installed table-miss flow on Switch {datapath.id} to send packets to controller.")

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        """
        Helper function to add a flow entry to the switch.
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Define the instruction to apply the actions
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        # Create the flow mod message
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

        # Send the flow mod message to the switch
        datapath.send_msg(mod)
        print(f"Added flow: Priority={priority}, Match={match}, Actions={actions}")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """
        Handle incoming packets sent to the controller.
        For each Packet-In, install a flow entry to flood packets with the same destination MAC.
        """
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Get the port from which the packet was received
        in_port = msg.match['in_port']

        # Parse the packet
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth is None:
            print(f"Received a non-Ethernet packet on Switch {datapath.id}, In Port {in_port}")
            return

        src_mac = eth.src
        dst_mac = eth.dst

        print(f"Packet-In on Switch {datapath.id}: In Port {in_port}, Src MAC {src_mac}, Dst MAC {dst_mac}")

        # Define the match for the flow: match on destination MAC address
        match = parser.OFPMatch(eth_dst=dst_mac)

        # Define the action to flood the packet
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]

        # Install the flow with higher priority to handle future packets with the same destination MAC
        priority = 1  # Higher than table-miss

        # Add the flow to the switch
        self.add_flow(datapath, priority, match, actions, buffer_id=msg.buffer_id)

        # If buffer_id is not set, send the packet out
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        else:
            data = None

        # Create the Packet-Out message to flood the current packet
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=msg.buffer_id,
                                  in_port=in_port,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)
        print(f"Sent Packet-Out on Switch {datapath.id}: In Port {in_port}, Action=FLOOD")