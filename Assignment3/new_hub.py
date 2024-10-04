from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.lib.dpid import dpid_to_str
from ryu.lib.packet import ethernet, packet
from ryu.ofproto import ofproto_v1_3


class HubController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(HubController, self).__init__(*args, **kwargs)
        print("Hub Controller initialized.")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Handles switch connection and installs table-miss flow entry."""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id

        print(f"Switch connected: DPID={dpid_to_str(dpid)}")

        # Define table-miss flow entry: send unmatched packets to controller
        match = parser.OFPMatch()  # Matches all packets
        actions = [
            parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)
        ]
        priority = 0  # Lowest priority

        # Create and send Flow-Mod message to install table-miss entry
        self.add_flow(datapath, priority, match, actions)
        print(f"Table-miss flow installed on switch: DPID={dpid_to_str(dpid)}")

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        """Helper function to add a flow to the switch."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
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
        print(
            f"Flow-Mod sent to switch: DPID={dpid_to_str(datapath.id)}, Priority={priority}"
        )

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """Handles incoming packets that do not match any flow."""
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        src = eth.src
        dst = eth.dst

        print(f"Packet-In on switch: DPID={dpid_to_str(dpid)}")
        print(f"Source MAC: {src} | Destination MAC: {dst} | Ingress Port: {in_port}")

        # Define actions: Flood out of all ports except ingress port
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]

        # If the packet was buffered by the switch, include the buffer_id
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        # Create and send Packet-Out message to flood the packet
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data,
        )
        datapath.send_msg(out)
        print(
            f"Packet flooded out of switch: DPID={dpid_to_str(dpid)} via ports (all except {in_port})"
        )

        # Log traversal information
        self.log_traversal(dpid, src, dst, in_port)

    def log_traversal(self, dpid, src, dst, in_port):
        """Logs the traversal details of each packet."""
        print(f"Packet traversed through switch: DPID={dpid_to_str(dpid)}")
        print(f"Packet details: {src} -> {dst} | Ingress Port: {in_port}")
        print("--------------------------------------------------")
