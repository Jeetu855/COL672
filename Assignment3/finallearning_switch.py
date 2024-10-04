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
        )  # {switch_datapath_id: {mac_of_host: port_on_which_host_sends_packet}}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id

        print(f"Switch connected: {dpid_to_str(dpid)}")

        # Initialize the MAC to port mapping for this datapath
        if dpid not in self.mac_to_port:
            self.mac_to_port[dpid] = {}
        #            self.mac_to_port = {  when a switch with dpid 1 connects to controller for first time
        # this is how its entry looks like in the mac_to_port attribute
        #    1: {}  # Switch1's DPID is 1, and an empty dictionary is created for it
        # }
        # 1: { later on when it connects again, it looks like this
        #        "00:00:00:00:00:01": 1  # MAC address of Host1 is connected to port 1 on Switch1
        #    }
        # Install table-miss flow entry
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

        # Ignore LLDP packets
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        src = eth.src
        dst = eth.dst

        print(
            f"Packet in: src={src} dst={dst} dpid={dpid_to_str(dpid)} in_port={in_port}"
        )

        # Initialize MAC to port mapping for this datapath if not present
        if dpid not in self.mac_to_port:
            self.mac_to_port[dpid] = {}

        # Learn the source MAC address to avoid flooding next time
        self.mac_to_port[dpid][src] = in_port
        print(f"Learned MAC {src} on port {in_port} for switch {dpid_to_str(dpid)}")

        # If destination MAC is known, set the output port to the learned port
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
            print(
                f"Found destination MAC {dst} on port {out_port} for switch {dpid_to_str(dpid)}"
            )
        else:
            # Destination MAC is unknown, flood the packet
            # This situation would occur when the destination MAC address is not yet known to the
            # switch, which happens when the switch has not yet learned the MAC address of the
            # destination host through previous traffic.
            # Even though the switch knows about its ports, it doesn't initially know
            # which hosts (with specific MAC addresses) are connected to those ports.
            out_port = ofproto.OFPP_FLOOD
            print(
                f"Destination MAC {dst} unknown, flooding on switch {dpid_to_str(dpid)}"
            )

        actions = [parser.OFPActionOutput(out_port)]

        # If the destination port is known, avoid flooding by setting appropriate actions
        if out_port != ofproto.OFPP_FLOOD:
            # Install a flow to avoid packet_in next time
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # Give high priority to this flow
            priority = 1
            self.add_flow(datapath, priority, match, actions)
            print(
                f"Installed flow for src={src} dst={dst} on switch {dpid_to_str(dpid)}"
            )

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        # Construct and send the packet out message
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


# we are creating an object of the controller, not the switch. However, the controller
# interacts with multiple switches, and for each switch connected to the controller, the
# Ryu framework internally creates an object representing the switch (called datapath).
# The main class in your Ryu application is the controller. This controller is a Python
# class (in your case, LearningSwitch) that extends the base class RyuApp. When you run
# the controller using ryu-manager, an instance of this class is created by the Ryu
# framework. This class represents the logic of your software-defined networking (SDN)
# controller and can handle OpenFlow events, such as when a switch
