from ryu.base.app_manager import (
    RyuApp,
)  # RyuApp : The base class for all Ryu applications.

# Every Ryu controller must extend this class.
from ryu.controller import ofp_event  # ofp_event: This module contains
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.lib.dpid import dpid_to_str

# ofproto_v1_3: Defines the OpenFlow protocol version 1.3,
# used by the controller to communicate with OpenFlow switches.
from ryu.lib.packet import packet

# packet: A module that helps parse and handle network packets like Ethernet frames and IP packets.
from ryu.ofproto import ofproto_v1_3

# CONFIG_DISPATCHER: This state occurs when a switch first connects to the controller and shares its features
# (like port configurations). It’s where initial setup happens.
# MAIN_DISPATCHER: This state occurs after the switch has been fully configured and is ready to forward traffic. At this point, it
# can handle regular network events like packet forwarding.
# set_ev_cls: A decorator used to bind specific OpenFlow events to corresponding handler methods in the controller, based on the
# current dispatcher state (like CONFIG_DISPATCHER or MAIN_DISPATCHER).
# A decorator in Python is a special function that can modify or extend the behavior of another function or method
# ofproto_v1_3: Defines the OpenFlow protocol version 1.3, used by the controller to communicate with OpenFlow switches.
# decorators can be used to extend or modify a method of a class. When you apply a decorator to a
# method, it wraps the original method with additional functionality. This allows you to add behavior
# before, after, or even instead of the original method's logic without changing the method's internal code.


# OpenFlow events (like packet_in) used to handle OpenFlow protocol messages between switches and the controller.


# RyuApp is the base class for every Ryu application. When creating a custom SDN controller,
# your application must extend this class.
# By inheriting from RyuApp, your custom controller will have access to all the necessary
# functionality for managing OpenFlow switches, handling network events, and communicating with the SDN infrastructure.


class Controller(RyuApp):
    # defines a new class called Controller, which inherits from the base class RyuApp. By
    # inheriting from RyuApp, this class becomes a Ryu controller and can handle OpenFlow messages and interact with OpenFlow-enabled switches.

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    # This defines the OpenFlow protocol versions that this controller supports. In this case, the
    # controller supports OpenFlow version 1.3, as indicated by ofproto_v1_3.OFP_VERSION.

    def __init__(self, *args, **kwargs):

        # defines the constructor method (__init__) for the Controller class.
        # It initializes the object when an instance of the class is created.
        # *args and **kwargs: These are used to pass a variable number of arguments to the method. *args allows for positional arguments, while **kwargs allows for keyword arguments.
        # self refers to the instance of the class. It allows methods in the class to
        # access instance variables and other methods. In Python, self must be explicitly
        # passed as the first parameter in instance methods.
        # *args is used to pass a variable number of positional arguments to a function. It collects arguments into a tuple.
        print("Controller initialized with DEBUG logging.")
        super(Controller, self).__init__(*args, **kwargs)

        # This calls the parent class's constructor (RyuApp.__init__). This ensures that the
        # RyuApp class's initialization logic runs properly, allowing the Controller class to inherit all
        # functionality from RyuApp.

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    # The decorator helps Ryu know which method should be called when an event, like packet_in, is triggered.
    # A decorator that binds the features_handler method to the EventOFPSwitchFeatures event.
    # This event is triggered when a switch connects to the controller and sends its features (e.g., port info and capabilities).
    # The CONFIG_DISPATCHER state indicates the switch is in its configuration phase.
    # EventOFPSwitchFeatures is the specific event being handled
    # CONFIG_DISPATCHER is the state in which this event is being processed.
    def switch_features_handler(self, ev):
        # This method handles the event (ev) where the switch sends its features, typically used to install
        # a "table-miss" flow for unmatched packets.
        self.logger.info("Switch connected: {}".format(ev.msg.datapath.id))
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # datapath: Represents the switch that is connected to the controller.
        # ofproto: Provides protocol constants, such as port numbers and message types.
        # parser: Helper object to construct OpenFlow protocol messages like flow-mod or packet-out.
        match = parser.OFPMatch()
        actions = [
            parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)
        ]

        print(f"Handshake taken place with {dpid_to_str(datapath.id)}")
        self.__add_flow(datapath, 0, match, actions)

    # OFPMatch(): Matches all incoming packets (this is a "catch-all" match for packets).
    # OFPActionOutput: An OpenFlow action that specifies where packets should be sent.
    # OFPP_CONTROLLER: Tells the switch to send the packet to the controller.
    # OFPCML_NO_BUFFER: Specifies that the entire packet should be sent to the controller (not just a truncated version).
    # __add_flow: A helper method to add the flow rule to the switch’s flow table.

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        # packet_in_handler: Handles packet_in events, triggered when the switch sends a packet to the controller because no flow was matched.
        # MAIN_DISPATCHER: The state when the switch is ready to forward packets.

        msg = ev.msg
        datapath = msg.datapath
        ofproto = msg.datapath.ofproto
        parser = msg.datapath.ofproto_parser
        dpid = msg.datapath.id
        pkt = packet.Packet(msg.data)
        in_port = msg.match["in_port"]
        # msg: The OpenFlow message containing the packet.
        # datapath: Represents the switch.
        # pkt: Parses the raw packet data to extract Ethernet frames or higher-level protocols (e.g., IP, ARP).
        # in_port: The port where the packet arrived.
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        # If the packet is not buffered (indicated by OFP_NO_BUFFER), the actual packet data is
        # assigned to data. Otherwise, data is set to None.
        actions = [datapath.ofproto_parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        # This defines the flooding action. It tells the switch to forward the packet out on all ports (except the input port).
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data,
        )

        # Constructs a Packet-Out message. This message sends the packet from the controller back to
        # the switch, which will then flood the packet to all its ports.
        print("Packet received in packet_in_handler")
        datapath.send_msg(out)

        print("Sending packet out")
        # send_msg: Sends the packet-out message to the switch.
        return

    def __add_flow(self, datapath, priority, match, actions):

        ofproto = datapath.ofproto
        #  Retrieves protocol constants (e.g., flow types).
        parser = datapath.ofproto_parser
        # Used to construct OpenFlow messages.
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        # Defines actions (e.g., what to do when a packet matches the flow).
        mod = parser.OFPFlowMod(
            datapath=datapath, priority=priority, match=match, instructions=inst
        )
        # Constructs a Flow-Mod message, which contains the flow's match conditions, priority, and actions.

        print("Flow-Mod written to {}".format(dpid_to_str(datapath.id)))
        datapath.send_msg(mod)


# A packet_in message is sent from a switch to the controller when a packet arrives that
# doesn't match any flow rules in the switch's flow table. This informs the controller
# that it needs to make a forwarding decision for the packet.
# A packet_out message is sent from the controller to the switch. It instructs the switch
# on how to handle a specific packet (e.g., forward it to a particular port).
# This is typically used in response to a packet_in event.

# a packet_out message does not directly add an entry to the flow table. Instead,
# packet_out tells the switch how to forward a specific packet.
# If you want to add a flow entry to the switch's flow table, you use an OFPFlowMod message.
# This is typically done after the controller receives a packet_in event, makes a
# forwarding decision, and then adds a flow entry to handle future packets without involving the controller.
# So, a packet_out message is for immediate action, while OFPFlowMod adds a flow entry.
