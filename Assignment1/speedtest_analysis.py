#!/usr/bin/env python3

import argparse
import warnings

from scapy.all import *
from scapy.layers.inet import IP, TCP

warnings.filterwarnings("ignore", category=DeprecationWarning)

ip1 = "61.246.223.11"
ip2 = "192.168.29.159"
tcp_port = 443

filtered_packets = []
downlink = []
uplink = []
total_downlink_bytes = 0
downlink_start_time = None
downlink_end_time = None
total_uplink_bytes = 0
uplink_start_time = None
uplink_end_time = None


def throughput():
    global total_downlink_bytes
    global total_uplink_bytes
    global downlink_start_time, downlink_end_time
    global uplink_start_time, uplink_end_time

    for pkt in filtered_packets:
        ip_header = pkt[IP]
        # print(pkt.time)
        pkt_time = float(
            pkt.time
        )  # some unhashable type error, need it to be int or float
        if ip_header.src == ip1 and ip_header.dst == ip2:
            downlink.append(pkt)
            # print(len(pkt))
            total_downlink_bytes += len(pkt)
            if downlink_start_time is None:
                downlink_start_time = pkt_time
            downlink_end_time = pkt_time
        elif ip_header.src == ip2 and ip_header.dst == ip1:
            uplink.append(pkt)
            total_uplink_bytes += len(pkt)

            if uplink_start_time is None:
                uplink_start_time = pkt_time
            uplink_end_time = pkt_time

    if downlink_start_time and downlink_end_time:
        downlink_time_interval = downlink_end_time - downlink_start_time

        downlink_speed_bps = (total_downlink_bytes * 8) / downlink_time_interval
        downlink_speed_mbps = downlink_speed_bps / (2**20)
        print(downlink_time_interval)
        print(50 * "*")
        print(total_downlink_bytes)
        print(50 * "*")
        print(f"Download speed in Mbps is {downlink_speed_mbps}")
        print(50 * "*")

    if uplink_start_time and uplink_end_time:
        uplink_time_interval = uplink_end_time - uplink_start_time

        print(uplink_time_interval)
        uplink_speed_bps = (total_uplink_bytes * 8) / uplink_time_interval
        uplink_speed_mbps = uplink_speed_bps / (2**20)
        print(total_uplink_bytes)
        print(50 * "*")
        print(f"Upload speed in Mbps is {uplink_speed_mbps}")
        print(50 * "*")


def filter(pcap_file):
    packets = rdpcap(pcap_file)
    # print(packets)  # gives info on number of TCP or UDP or ICMP packets
    for pkt in packets:
        if IP in pkt and TCP in pkt:
            ip_header = pkt[IP]
            tcp_header = pkt[TCP]
            if (
                (ip_header.src == ip1 and ip_header.dst == ip2)
                or (ip_header.src == ip2 and ip_header.dst == ip1)
            ) and (tcp_header.sport == tcp_port or tcp_header.dport == tcp_port):
                filtered_packets.append(pkt)

    print(f"Number of filtered packets: {len(filtered_packets)}")
    # print(f"Packet number 100 {filtered_packets[100]}")
    # print(len(packets))  # gives number of packets
    # pkt = packets[100]  # to examine the 100th packet
    # print(pkt)


def main():
    parser = argparse.ArgumentParser(description="To perform speedtest")
    parser.add_argument("pcap_file", type=str, help="The PCAP file to process")

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--plot", action="store_true", help="Run to plot the graph")
    group.add_argument(
        "--throughput",
        action="store_true",
        help="Run to calculate throughput",
    )

    args = parser.parse_args()
    filter(args.pcap_file)

    if args.plot:
        print("In mode plot")

    elif args.throughput:
        # print("In mode throughput")
        throughput()


if __name__ == "__main__":
    main()
