#!/usr/bin/env python3

import argparse
import warnings

import matplotlib.pyplot as plt
from scapy.all import *
from scapy.layers.inet import IP, TCP

warnings.filterwarnings("ignore", category=ImportWarning)

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

    downlink_throughput = {}
    uplink_throughput = {}

    for pkt in filtered_packets:
        ip_layer = pkt[IP]
        pkt_time = int(pkt.time)  # Round to the nearest second

        if ip_layer.src == ip1 and ip_layer.dst == ip2:
            downlink.append(pkt)
            total_downlink_bytes += len(pkt)
            downlink_throughput[pkt_time] = downlink_throughput.get(pkt_time, 0) + len(
                pkt
            )
            if downlink_start_time is None:
                downlink_start_time = pkt.time  # Timestamp of the first packet
            downlink_end_time = (
                pkt.time
            )  # Continuously update with the latest timestamp
        elif ip_layer.src == ip2 and ip_layer.dst == ip1:
            uplink.append(pkt)
            total_uplink_bytes += len(pkt)
            uplink_throughput[pkt_time] = uplink_throughput.get(pkt_time, 0) + len(pkt)
            if uplink_start_time is None:
                uplink_start_time = pkt.time  # Timestamp of the first packet
            uplink_end_time = pkt.time  # Continuously update with the latest timestamp

    if downlink_start_time and downlink_end_time:
        time_interval = downlink_end_time - downlink_start_time  # Time in seconds
        if time_interval > 0:
            download_speed_bps = (
                total_downlink_bytes * 8
            ) / time_interval  # Speed in bits per second
            download_speed_mbps = download_speed_bps / (1024 * 1024)  # Convert to Mbps
            print(50 * "*")
            print(f"Download speed in Mbps is {download_speed_mbps}")
            print(50 * "*")

    if uplink_start_time and uplink_end_time:
        time_interval = uplink_end_time - uplink_start_time  # Time in seconds
        if time_interval > 0:
            upload_speed_bps = (
                total_uplink_bytes * 8
            ) / time_interval  # Speed in bits per second
            upload_speed_mbps = upload_speed_bps / (1024 * 1024)  # Convert to Mbps
            print(50 * "*")
            print(f"Upload speed in Mbps is {upload_speed_mbps}")
            print(50 * "*")

    return downlink_throughput, uplink_throughput


def plot_throughput(downlink_throughput, uplink_throughput):
    times = sorted(set(downlink_throughput.keys()).union(set(uplink_throughput.keys())))

    downlink_speeds = [
        downlink_throughput.get(t, 0) * 8 / (1024 * 1024) for t in times
    ]  # Convert to Mbps
    uplink_speeds = [
        uplink_throughput.get(t, 0) * 8 / (1024 * 1024) for t in times
    ]  # Convert to Mbps

    plt.figure(figsize=(10, 6))

    plt.plot(times, downlink_speeds, label="Download Throughput (Mbps)", color="blue")
    plt.plot(times, uplink_speeds, label="Upload Throughput (Mbps)", color="green")

    plt.xlabel("Time (seconds)")
    plt.ylabel("Throughput (Mbps)")
    plt.title("Throughput Over Time")
    plt.legend()
    plt.grid(True)
    plt.show()


def filter(pcap_file):
    packets = rdpcap(pcap_file)
    for pkt in packets:
        if IP in pkt and TCP in pkt:
            ip_layer = pkt[IP]
            tcp_layer = pkt[TCP]
            if (
                (ip_layer.src == ip1 and ip_layer.dst == ip2)
                or (ip_layer.src == ip2 and ip_layer.dst == ip1)
            ) and (tcp_layer.sport == tcp_port or tcp_layer.dport == tcp_port):
                filtered_packets.append(pkt)

    print(f"Number of filtered packets: {len(filtered_packets)}")


def main():
    parser = argparse.ArgumentParser(description="PCAP file to process")
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
        downlink_throughput, uplink_throughput = throughput()
        plot_throughput(downlink_throughput, uplink_throughput)

    elif args.throughput:
        print("In mode throughput")
        throughput()


if __name__ == "__main__":
    main()
