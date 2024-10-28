import argparse
import json
import socket
import time

# Constants
MSS = 1000  # Maximum Segment Size for each packet
WINDOW_SIZE = 5  # Number of packets in flight
DUP_ACK_THRESHOLD = 3  # Threshold for duplicate ACKs to trigger fast recovery
FILE_PATH = "input.txt"
ALPHA = 0.125  # Weight for estimated RTT
BETA = 0.25  # Weight for RTT deviation


def send_file(server_ip, server_port, enable_fast_recovery):
    """
    Sends a file to the client reliably over UDP.
    Implements sliding window protocol with cumulative ACKs, fast recovery,
    and adaptive timeout using RTT estimation.
    """
    # Initialize UDP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((server_ip, server_port))

    print(f"Server listening on {server_ip}:{server_port}")

    # Initialize RTT estimation variables
    estimated_rtt = 0.5  # Initial estimated RTT in seconds
    dev_rtt = 0.25  # Initial RTT deviation
    timeout_interval = estimated_rtt + 4 * dev_rtt  # Initial timeout interval

    # Wait for client to initiate connection
    client_address = None

    # Open the file to be sent
    with open(FILE_PATH, "rb") as file:
        # Initialize sequence numbers and window parameters
        next_sequence_number = 0  # Next sequence number to be used
        window_base = 0  # Sequence number of the earliest unacknowledged byte
        unacked_packets = {}  # Dictionary to hold unacknowledged packets
        duplicate_ack_count = 0  # Counter for duplicate ACKs
        last_ack_received = -1  # Last ACK received
        eof = False  # End of file flag

        # Start the file transmission
        while True:
            # Establish connection with client if not already done
            if not client_address:
                print("Waiting for client connection...")
                try:
                    server_socket.settimeout(2)
                    data, client_address = server_socket.recvfrom(1024)
                    if data == b"START":
                        print(f"Connection established with client {client_address}")
                        # Send acknowledgment to client
                        server_socket.sendto(b"ACK_START", client_address)
                    else:
                        continue
                except socket.timeout:
                    # Keep waiting for client's START message
                    continue

            # Send packets within the window
            while next_sequence_number < window_base + WINDOW_SIZE * MSS and not eof:
                # Read data from file
                file.seek(next_sequence_number)
                data_chunk = file.read(MSS)
                if not data_chunk:
                    # End of file reached
                    eof = True
                    break

                # Create and send the packet
                packet = create_packet(next_sequence_number, data_chunk)
                server_socket.sendto(packet, client_address)
                unacked_packets[next_sequence_number] = {
                    "packet": packet,
                    "send_time": time.time(), 
                }
                print(f"Sent packet with sequence number {next_sequence_number}")
                next_sequence_number += len(data_chunk)

            # Wait for ACKs and handle retransmissions
            try:
                # Set socket timeout using adaptive timeout interval
                server_socket.settimeout(timeout_interval)

                # Receive ACK from client
                ack_packet, _ = server_socket.recvfrom(1024)
                ack_sequence_number = get_sequence_number_from_ack(ack_packet)

                # Calculate sample RTT
                if ack_sequence_number in unacked_packets:
                    sample_rtt = (
                        time.time() - unacked_packets[ack_sequence_number]["send_time"]
                    )
                    # Update estimated RTT and dev RTT
                    estimated_rtt = (1 - ALPHA) * estimated_rtt + ALPHA * sample_rtt
                    dev_rtt = (1 - BETA) * dev_rtt + BETA * abs(
                        sample_rtt - estimated_rtt
                    )
                    # Update timeout interval
                    timeout_interval = estimated_rtt + 4 * dev_rtt
                    print(f"Updated timeout interval: {timeout_interval:.4f} seconds")

                if ack_sequence_number > window_base:
                    # Cumulative ACK received, slide the window
                    print(
                        f"Received cumulative ACK for sequence number {ack_sequence_number - 1}"
                    )
                    window_base = ack_sequence_number
                    last_ack_received = ack_sequence_number
                    # Remove acknowledged packets from the buffer
                    for seq in list(unacked_packets):
                        if seq < ack_sequence_number:
                            del unacked_packets[seq]
                    duplicate_ack_count = 0  # Reset duplicate ACK count
                elif ack_sequence_number == last_ack_received:
                    # Duplicate ACK received
                    duplicate_ack_count += 1
                    print(
                        f"Received duplicate ACK for sequence number {ack_sequence_number - 1}, count={duplicate_ack_count}"
                    )

                    if (
                        enable_fast_recovery
                        and duplicate_ack_count >= DUP_ACK_THRESHOLD
                    ):
                        print("Fast recovery triggered")
                        fast_recovery(
                            server_socket,
                            client_address,
                            ack_sequence_number,
                            unacked_packets,
                        )
                        duplicate_ack_count = 0  # Reset after fast recovery
                else:
                    # Old ACK received, ignore
                    print(
                        f"Received old ACK for sequence number {ack_sequence_number - 1}, ignoring"
                    )
            except socket.timeout:
                # Timeout occurred, retransmit unacknowledged packets
                print("Timeout occurred, retransmitting unacknowledged packets")
                retransmit_unacked_packets(
                    server_socket, client_address, unacked_packets
                )
                # Adjust timeout_interval if needed (e.g., exponential backoff)
                timeout_interval = min(timeout_interval * 2, 4)  # Cap at 4 seconds
                print(
                    f"Increased timeout interval to {timeout_interval:.4f} seconds due to timeout"
                )

            # Check if all data has been sent and acknowledged
            if eof and not unacked_packets:
                # Send EOF packet to client
                eof_packet = create_packet(next_sequence_number, b"EOF")
                server_socket.sendto(eof_packet, client_address)
                print("File transfer complete")
                break


def create_packet(sequence_number, data):
    """
    Create a packet with the sequence number and data.
    Packet structure:
    {
        'sequence_number': Sequence number of the packet (byte offset),
        'data_length': Length of the data,
        'data': Data encoded as a string
    }
    """
    packet_dict = {
        "sequence_number": sequence_number,
        "data_length": len(data),
        "data": data.decode("latin1"),  # Use latin1 to preserve binary data
    }
    packet_json = json.dumps(packet_dict)
    return packet_json.encode("utf-8")


def get_sequence_number_from_ack(ack_packet):
    """
    Extract the next expected sequence number from the ACK packet.
    ACK packet structure:
    {
        'next_sequence_number': Next expected sequence number (byte offset)
    }
    """
    ack_json = ack_packet.decode("utf-8")
    ack_dict = json.loads(ack_json)
    return ack_dict["next_sequence_number"]


def retransmit_unacked_packets(server_socket, client_address, unacked_packets):
    """
    Retransmit all unacknowledged packets.
    """
    for sequence_number, packet_info in unacked_packets.items():
        server_socket.sendto(packet_info["packet"], client_address)
        unacked_packets[sequence_number]["send_time"] = time.time()
        print(f"Retransmitted packet with sequence number {sequence_number}")


def fast_recovery(server_socket, client_address, ack_sequence_number, unacked_packets):
    """
    Retransmit the missing packet upon receiving 3 duplicate ACKs.
    """
    if ack_sequence_number in unacked_packets:
        packet_info = unacked_packets[ack_sequence_number]
        server_socket.sendto(packet_info["packet"], client_address)
        unacked_packets[ack_sequence_number]["send_time"] = time.time()
        print(f"Fast retransmitted packet with sequence number {ack_sequence_number}")
    else:
        print(
            f"No unacknowledged packet with sequence number {ack_sequence_number} found for fast recovery"
        )


# Parse command-line arguments
parser = argparse.ArgumentParser(description="Reliable file transfer server over UDP.")
parser.add_argument("server_ip", help="IP address of the server")
parser.add_argument("server_port", type=int, help="Port number of the server")
parser.add_argument(
    "fast_recovery", type=int, help="Enable fast recovery (1 to enable, 0 to disable)"
)

args = parser.parse_args()

# Run the server
send_file(args.server_ip, args.server_port, args.fast_recovery)
