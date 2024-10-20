import argparse
import os
import socket
import time
from threading import Timer

# Constants
MSS = 1400  # Maximum Segment Size for each packet
WINDOW_SIZE = 5  # Number of packets in flight
DUP_ACK_THRESHOLD = 3  # Threshold for duplicate ACKs to trigger fast retransmit
FILE_PATH = "./input.txt"  # Path to the file to send
INITIAL_TIMEOUT = 1.0  # Initial timeout value in seconds
END_SIGNAL = b"END"  # Signal to indicate end of file transfer


def send_file(server_ip, server_port, enable_fast_recovery):
    """
    Send a predefined file to the client, ensuring reliability over UDP.
    """
    # Initialize UDP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((server_ip, server_port))

    print(f"Server listening on {server_ip}:{server_port}")

    # Wait for client to initiate connection
    print("Waiting for connection from client...")
    try:
        server_socket.settimeout(10)  # Timeout for initial connection
        data, client_address = server_socket.recvfrom(1024)
    except socket.timeout:
        print("No connection initiation received. Exiting.")
        server_socket.close()
        return

    if data != b"START":
        print("Received invalid connection initiation. Exiting.")
        server_socket.close()
        return

    print(f"Connection established with client {client_address}")

    # Read the file into memory
    if not os.path.exists(FILE_PATH):
        print(f"File {FILE_PATH} does not exist. Exiting.")
        server_socket.close()
        return

    with open(FILE_PATH, "rb") as file:
        file_data = file.read()

    # Split file into chunks
    chunks = [file_data[i : i + MSS] for i in range(0, len(file_data), MSS)]
    total_packets = len(chunks)
    print(f"Total packets to send: {total_packets}")

    # Initialize variables for sliding window
    base = 0  # Next sequence number expecting ACK
    next_seq_num = 0  # Next sequence number to send
    unacked_packets = {}  # seq_num: (packet, send_time)
    timers = {}  # seq_num: Timer object
    duplicate_ack_count = {}  # seq_num: count of duplicate ACKs
    last_ack_received = -1

    while base < total_packets:
        # Send packets within the window
        while next_seq_num < base + WINDOW_SIZE and next_seq_num < total_packets:
            packet = create_packet(next_seq_num, chunks[next_seq_num])
            server_socket.sendto(packet, client_address)
            send_time = time.time()
            unacked_packets[next_seq_num] = (packet, send_time)
            print(f"Sent packet {next_seq_num}")
            # Start a timer for the packet
            timers[next_seq_num] = Timer(
                INITIAL_TIMEOUT,
                timeout_handler,
                [
                    server_socket,
                    client_address,
                    next_seq_num,
                    unacked_packets,
                    timers,
                    enable_fast_recovery,
                ],
            )
            timers[next_seq_num].start()
            next_seq_num += 1

        try:
            server_socket.settimeout(INITIAL_TIMEOUT)
            ack_packet, _ = server_socket.recvfrom(1024)
            ack_seq_num = parse_ack(ack_packet)

            if ack_seq_num is None:
                print("Received malformed ACK. Ignoring.")
                continue

            print(f"Received ACK for packet {ack_seq_num}")

            if ack_seq_num > last_ack_received:
                # New ACK received
                last_ack_received = ack_seq_num
                base = ack_seq_num + 1  # Slide the window
                print(f"Sliding window. New base: {base}")

                # Cancel timers for acknowledged packets
                for seq in list(unacked_packets):
                    if seq <= ack_seq_num:
                        if seq in timers:
                            timers[seq].cancel()
                            del timers[seq]
                        del unacked_packets[seq]
                        if seq in duplicate_ack_count:
                            del duplicate_ack_count[seq]
            else:
                # Duplicate ACK received
                if enable_fast_recovery:
                    if ack_seq_num in duplicate_ack_count:
                        duplicate_ack_count[ack_seq_num] += 1
                    else:
                        duplicate_ack_count[ack_seq_num] = 1
                    print(
                        f"Duplicate ACK count for packet {ack_seq_num}: {duplicate_ack_count[ack_seq_num]}"
                    )

                    if duplicate_ack_count[ack_seq_num] == DUP_ACK_THRESHOLD:
                        print("DUP_ACK_THRESHOLD reached. Initiating fast retransmit.")
                        # Retransmit the missing packet
                        fast_recovery(
                            server_socket,
                            client_address,
                            unacked_packets,
                            timers,
                            duplicate_ack_count,
                            enable_fast_recovery,
                        )
        except socket.timeout:
            print(
                "Socket timeout occurred. Initiating retransmission of all unacked packets."
            )
            # Retransmit all unacknowledged packets
            for seq_num in list(unacked_packets):
                server_socket.sendto(unacked_packets[seq_num][0], client_address)
                print(f"Retransmitted packet {seq_num}")
                # Restart timer
                if seq_num in timers:
                    timers[seq_num].cancel()
                timers[seq_num] = Timer(
                    INITIAL_TIMEOUT,
                    timeout_handler,
                    [
                        server_socket,
                        client_address,
                        seq_num,
                        unacked_packets,
                        timers,
                        enable_fast_recovery,
                    ],
                )
                timers[seq_num].start()

    # After all packets are acknowledged, send END signal
    server_socket.sendto(END_SIGNAL, client_address)
    print("Sent END signal to client.")

    # Optionally wait for final ACK
    try:
        server_socket.settimeout(2)
        ack_packet, _ = server_socket.recvfrom(1024)
        ack_seq_num = parse_ack(ack_packet)
        if ack_seq_num == total_packets - 1:
            print("Received final ACK from client.")
    except socket.timeout:
        print("Did not receive final ACK from client.")

    # Clean up
    server_socket.close()
    print("File transfer complete. Server socket closed.")


def create_packet(seq_num, data):
    """
    Create a packet with the sequence number and data.
    Packet format: seq_num|data
    """
    header = f"{seq_num}|".encode()
    packet = header + data
    return packet


def parse_ack(ack_packet):
    """
    Parse the ACK packet to extract the acknowledged sequence number.
    ACK format: seq_num|ACK
    """
    try:
        header, ack = ack_packet.split(b"|", 1)
        if ack != b"ACK":
            print(f"Malformed ACK packet: {ack_packet}")
            return None
        seq_num = int(header.decode())
        return seq_num
    except ValueError:
        print(f"Error parsing ACK packet: {ack_packet}")
        return None


def timeout_handler(
    server_socket,
    client_address,
    seq_num,
    unacked_packets,
    timers,
    enable_fast_recovery,
):
    """
    Handle packet timeout by retransmitting the packet.
    """
    if seq_num in unacked_packets:
        print(f"Timeout for packet {seq_num}. Retransmitting.")
        server_socket.sendto(unacked_packets[seq_num][0], client_address)
        # Restart timer
        timers[seq_num] = Timer(
            INITIAL_TIMEOUT,
            timeout_handler,
            [
                server_socket,
                client_address,
                seq_num,
                unacked_packets,
                timers,
                enable_fast_recovery,
            ],
        )
        timers[seq_num].start()


def fast_recovery(
    server_socket,
    client_address,
    unacked_packets,
    timers,
    duplicate_ack_count,
    enable_fast_recovery,
):
    """
    Implement fast recovery by retransmitting the missing packet.
    """
    if unacked_packets:
        # Find the smallest sequence number in the unacked_packets
        missing_seq = min(unacked_packets.keys())

        # Retransmit the missing packet
        server_socket.sendto(unacked_packets[missing_seq][0], client_address)
        print(f"Fast recovery: Retransmitted packet {missing_seq}")

        # Restart timer for the retransmitted packet
        if missing_seq in timers:
            timers[missing_seq].cancel()

        timers[missing_seq] = Timer(
            INITIAL_TIMEOUT,
            timeout_handler,
            [
                server_socket,
                client_address,
                missing_seq,
                unacked_packets,
                timers,
                enable_fast_recovery,
            ],
        )
        timers[missing_seq].start()


# Parse command-line arguments
parser = argparse.ArgumentParser(description="Reliable file transfer server over UDP.")
parser.add_argument("server_ip", help="IP address of the server")
parser.add_argument("server_port", type=int, help="Port number of the server")
parser.add_argument(
    "fast_recovery", type=int, help="Enable fast recovery (1 for Yes, 0 for No)"
)

args = parser.parse_args()

# Run the server
send_file(args.server_ip, args.server_port, args.fast_recovery == 1)
