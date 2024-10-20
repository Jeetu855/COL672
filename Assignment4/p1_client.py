import argparse
import os
import socket

# Constants
MSS = 1400  # Maximum Segment Size
END_SIGNAL = b"END"  # Signal to indicate end of file transfer


def receive_file(server_ip, server_port):
    """
    Receive the file from the server with reliability, handling packet loss
    and reordering.
    """
    # Initialize UDP socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_socket.settimeout(2)  # Set timeout for server response

    server_address = (server_ip, server_port)
    expected_seq_num = 0
    received_packets = {}
    output_file_path = "received_file.txt"  # Default file name

    # Initiate connection
    client_socket.sendto(b"START", server_address)
    print("Sent connection request to server.")

    with open(output_file_path, "wb") as file:
        while True:
            try:
                # Receive the packet
                packet, _ = client_socket.recvfrom(MSS + 100)  # Allow room for headers

                # Check for end signal
                if packet == END_SIGNAL:
                    print("Received END signal from server, file transfer complete")
                    # Send final ACK
                    send_ack(client_socket, server_address, expected_seq_num - 1)
                    break

                # Parse the packet
                seq_num, data = parse_packet(packet)

                if seq_num == expected_seq_num:
                    # Write the data to file
                    file.write(data)
                    print(f"Received packet {seq_num}, writing to file")
                    expected_seq_num += 1

                    # Check if any subsequent packets are already received
                    while expected_seq_num in received_packets:
                        file.write(received_packets.pop(expected_seq_num))
                        print(f"Writing buffered packet {expected_seq_num}")
                        expected_seq_num += 1

                    # Send cumulative ACK
                    send_ack(client_socket, server_address, expected_seq_num - 1)
                elif seq_num > expected_seq_num:
                    # Out-of-order packet, buffer it
                    if seq_num not in received_packets:
                        received_packets[seq_num] = data
                        print(f"Buffered out-of-order packet {seq_num}")
                    # Send cumulative ACK for the last in-order packet
                    send_ack(client_socket, server_address, expected_seq_num - 1)
                else:
                    # Duplicate or old packet, resend ACK
                    print(f"Received duplicate/old packet {seq_num}, resending ACK")
                    send_ack(client_socket, server_address, expected_seq_num - 1)

            except socket.timeout:
                print(
                    "Timeout waiting for data. Resending ACK for the last received packet."
                )
                # Resend ACK to prompt server retransmission if needed
                send_ack(client_socket, server_address, expected_seq_num - 1)

    client_socket.close()
    print(f"File received successfully and saved as {output_file_path}.")


def parse_packet(packet):
    """
    Parse the packet to extract the sequence number and data.
    Packet format: seq_num|data
    """
    try:
        header, data = packet.split(b"|", 1)
        seq_num = int(header.decode())
        return seq_num, data
    except ValueError:
        print("Received a malformed packet.")
        return -1, b""


def send_ack(client_socket, server_address, seq_num):
    """
    Send a cumulative acknowledgment for the received packet.
    ACK format: seq_num|ACK
    """
    if seq_num >= 0:  # Only send ACKs for valid sequence numbers
        ack_packet = f"{seq_num}|ACK".encode()
        client_socket.sendto(ack_packet, server_address)
        print(f"Sent cumulative ACK for packet {seq_num}")
    else:
        print(f"Invalid sequence number {seq_num}. ACK not sent.")


# Parse command-line arguments
parser = argparse.ArgumentParser(description="Reliable file receiver over UDP.")
parser.add_argument("server_ip", help="IP address of the server")
parser.add_argument("server_port", type=int, help="Port number of the server")

args = parser.parse_args()

# Run the client
receive_file(args.server_ip, args.server_port)
