# import argparse
# import json
# import socket
# import threading
# import time
#
## Constants
# MSS = 700  # Maximum Segment Size
# RECEIVE_WINDOW_SIZE = 5 * MSS  # Size of the receive window
# ACK_DELAY = 0.2  # Delay before sending an ACK in seconds
#
#
# def receive_file(server_ip, server_port):
#    """
#    Receives a file from the server reliably over UDP.
#    Implements a receive window and delayed ACKs to improve efficiency.
#    """
#    # Initialize UDP socket
#    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#    client_socket.settimeout(2)  # Set timeout for server response
#
#    server_address = (server_ip, server_port)
#    expected_sequence_number = 0  # Next expected sequence number (byte offset)
#    output_file_path = "received_file.txt"  # Output file name
#    out_of_order_buffer = {}  # Buffer to store out-of-order packets
#    receive_window = {}  # Receive window buffer
#    window_size = RECEIVE_WINDOW_SIZE
#    ack_timer = None  # Timer for delayed ACKs
#    ack_lock = threading.Lock()  # Lock for ACK timing
#
#    # Send initial connection request to server and wait for acknowledgment
#    connected = False
#    while not connected:
#        try:
#            print("Sending connection request to server...")
#            client_socket.sendto(b"START", server_address)
#            # Wait for server acknowledgment
#            data, _ = client_socket.recvfrom(1024)
#            if data == b"ACK_START":
#                print("Connection established with server")
#                connected = True
#        except socket.timeout:
#            print("No response from server, retrying connection...")
#
#    with open(output_file_path, "wb") as file:
#        while True:
#            try:
#                # Receive packet from server
#                packet, _ = client_socket.recvfrom(MSS + 1024)  # Allow room for headers
#
#                # Parse the packet
#                sequence_number, data = parse_packet(packet)
#
#                # Check for EOF signal
#                if data == b"EOF":
#                    print("Received EOF signal from server, file transfer complete")
#                    # Write any remaining data in the receive window
#                    write_receive_window(file, receive_window, expected_sequence_number)
#                    # Send final ACK
#                    send_ack(client_socket, server_address, expected_sequence_number)
#                    break
#
#                if (
#                    sequence_number >= expected_sequence_number
#                    and sequence_number < expected_sequence_number + window_size
#                ):
#                    # Packet is within the receive window
#                    receive_window[sequence_number] = data
#                    print(f"Buffered packet with sequence number {sequence_number}")
#
#                    # Start or reset the ACK timer
#                    with ack_lock:
#                        if ack_timer:
#                            ack_timer.cancel()
#                        ack_timer = threading.Timer(
#                            ACK_DELAY,
#                            delayed_ack,
#                            args=(
#                                client_socket,
#                                server_address,
#                                expected_sequence_number,
#                                ack_lock,
#                            ),
#                        )
#                        ack_timer.start()
#
#                    # Check if we can advance the window
#                    expected_sequence_number = write_receive_window(
#                        file, receive_window, expected_sequence_number
#                    )
#
#                    # If receive window is full, send ACK immediately
#                    if len(receive_window) * MSS >= window_size:
#                        with ack_lock:
#                            if ack_timer:
#                                ack_timer.cancel()
#                            send_ack(
#                                client_socket, server_address, expected_sequence_number
#                            )
#                else:
#                    # Packet is outside the receive window (duplicate or old), send ACK
#                    print(
#                        f"Received packet outside window with sequence number {sequence_number}, expected range {expected_sequence_number} - {expected_sequence_number + window_size - 1}"
#                    )
#                    with ack_lock:
#                        if ack_timer:
#                            ack_timer.cancel()
#                        send_ack(
#                            client_socket, server_address, expected_sequence_number
#                        )
#            except socket.timeout:
#                print("Timeout waiting for data")
#                # Send ACK for the last in-order byte received
#                with ack_lock:
#                    if ack_timer:
#                        ack_timer.cancel()
#                    send_ack(client_socket, server_address, expected_sequence_number)
#            except json.JSONDecodeError:
#                print("Received invalid packet, ignoring.")
#
#
# def parse_packet(packet):
#    """
#    Parse the packet to extract the sequence number and data.
#    Packet structure:
#    {
#        'sequence_number': Sequence number of the packet (byte offset),
#        'data_length': Length of the data,
#        'data': Data encoded as a string
#    }
#    """
#    packet_json = packet.decode("utf-8")
#    packet_dict = json.loads(packet_json)
#    sequence_number = packet_dict["sequence_number"]
#    data = packet_dict["data"].encode("latin1")  # Encode back to bytes
#    return sequence_number, data
#
#
# def send_ack(client_socket, server_address, next_sequence_number):
#    """
#    Send a cumulative acknowledgment for the received packets.
#    """
#    ack_packet = {"next_sequence_number": next_sequence_number}
#    ack_json = json.dumps(ack_packet)
#    client_socket.sendto(ack_json.encode("utf-8"), server_address)
#    print(f"Sent cumulative ACK for sequence number {next_sequence_number - 1}")
#
#
# def delayed_ack(client_socket, server_address, next_sequence_number, ack_lock):
#    """
#    Send an ACK after a delay (used for delayed ACKs).
#    """
#    with ack_lock:
#        send_ack(client_socket, server_address, next_sequence_number)
#
#
# def write_receive_window(file, receive_window, expected_sequence_number):
#    """
#    Write in-order data from the receive window to the file and update expected_sequence_number.
#    """
#    while expected_sequence_number in receive_window:
#        data = receive_window.pop(expected_sequence_number)
#        file.write(data)
#        print(f"Wrote packet with sequence number {expected_sequence_number} to file")
#        expected_sequence_number += len(data)
#    return expected_sequence_number
#
#
## Parse command-line arguments
# parser = argparse.ArgumentParser(
#    description="Reliable file receiver over UDP with receive window."
# )
# parser.add_argument("server_ip", help="IP address of the server")
# parser.add_argument("server_port", type=int, help="Port number of the server")
#
# args = parser.parse_args()
#
## Run the client
# receive_file(args.server_ip, args.server_port)

import argparse
import json
import socket
import threading
import time

# Constants
MSS = 700  # Maximum Segment Size
RECEIVE_WINDOW_SIZE = 5 * MSS  # Size of the receive window
ACK_DELAY = 0.2  # Delay before sending an ACK in seconds


def receive_file(server_ip, server_port):
    """
    Receives a file from the server reliably over UDP.
    Implements a receive window and delayed ACKs to improve efficiency.
    """
    # Initialize UDP socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_socket.settimeout(2)  # Set timeout for server response

    server_address = (server_ip, server_port)
    expected_sequence_number = 0  # Next expected sequence number (byte offset)
    output_file_path = "received_file.txt"  # Output file name
    out_of_order_buffer = {}  # Buffer to store out-of-order packets
    receive_window = {}  # Receive window buffer
    window_size = RECEIVE_WINDOW_SIZE
    ack_timer = None  # Timer for delayed ACKs
    ack_lock = threading.Lock()  # Lock for ACK timing

    # Send initial connection request to server and wait for acknowledgment
    connected = False
    while not connected:
        try:
            print("Sending connection request to server...")
            client_socket.sendto(b"START", server_address)
            # Wait for server acknowledgment
            data, _ = client_socket.recvfrom(1024)
            if data == b"ACK_START":
                print("Connection established with server")
                connected = True
        except socket.timeout:
            print("No response from server, retrying connection...")

    with open(output_file_path, "wb") as file:
        while True:
            try:
                # Receive packet from server
                packet, _ = client_socket.recvfrom(MSS + 1024)  # Allow room for headers

                # Print the JSON packet received
                print_json_packet(packet)

                # Parse the packet
                sequence_number, data = parse_packet(packet)

                # Check for EOF signal
                if data == b"EOF":
                    print("Received EOF signal from server, file transfer complete")
                    # Write any remaining data in the receive window
                    write_receive_window(file, receive_window, expected_sequence_number)
                    # Send final ACK
                    with ack_lock:
                        if ack_timer:
                            ack_timer.cancel()
                        send_ack(
                            client_socket, server_address, expected_sequence_number
                        )
                    break

                if (
                    sequence_number >= expected_sequence_number
                    and sequence_number < expected_sequence_number + window_size
                ):
                    # Packet is within the receive window
                    receive_window[sequence_number] = data
                    print(f"Buffered packet with sequence number {sequence_number}")

                    # Start or reset the ACK timer
                    with ack_lock:
                        if ack_timer:
                            ack_timer.cancel()
                        ack_timer = threading.Timer(
                            ACK_DELAY,
                            delayed_ack,
                            args=(
                                client_socket,
                                server_address,
                                expected_sequence_number,
                                ack_lock,
                            ),
                        )
                        ack_timer.start()

                    # Check if we can advance the window
                    expected_sequence_number = write_receive_window(
                        file, receive_window, expected_sequence_number
                    )

                    # If receive window is full, send ACK immediately
                    if len(receive_window) * MSS >= window_size:
                        with ack_lock:
                            if ack_timer:
                                ack_timer.cancel()
                            send_ack(
                                client_socket, server_address, expected_sequence_number
                            )
                else:
                    # Packet is outside the receive window (duplicate or old), send ACK
                    print(
                        f"Received packet outside window with sequence number {sequence_number}, expected range {expected_sequence_number} - {expected_sequence_number + window_size - 1}"
                    )
                    with ack_lock:
                        if ack_timer:
                            ack_timer.cancel()
                        send_ack(
                            client_socket, server_address, expected_sequence_number
                        )
            except socket.timeout:
                print("Timeout waiting for data")
                # Send ACK for the last in-order byte received
                with ack_lock:
                    if ack_timer:
                        ack_timer.cancel()
                    send_ack(client_socket, server_address, expected_sequence_number)
            except json.JSONDecodeError:
                print("Received invalid packet, ignoring.")


def print_json_packet(packet):
    """
    Print the JSON packet received by the client.
    """
    try:
        packet_json = packet.decode("utf-8")
        print("Received JSON packet:", packet_json)
    except UnicodeDecodeError:
        print("Received a non-UTF-8 packet, unable to decode.")
    except Exception as e:
        print(f"Error decoding packet: {e}")


def parse_packet(packet):
    """
    Parse the packet to extract the sequence number and data.
    Packet structure:
    {
        'sequence_number': Sequence number of the packet (byte offset),
        'data_length': Length of the data,
        'data': Data encoded as a string
    }
    """
    packet_json = packet.decode("utf-8")
    packet_dict = json.loads(packet_json)
    sequence_number = packet_dict["sequence_number"]
    data = packet_dict["data"].encode("latin1")  # Encode back to bytes
    return sequence_number, data


def send_ack(client_socket, server_address, next_sequence_number):
    """
    Send a cumulative acknowledgment for the received packets.
    """
    ack_packet = {"next_sequence_number": next_sequence_number}
    ack_json = json.dumps(ack_packet)
    client_socket.sendto(ack_json.encode("utf-8"), server_address)
    print(f"Sent cumulative ACK for sequence number {next_sequence_number - 1}")


def delayed_ack(client_socket, server_address, next_sequence_number, ack_lock):
    """
    Send an ACK after a delay (used for delayed ACKs).
    """
    with ack_lock:
        send_ack(client_socket, server_address, next_sequence_number)


def write_receive_window(file, receive_window, expected_sequence_number):
    """
    Write in-order data from the receive window to the file and update expected_sequence_number.
    """
    while expected_sequence_number in receive_window:
        data = receive_window.pop(expected_sequence_number)
        file.write(data)
        print(f"Wrote packet with sequence number {expected_sequence_number} to file")
        expected_sequence_number += len(data)
    return expected_sequence_number


# Parse command-line arguments
parser = argparse.ArgumentParser(
    description="Reliable file receiver over UDP with receive window."
)
parser.add_argument("server_ip", help="IP address of the server")
parser.add_argument("server_port", type=int, help="Port number of the server")

args = parser.parse_args()

# Run the client
receive_file(args.server_ip, args.server_port)
