import argparse
import json
import socket
import threading
import time

# Constants
MSS = 1000  # Maximum Segment Size
RECEIVE_WINDOW_SIZE = 5 * MSS  # Size of the receive window
BUFFER_SIZE=5
size=5
INITIAL_ACK_DELAY = 0.2  # Initial delay before sending an ACK in seconds
ALPHA = 0.125  # Smoothing factor for RTT estimation
BETA = 0.25  # Smoothing factor for RTT variance
INITIAL_RTT = 1.0  # Initial RTT estimate in seconds
INITIAL_RTO = 1.0  # Initial Retransmission Timeout in seconds


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
    #out_of_order_buffer = {}  # Buffer to store out-of-order packets
    receive_window = {}  # Receive window buffer
    window_size = RECEIVE_WINDOW_SIZE
    ack_timer = None  # Timer for delayed ACKs
    ack_lock = threading.Lock()  # Lock for ACK timing
    #packet_before_expected=0

    # RTT and RTO estimates
    estimated_rtt = INITIAL_RTT
    dev_rtt = INITIAL_RTT / 2
    rto = INITIAL_RTO
    rtt_lock = threading.Lock()
    
    
    
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
        buffer=[]
        while True :
            try: 
                
                packet, _ = client_socket.recvfrom(MSS + 1024)  # Allow room for headers
                print_json_packet(packet) 
                sequence_number, data,packet_timestamp = parse_packet(packet)  
                if(len(buffer)<BUFFER_SIZE ) :
                        if(sequence_number<expected_sequence_number) :
                              print(" ")# print(f"Packet with {sequence_number} is present Packet Discard .Send Ack for expected Sequence no {expected_sequence_number} ")
                        else :
                            print(f"Buffered packet with sequence number {sequence_number} at {time.time()}")
                            buffer.append([sequence_number, data,packet_timestamp])
               
                if len(buffer)==BUFFER_SIZE and data != b"EOF":
                    print("Buffer is full in two ")
                    buffer.sort(key=lambda x: x[0])
                    count=0
                    for item in buffer :
                       
                        if(item[0] ==expected_sequence_number ) :
                            count=count+1
                            print("Data write in file for sequence no ",item[0])
                            D=item[1]
                            #expected_sequence_number=write_in_file(file,D)
                            if(expected_sequence_number>10000):
                               print(f"Data at sequence no {expected_sequence_number} {item[1]}")
                            #write_in_file(file,D)   
                            file.write(item[1])                       ## data = item[1]
                            expected_sequence_number=expected_sequence_number+len(item[1])
                            print(f"(Expected Sequence no){expected_sequence_number} =(sequence no) {item[0]}+ (len(data)) {len(item[1])}")

                        elif   item[0] < expected_sequence_number : 
                               print("Already present in FIle ",item[0])
                               count= count+1  

                        else :
                            del buffer[0 : count]
                            print(f"Sent cumulative ACK from inner  for lop sequence number {expected_sequence_number} at {time.time()}")
                            send_ack(client_socket, server_address, expected_sequence_number)
                            count=0
                            break
                    if count==BUFFER_SIZE:
                        del buffer[0 : count]
                        del buffer[count+1:BUFFER_SIZE]
                        print(f"Sent cumulative ACK from outer for loop sequence number {expected_sequence_number} at {time.time()}")
                        send_ack(client_socket, server_address, expected_sequence_number)

                if data == b"EOF" :
                    print("EOF")
                    buffer.sort(key=lambda x: x[0])
                    print(buffer)
                    count=0
                    for item in buffer :
                        if(item[0] ==expected_sequence_number ) :
                            count=count+1
                           # file.write(item[1])                       ## data = item[1]
                            expected_sequence_number=expected_sequence_number+len(item[1])
                           # print(f"{expected_sequence_number} = {expected_sequence_number} + {len(item[1])}")

                        elif   item[0] < expected_sequence_number : 
                               count= count+1  

                        else :
                            del buffer[0 : count]
                            del buffer[count+1:BUFFER_SIZE]
                            if sequence_number <=expected_sequence_number :
                                print("File Succesfully Download")
                                client_socket.sendto(b"END", server_address)
                                return 

                            print(f"Sent cumulative ACK for sequence number {expected_sequence_number} at {time.time()}")
                            send_ack(client_socket, server_address, expected_sequence_number)
                            count=0
                            break
                    if count==BUFFER_SIZE :
                        del buffer[0 : count]
                        print(f"Sent cumulative ACK for sequence number {expected_sequence_number} at {time.time()}")
                        send_ack(client_socket, server_address, expected_sequence_number)
                    
            except :continue
                 #print("Timeout waiting for data")
                # Send ACK for the last in-order byte received
   
           # if data == b"EOF":
        #             if sequence_number <=expected_sequence_number :
        #                  print("Received EOF signal from server, file transfer complete")
        #             # Write any remaining data in the receive window
        #             else :
        #                 print("Received EOF signal from server, Still left with some packet ")
        #                 write_receive_window(file, receive_window, expected_sequence_number)
        #                 # Send final ACK
        #                 with ack_lock:
        #                     if ack_timer:
        #                         ack_timer.cancel()
        #                     send_ack(
        #                         client_socket, server_address, expected_sequence_number
        #                     )
        #                 break             



                           


                          

        # while True:
        #     count =1
        #     buffer=[]
        #     while count<=size : 
        #     try:
        #         # Receive packet from server
        #         packet, _ = client_socket.recvfrom(MSS + 1024)  # Allow room for headers
        #         count=count+1
        #         # Print the JSON packet received
        #         print_json_packet(packet)
          
        #         # Parse the packet
        #         sequence_number, data,packet_timestamp = parse_packet(packet)
        #         buffer.append([sequence_number, data,packet_timestamp])
        #         receive_window[sequence_number] = data
        #         print(f"Buffered packet with sequence number {sequence_number}")
        #         # Measure RTT
        #         current_time = time.time()
        #         measured_rtt = current_time - packet_timestamp

        #         # Update RTT estimates
        #         with rtt_lock:
        #             estimated_rtt = (1 - ALPHA) * estimated_rtt + ALPHA * measured_rtt
        #             dev_rtt = (1 - BETA) * dev_rtt + BETA * abs(measured_rtt - estimated_rtt)
        #             rto = estimated_rtt + 4 * dev_rtt
        #             # Optionally, cap RTO to avoid extreme values
        #             rto = max(0.5, min(rto, 60))

        #         # Adjust ACK_DELAY based on RTT
        #         ack_delay = min(INITIAL_ACK_DELAY, estimated_rtt / 2)
                
        #         # Check for EOF signal
        #         if data == b"EOF":
        #             if sequence_number <=expected_sequence_number :
        #                  print("Received EOF signal from server, file transfer complete")
        #             # Write any remaining data in the receive window
        #             else :
        #                 print("Received EOF signal from server, Still left with some packet ")
        #                 write_receive_window(file, receive_window, expected_sequence_number)
        #                 # Send final ACK
        #                 with ack_lock:
        #                     if ack_timer:
        #                         ack_timer.cancel()
        #                     send_ack(
        #                         client_socket, server_address, expected_sequence_number
        #                     )
        #                 break

        #         if ( sequence_number >= expected_sequence_number and sequence_number < expected_sequence_number + window_size ):
        #             # Packet is within the receive window
        #             # receive_window[sequence_number] = data
        #             # print(f"Buffered packet with sequence number {sequence_number}")
                    
        #             # Start or reset the ACK timer
        #             with ack_lock:
        #                 if ack_timer:
        #                     ack_timer.cancel()
        #                 ack_timer = threading.Timer(
        #                     ack_delay,
        #                     delayed_ack,
        #                     args=(
        #                         client_socket,
        #                         server_address,
        #                         expected_sequence_number,
        #                         ack_lock,
        #                     ),
        #                 )
        #                 ack_timer.start()

        #             # Check if we can advance the window
        #             expected_sequence_number = write_receive_window( file, receive_window, expected_sequence_number )
        #             # If receive window is full, send ACK immediately
        #             if len(receive_window) * MSS >= window_size:
        #                 with ack_lock:
        #                     if ack_timer:
        #                         ack_timer.cancel()
        #                     send_ack(
        #                         client_socket, server_address, expected_sequence_number
        #                     )
        #         else:
        #             # Packet is outside the receive window (duplicate or old), send ACK
        #             print(
        #                 f"Received packet outside window with sequence number {sequence_number}, expected range {expected_sequence_number} - {expected_sequence_number + window_size - 1}"
        #             )
        #             # with ack_lock:
        #             #     if ack_timer:
        #             #         ack_timer.cancel()
        #             #     send_ack(
        #             #         client_socket, server_address, expected_sequence_number
        #             #     )
        #     except socket.timeout:
        #         print("Timeout waiting for data")
        #         # Send ACK for the last in-order byte received
        #         with ack_lock:
        #             if ack_timer:
        #                 ack_timer.cancel()
        #             send_ack(client_socket, server_address, expected_sequence_number)
        #     except json.JSONDecodeError:
        #         print("Received invalid packet, ignoring.")


def print_json_packet(packet):
    """
    Print the JSON packet received by the client.
    """
    try:
        
        packet_json = packet.decode("utf-8")
      #  print("Received JSON packet:", packet_json)
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
        'timestamp': Time when the packet was sent (float)
    }
    """
    packet_json = packet.decode("utf-8")
    packet_dict = json.loads(packet_json)
    sequence_number = packet_dict["sequence_number"]
    data = packet_dict["data"].encode("latin1")  # Encode back to bytes
    timestamp = packet_dict.get("timestamp", time.time())  # Use current time if not present
    return sequence_number, data, timestamp
   


def send_ack(client_socket, server_address, next_sequence_number):
    """
    Send a cumulative acknowledgment for the received packets.
    """
    ack_packet = {"next_sequence_number": next_sequence_number}
    ack_json = json.dumps(ack_packet)
    client_socket.sendto(ack_json.encode("utf-8"), server_address)
    #print(f"Sent cumulative ACK for sequence number {next_sequence_number }")


def delayed_ack(client_socket, server_address, next_sequence_number, ack_lock):
    """
    Send an ACK after a delay (used for delayed ACKs).
    """
    with ack_lock:
        send_ack(client_socket, server_address, next_sequence_number)


# def write_receive_window(file, receive_window, expected_sequence_number):
#     """
#     Write in-order data from the receive window to the file and update expected_sequence_number.
#     """
#     while expected_sequence_number in receive_window:
#         data = receive_window.pop(expected_sequence_number)
#         file.write(data)
#         print(f"Wrote packet with sequence number {expected_sequence_number} to file")
#         expected_sequence_number += len(data)
#     return expected_sequence_number

def  write_in_file(file,data) :
    file.write(data)
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
