# on one side we start:
# python udp_p2p.py --listen_port <first_port> --target_ip <target_ip> --target_port <second_port> --save_dir "PATH"

# on other side
# python udp_p2p.py --listen_port <second_port> --target_ip <target_ip> --target_port <first_port> --save_dir "PATH"
import socket
import argparse
import threading
import os
import time


# Keep-alive constants
HEARTBEAT_INTERVAL = 5
MAX_MISSED_HEARTBEATS = 3
missed_heartbeats = 0
MAX_RECONNECT_ATTEMPTS = 5


def send_heartbeat(udp_socket, target_ip, target_port):
    global missed_heartbeats

    while True:
        try:
            udp_socket.sendto("HEARTBEAT".encode('utf-8'), (target_ip, target_port))
            print("Sent HEARTBEAT.")
            time.sleep(HEARTBEAT_INTERVAL)
        except Exception as e:
            print(f"Error sending heartbeat: {e}")
            return


def handle_heartbeat(udp_socket, addr):
    global missed_heartbeats
    missed_heartbeats = 0
    udp_socket.sendto("ACK-HEARTBEAT".encode('utf-8'), addr)
    print(f"Received HEARTBEAT from {addr}. Sent ACK-HEARTBEAT.")


def monitor_connection(udp_socket, target_ip, target_port):
    global missed_heartbeats

    while True:
        time.sleep(HEARTBEAT_INTERVAL + 2)
        missed_heartbeats += 1
        if missed_heartbeats > MAX_MISSED_HEARTBEATS:
            print("Connection lost. Too many missed heartbeats.")
            missed_heartbeats = 0
            print("Attempting to reconnect...")
            reconnect(udp_socket, target_ip, target_port)


# If connection is lost trying to reconnect
def reconnect(udp_socket, target_ip, target_port):
    attempts = 0
    while attempts < MAX_RECONNECT_ATTEMPTS:
        print(f"Attempt {attempts + 1} of {MAX_RECONNECT_ATTEMPTS} to reconnect...")
        if handshake(udp_socket, target_ip, target_port):
            print("Reconnected successfully!")
            attempts = 0
            return
        attempts += 1
        time.sleep(5)
    print(f"Failed to reconnect after {MAX_RECONNECT_ATTEMPTS} attempts. Exiting.")
    os._exit(1)


# Function to checksum
def crc16(data: bytes) -> int:
    crc = 0xFFFF  # Start CRC value
    for byte in data:
        crc ^= byte << 8  # move bite
        for _ in range(8):  # For each bite
            if crc & 0x8000:
                crc = (crc << 1) ^ 0x11021  # Polinom divide
            else:
                crc <<= 1
            crc &= 0xFFFF  # Leave only 16 bit
    return crc


# Function to handle the handshake
def handshake(udp_socket, target_ip, target_port):
    time.sleep(5)
    print("Starting handshake...")
    udp_socket.sendto("SYN".encode('utf-8'), (target_ip, target_port))

    try:
        udp_socket.settimeout(15)
        while True:
            try:
                message, addr = udp_socket.recvfrom(1024)
                decoded_message = message.decode('utf-8')
                if decoded_message == "SYN":
                    print(f"Received SYN from {addr}. Sending  SYN-ACK...")
                    udp_socket.sendto("SYN-ACK".encode('utf-8'), addr)
                elif decoded_message == "SYN-ACK":
                    print(f"Received SYN-ACK from {addr}. Sending ACK...")
                    udp_socket.sendto("ACK".encode('utf-8'), addr)
                elif decoded_message == "ACK":
                    print(f"Received ACK from {addr}")
                    print("Handshake simulation completed successfully!")
                    return True
            except socket.timeout:
                print("Timed out waiting for handshake message. Retrying...")
                udp_socket.sendto("SYN".encode('utf-8'), (target_ip, target_port))  # Resend SYN
    except Exception as e:
        print(f"Error during handshake: {e}")
    return False


def receive_messages(udp_socket, save_dir):
    udp_socket.settimeout(10)
    udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
    print("Listening for incoming messages...")
    fragments = {}
    start_time = None
    file_extension = ""

    while True:
        try:
            message, addr = udp_socket.recvfrom(2048)
            # Control that message is correct
            if b"FRAG" in message:
                # Split by CRC
                parts = message.split(b"|CRC:")
                if len(parts) != 2:
                    print(f"Invalid message format: {message}")
                    continue

                frag_info, payload_with_crc = parts[0], parts[1]
                # Split by EXT for file extension
                if b"|EXT:" in payload_with_crc:
                    payload_with_crc, ext_part = payload_with_crc.split(b"|EXT:")
                    file_extension = ext_part.decode('utf-8')

                frag_parts = frag_info.split(b":")
                if len(frag_parts) < 4:
                    print(f"Invalid fragment info format: {frag_info}")
                    continue

                seq_num = int(frag_parts[1])
                total_frags = int(frag_parts[2])
                payload = b":".join(frag_parts[3:])
                received_crc = int(payload_with_crc)
                # CRC verification
                calculated_crc = crc16(payload)
                if calculated_crc != received_crc:
                    print(f"CRC mismatch for fragment {seq_num}/{total_frags}. Discarding fragment.")
                    udp_socket.sendto(f"NACK:{seq_num}".encode('utf-8'), addr)
                    continue
                else:
                    if seq_num not in fragments:
                        fragments[seq_num] = payload

                udp_socket.sendto(f"ACK:{seq_num}".encode('utf-8'), addr)

                if start_time is None:
                    start_time = time.time()

                print(f"Received fragment {seq_num}/{total_frags} from {addr}")

                # if seq_num not in fragments:
                #     fragments[seq_num] = payload

                if len(fragments) == total_frags:
                    print("All fragments received. Reassembling...")
                    full_data = b''.join(fragments[i] for i in range(1, total_frags + 1))

                    # Save file with extension
                    file_path = os.path.join(save_dir, f"received_file_{int(time.time())}{file_extension}")
                    with open(file_path, 'wb') as f:
                        f.write(full_data)

                    duration = time.time() - start_time
                    print(f"Transfer complete! File saved at {file_path}")
                    print(f"Transfer duration: {duration:.2f}s, File size: {len(full_data)} bytes")
                    fragments.clear()
                    start_time = None
            else:
                if message.decode('utf-8') == "HEARTBEAT":
                    handle_heartbeat(udp_socket, addr)
                elif message.decode('utf-8') == "ACK-HEARTBEAT":
                    print(f"Received ACK-HEARTBEAT from {addr}")
                    missed_heartbeats = 0
                else:
                    decoded_message = message.decode('utf-8')
                    print(f"Received message: {decoded_message}")
                    if b"|CRC:" in message:
                        parts = decoded_message.split("|CRC:")
                        if len(parts) == 2:
                            message_body = parts[0].encode('utf-8')
                            crc_part = parts[1]
                            crc_part = crc_part.split("|EXT:")[0]
                            received_crc = int(crc_part)

                            calculated_crc = crc16(message_body)
                            if calculated_crc != received_crc:
                                print(f"CRC mismatch for message from {addr}. Discarding message.")
                                continue
                        else:
                            print(f"Message from {addr}: {message.decode('utf-8')}")
        except socket.timeout:
            continue
        except Exception as e:
            print(f"Error receiving message: {e}")


# Function to send messages
def send_messages(udp_socket, target_ip, target_port):
    simulate_error = False
    fragment_size = 1024  # Default fragment size

    while True:
        print(f"Current fragment size: {fragment_size} bytes.")
        print("Options: [1] Send text, [2] Send file, [3] Change fragment size, [4] Turn on error simulation, [5] for exit")
        option = input("Choose an option: ")

        if option == '1':
            message = input("Enter message to send: ")
            send_data(udp_socket, target_ip, target_port, message, fragment_size, simulate_error=simulate_error)
        elif option == '2':
            file_path = input("Enter file path: ").strip()
            if file_path:
                with open(file_path, 'rb') as f:
                    file_data = f.read()
                send_data(udp_socket, target_ip, target_port, file_data, fragment_size, file_path, simulate_error=simulate_error)
        elif option == '3':
            try:
                new_size = int(input("Enter new fragment size (max 1024 bytes): "))
                if 1 <= new_size <= 1024:
                    fragment_size = new_size
                else:
                    print("Invalid size. Please enter a value between 1 and 1024.")
            except ValueError:
                print("Invalid input. Please enter a number.")
        elif option == '4':
            if not simulate_error:
                simulate_error = True
                print("Error simulating is on")
            else:
                simulate_error = False
                print("Error simulating is off")
        elif option == '5':
            os._exit(1)


def send_data(udp_socket, target_ip, target_port, data, fragment_size, file_path=None, simulate_error=False):
    if isinstance(data, str):
        data = data.encode('utf-8')

    # If its file save the file extension
    if file_path:
        file_extension = os.path.splitext(file_path)[1]
    else:
        file_extension = ''

    if len(data) <= fragment_size:
        crc = crc16(data)
        if not simulate_error:
            message = data + f"|CRC:{crc}|EXT:{file_extension}".encode('utf-8')
            print(crc)
        else:
            message = data + f"|CRC:{crc+1}|EXT:{file_extension}".encode('utf-8')
            print(crc)
        udp_socket.sendto(message, (target_ip, target_port))
        print(f"Sent data: {len(data)} bytes (no fragmentation).")
    else:
        total_fragments = (len(data) + fragment_size - 1) // fragment_size
        print(f"Sending file: {file_path or 'Binary data'}")
        print(f"Total size: {len(data)} bytes, Fragments: {total_fragments}, Fragment size: {fragment_size} bytes")

        for i in range(total_fragments):
            start = i * fragment_size
            end = start + fragment_size
            fragment = data[start:end]
            crc = crc16(fragment)
            if not simulate_error:
                message = f"FRAG:{i + 1}:{total_fragments}:".encode('utf-8') + fragment + f"|CRC:{crc}|EXT:{file_extension}".encode('utf-8')
            else:
                message = f"FRAG:{i + 1}:{total_fragments}:".encode('utf-8') + fragment + f"|CRC:{crc+1}|EXT:{file_extension}".encode('utf-8')
            udp_socket.sendto(message, (target_ip, target_port))
            print(f"Sent fragment {i + 1}/{total_fragments} ({len(fragment)} bytes)")

            # Wait for ACK or NACK
            while True:
                try:
                    udp_socket.settimeout(0.03)
                    response, addr = udp_socket.recvfrom(2048)
                    if response.decode('utf-8') == f"ACK:{i + 1}":
                        print(f"Fragment {i + 1} acknowledged.")
                        break
                    elif response.decode('utf-8') == f"NACK:{i + 1}":
                        print(f"Fragment {i + 1} NACK received. Retrying...")
                        udp_socket.sendto(message, (target_ip, target_port))  # Resend the fragment
                except socket.timeout:
                    print(f"Timeout waiting for ACK for fragment {i + 1}. Resending...")
                    udp_socket.sendto(message, (target_ip, target_port))  # Resend the fragment


def main():
    # Using argparse to handle command line arguments
    parser = argparse.ArgumentParser(description="P2P Communication with Fragmentation.")
    parser.add_argument('--listen_port', type=int, required=True, help="Port on which this node listens.")
    parser.add_argument('--target_ip', type=str, required=True, help="Target IP to send messages.")
    parser.add_argument('--target_port', type=int, required=True, help="Target port to send messages.")
    parser.add_argument('--save_dir', type=str, required=True, help="Directory to save received files.")

    args = parser.parse_args()

    # Creating a UDP socket
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Binding to the port
    udp_socket.bind(('', args.listen_port))
    print(f"Listening on port {args.listen_port}...")

    # Perform handshake
    if not handshake(udp_socket, args.target_ip, args.target_port):
        print("Handshake failed. Exiting.")
        return

    # Start a thread to receive messages
    receive_thread = threading.Thread(target=receive_messages, args=(udp_socket, args.save_dir))
    receive_thread.daemon = True  # Daemon thread to exit when the main program exits
    receive_thread.start()

    # Start a thread for sending heartbeat
    heartbeat_thread = threading.Thread(target=send_heartbeat, args=(udp_socket, args.target_ip, args.target_port))
    heartbeat_thread.daemon = True
    heartbeat_thread.start()

    # Start a thread to monitor connection
    monitor_thread = threading.Thread(target=monitor_connection, args=(udp_socket, args.target_ip, args.target_port))
    monitor_thread.daemon = True
    monitor_thread.start()

    # Sending messages
    send_messages(udp_socket, args.target_ip, args.target_port)


if __name__ == "__main__":
    main()
