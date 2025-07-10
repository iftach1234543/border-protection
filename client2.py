
"""
Author: Iftach Kasorla
Date: 3/6/25
Description: A simple TLS client (no GUI) for an actuator robot (e.g., a "killer robot").
Connects to a server, authenticates, exchanges encrypted messages,
and interacts with an Arduino to perform actions based on server commands.
"""
import logging
import socket
import protocol # Assuming protocol.py exists
from aes import MyAES # Assuming aes.py and MyAES class exist
from rsa import MyRSA # Assuming rsa.py and MyRSA class exist
import serial
import time

# Configure serial port (change 'COM4' to your Arduino's port if different)
arduino_port = 'COM4'
baud_rate = 9600

HOST_NAME = '10.100.102.21' # Server's hostname or IP address (Note: Different from client1)
PORT = 8443                # Server's port
EXIT_CMD = 'by by'         # Command from server that signals client to exit
# USER_INPUT = 'please enter a command: ' # Unused global variable
send_again = False # Flag to indicate if the last message needs to be resent
did_send = False   # Flag to indicate if a message was just sent (e.g., by receive_client_messages)
last_massage = ''  # Stores the last message sent by this client
IMAGE_FILENAME = "received_image.jpg" # Filename to save received images
DEFAULT_MSG = "DEFAULT" # Unused global variable
msg = ''           # Holds the current message received from server or to be sent

# Configure logging at the beginning
logging.basicConfig(
    format='%(asctime)s | %(levelname)s | CLIENT2 - %(message)s', # Log identifier
    datefmt='%m/%d/%Y %I:%M:%S %p',
    level=logging.INFO,
    filename='tls_client2.log', # Specific log file for client2
    filemode='w'
)

def connect_to_robo_v3() -> serial.Serial | None:
    """
    Establishes a serial connection to the Arduino (robot).

    Returns:
        serial.Serial | None: The serial connection object if successful, None otherwise.
    """
    try:
        arduino = serial.Serial(arduino_port, baud_rate, timeout=1)
        logging.info(f"Attempting to connect to Arduino on {arduino_port} at {baud_rate} baud.")
        time.sleep(2)  # Wait for the connection to establish
        if arduino.is_open:
            logging.info(f"Successfully connected to Arduino on {arduino_port}.")
            print(f"Connected to {arduino_port}")
            return arduino
        else:
            logging.error(f"Failed to open serial port {arduino_port}.")
            print(f"Failed to open serial port {arduino_port}.")
            return None
    except serial.SerialException as se:
        logging.error(f"Serial error connecting to Arduino on {arduino_port}: {se}")
        print(f"Serial error on {arduino_port}: {se}")
        return None
    except Exception as e:
        logging.error(f"Unexpected error connecting to Arduino: {e}")
        print(f"Unexpected error connecting to Arduino: {e}")
        return None

def send_robo_v3(arduino: serial.Serial) -> None:
    """
    Sends an 'a' byte to the connected Arduino.
    Its specific purpose in this client's main loop is not immediately clear
    from the original `run_client` logic if `send_client_message` always sends 'h'.

    Args:
        arduino (serial.Serial): The active serial connection object to the Arduino.
    """
    if arduino and arduino.is_open:
        try:
            arduino.write(b'a')
            logging.debug("Sent 'a' byte to Arduino (send_robo_v3).")
        except serial.SerialException as se:
            logging.error(f"Serial error sending 'a' to Arduino: {se}")
            print(f"Serial error sending 'a': {se}")
        except Exception as e:
            logging.error(f"Unexpected error sending 'a' to Arduino: {e}")
            print(f"Unexpected error sending 'a': {e}")
    else:
        logging.warning("Arduino not connected or port not open. Cannot send 'a'.")
        print("Arduino not connected. Cannot send 'a'.")

def receive_massage_v3(arduino: serial.Serial) -> None:
    """
    Waits to receive a single byte from the Arduino.
    This function blocks until a byte is received or timeout occurs.
    The received byte is not returned or used by this function directly.
    It seems to function as a blocking acknowledgment or signal wait.

    Args:
        arduino (serial.Serial): The active serial connection object to the Arduino.
    """
    if not (arduino and arduino.is_open):
        logging.warning("Arduino not connected or port not open. Cannot receive message.")
        print("Arduino not connected. Cannot receive message.")
        return
    try:
        logging.debug("Waiting for a byte from Arduino (receive_massage_v3)...")
        while True:
            temp = arduino.read(1)
            if temp:
                logging.debug(f"Received a byte from Arduino: {temp}")
                break # Exit once a byte is received
            # If temp is empty, loop continues due to serial timeout=1
            logging.debug("Still waiting for byte from Arduino...")
    except serial.SerialException as se:
        logging.error(f"Serial error waiting for byte from Arduino: {se}")
        print(f"Serial error receiving: {se}")
    except Exception as e:
        logging.error(f"Unexpected error waiting for byte from Arduino: {e}")
        print(f"Unexpected error receiving: {e}")


def receive_image(my_socket: socket.socket, aes_protocol: MyAES) -> None:
    """
    Receives an encrypted image file and its checksum from the server,
    decrypts it, verifies the checksum, and saves the image.
    (Identical in structure to client1's receive_image)

    Args:
        my_socket (socket.socket): The connected socket to the server.
        aes_protocol (MyAES): The AES protocol object for decryption.
    """
    try:
        logging.info("Attempting to receive image from server...")
        encrypted_data = protocol.recv_encrypted_msg(my_socket, aes_protocol)
        if not encrypted_data:
            logging.error("Failed to receive encrypted image data from server.")
            return

        encrypted_chk = protocol.recv_encrypted_msg(my_socket, aes_protocol)
        if not encrypted_chk:
            logging.error("Failed to receive encrypted checksum from server.")
            return

        chk_decoded = encrypted_chk.decode()
        logging.debug("Received encrypted image data and checksum.")

        retries = 0
        max_retries = 3
        while not protocol.is_checksum(chk_decoded, encrypted_data) and retries < max_retries:
            logging.warning(f"Checksum mismatch for received image. Requesting resend (attempt {retries + 1}).")
            protocol.encrypt_and_send_msg("again".encode(), my_socket, aes_protocol)

            encrypted_data = protocol.recv_encrypted_msg(my_socket, aes_protocol)
            if not encrypted_data: logging.error(f"Failed to receive resent image (attempt {retries + 1})."); return
            encrypted_chk = protocol.recv_encrypted_msg(my_socket, aes_protocol)
            if not encrypted_chk: logging.error(f"Failed to receive resent checksum (attempt {retries + 1})."); return
            chk_decoded = encrypted_chk.decode()
            retries += 1

        if not protocol.is_checksum(chk_decoded, encrypted_data):
            logging.error(f"Checksum mismatch after {max_retries} retries. Aborting image receive.")
            protocol.encrypt_and_send_msg("error:checksum_failed".encode(), my_socket, aes_protocol)
            return

        logging.info("Image checksum verified. Sending 'ok' to server.")
        protocol.encrypt_and_send_msg("ok".encode(), my_socket, aes_protocol)

        try:
            with open(IMAGE_FILENAME, 'wb') as f:
                f.write(encrypted_data)
            logging.info(f"Received and saved image as '{IMAGE_FILENAME}'")
            print(f"Received image: {IMAGE_FILENAME}")
        except IOError as e:
            logging.error(f"IOError saving image '{IMAGE_FILENAME}': {e}")
            print(f"Error saving image: {e}")
        except Exception as e:
            logging.error(f"Unexpected error saving image '{IMAGE_FILENAME}': {e}")
            print(f"Error saving image: {e}")

    except (socket.error, AttributeError) as e:
        logging.error(f"Socket or AES protocol error during image reception: {e}")
    except UnicodeDecodeError as e:
        logging.error(f"Unicode decode error for checksum during image reception: {e}")
    except Exception as e:
        logging.error(f"Unexpected error during image reception: {e}")


def receive_client_messages(conn: socket.socket, aes_protocol: MyAES) -> None:
    """
    Receives and processes messages from the server.
    Handles checksums, "again" requests, "pic" commands, and general messages.
    Updates global variables based on received messages.
    (Identical in structure to client1's receive_client_messages)

    Args:
        conn (socket.socket): The connected socket to the server.
        aes_protocol (MyAES): The AES protocol object for decryption.
    """
    global send_again, did_send, last_massage, msg # msg is updated here
    try:
        encrypted_msg_data = protocol.recv_encrypted_msg(conn, aes_protocol)
        if not encrypted_msg_data:
            logging.warning("No data received from server. Connection might be closed.")
            msg = EXIT_CMD # Assume server closed, trigger exit
            return

        full_msg_decoded = encrypted_msg_data.decode()
        try:
            chk, current_msg_content = full_msg_decoded.split('{', 1)
        except ValueError:
            logging.error(f"Received message from server in unexpected format: {full_msg_decoded}")
            msg = EXIT_CMD
            return

        chk = chk.lstrip("0")
        logging.debug(f"Received from server: chk='{chk}', content='{current_msg_content}'")
        msg = current_msg_content

        if not current_msg_content:
            logging.warning("Received empty message content from server.")
            return

        if current_msg_content == "again":
            logging.info("Server requested resend ('again'). Preparing to resend last message.")
            did_send = True
            if last_massage:
                 protocol.encrypt_and_send_msg(last_massage.encode(), conn, aes_protocol)
            else:
                logging.warning("Server requested 'again', but no 'last_massage' to resend.")

        elif not protocol.is_checksum(chk, current_msg_content):
            logging.warning("Checksum mismatch for message from server. Requesting server resend.")
            protocol.encrypt_and_send_msg("again".encode(), conn, aes_protocol)
            did_send = True

        elif current_msg_content == "pic":
            logging.info("Received 'pic' command from server. Initiating image reception.")
            receive_image(conn, aes_protocol)
        else:
            logging.info(f"Received from server: '{current_msg_content}'")
            print(f"Client received: {current_msg_content}")

    except (socket.error, AttributeError) as e:
        logging.error(f"Socket or AES error receiving message from server: {e}")
        msg = EXIT_CMD
    except UnicodeDecodeError as e:
        logging.error(f"Unicode decode error for message from server: {e}")
        msg = EXIT_CMD
    except Exception as e:
        logging.error(f"Unexpected error receiving message from server: {e}")
        msg = EXIT_CMD


def send_client_message(conn: socket.socket, aes_protocol: MyAES, arduino: serial.Serial | None) -> None:
    """
    Sends a hardcoded message 'h' to the server after waiting for an Arduino acknowledgment.
    This typically serves as an acknowledgment from this client (robot).
    Updates global variables.

    Args:
        conn (socket.socket): The connected socket to the server.
        aes_protocol (MyAES): The AES protocol object for encryption.
        arduino (serial.Serial | None): The active serial connection to Arduino, or None.
    """
    global msg, last_massage, did_send

    if did_send: # If receive_client_messages already sent something
        did_send = False
        logging.debug("send_client_message: did_send was true, skipping send of 'h'.")
        return

    if not arduino:
        logging.error("Arduino not available, cannot get acknowledgment before sending 'h'.")
        # Proceeding to send 'h' anyway as per original logic, but this might be unintended.
        # Consider if 'h' should only be sent if Arduino ack is received.
    else:
        receive_massage_v3(arduino) # Wait for Arduino ack (byte received and discarded)
        logging.debug("Received acknowledgment from Arduino (or timeout).")

    msg_to_send = 'h' # This client always sends 'h' as its data message
    last_massage = msg_to_send
    msg = msg_to_send # Update global msg

    logging.info(f"Sending acknowledgement '{msg_to_send}' to server.")
    try:
        protocol.encrypt_and_send_msg(msg_to_send.encode(), conn, aes_protocol)
    except (socket.error, AttributeError) as e:
        logging.error(f"Socket or AES error sending '{msg_to_send}' to server: {e}")
    except Exception as e:
        logging.error(f"Unexpected error sending '{msg_to_send}' to server: {e}")

def starting_sql_client(my_socket: socket.socket) -> MyAES | None:
    """
    Performs the initial handshake with the server.
    (Identical in structure to client1's starting_sql_client)

    Args:
        my_socket (socket.socket): The connected socket to the server.

    Returns:
        MyAES | None: The established AES protocol object if successful, None otherwise.
    """
    try:
        public_key_data = protocol.recv_msg(my_socket)
        if not public_key_data:
            logging.error("Failed to receive public RSA key from server.")
            return None
        logging.info(f"Received public RSA key from server: {public_key_data.decode()[:30]}...")
        print("Received the server's public key.")

        aes_protocol_instance = MyAES()
        encrypted_aes_key = MyRSA.encrypt_with_key(aes_protocol_instance.export_key(), public_key_data)

        logging.info("Sending encrypted AES key to server.")
        protocol.send_msg(encrypted_aes_key, my_socket)
        print("Sent the encrypted AES key.")

        user_name = "iftach" # Hardcoded
        password = "1234"  # Hardcoded
        auth_msg_str = f"{user_name}!{password}"
        logging.info(f"Sending authentication credentials for user '{user_name}'.")
        protocol.encrypt_and_send_msg(auth_msg_str.encode(), my_socket, aes_protocol_instance)

        receive_client_messages(my_socket, aes_protocol_instance) # Updates global `msg`
        logging.info(f"Authentication response from server: '{msg}'")

        if "connected" in msg:
            return aes_protocol_instance
        else:
            logging.error(f"Authentication failed. Server response: {msg}")
            return None

    except (socket.error, AttributeError) as e:
        logging.error(f"Socket or crypto protocol error during initial handshake: {e}")
        return None
    except Exception as e:
        logging.error(f"Unexpected error during initial handshake: {e}")
        return None


def send_stop_num_to_arduino(num_str: str, arduino: serial.Serial | None) -> None:
    """
    Converts a number string to an integer and sends it as a single byte to the Arduino.
    This is likely a command or data point for the Arduino.

    Args:
        num_str (str): The string representation of the number to send.
        arduino (serial.Serial | None): The active serial connection to Arduino, or None.
    """
    if not (arduino and arduino.is_open):
        logging.warning("Arduino not connected or port not open. Cannot send number.")
        print("Arduino not connected. Cannot send number.")
        return
    try:
        # The original code printed global `msg` here, which might be confusing
        # if `num_str` is different. Let's log `num_str`.
        logging.debug(f"Attempting to send number string '{num_str}' to Arduino.")
        print(f"Sending to Arduino: {num_str}") # Original code printed global `msg`

        stop_number = int(num_str)
        if 0 <= stop_number <= 255: # Ensure it fits in one byte
            arduino.write(bytes([stop_number]))
            logging.info(f"Sent number {stop_number} (as byte) to Arduino.")
        else:
            logging.error(f"Number {stop_number} is out of byte range (0-255). Cannot send to Arduino.")
            print(f"Number {stop_number} is out of byte range.")
    except ValueError:
        logging.error(f"Cannot convert '{num_str}' to an integer to send to Arduino.")
        print(f"Error: '{num_str}' is not a valid number.")
    except serial.SerialException as se:
        logging.error(f"Serial error sending number to Arduino: {se}")
        print(f"Serial error sending number: {se}")
    except Exception as e:
        logging.error(f"Unexpected error sending number to Arduino: {e}")
        print(f"Unexpected error sending number: {e}")


def run_client() -> None:
    """
    Main function for client2.
    Connects to server, authenticates, connects to Arduino.
    Enters a loop to receive commands (numbers) from the server, send them to Arduino,
    and send an acknowledgment ('h') back to the server.
    """
    global msg # Used for EXIT_CMD check and by send_stop_num_to_arduino via print
    my_socket = socket.socket()
    aes_protocol_instance = None
    arduino_conn = None

    logging.info("Client2 starting...")

    try:
        logging.info(f"Attempting to connect to server at {HOST_NAME}:{PORT}...")
        my_socket.connect((HOST_NAME, PORT))
        print(f"Connected to server: {HOST_NAME}:{PORT}")
        logging.info(f"Successfully connected to server: {HOST_NAME}:{PORT}")

        aes_protocol_instance = starting_sql_client(my_socket)
        if not aes_protocol_instance:
            logging.critical("Failed to establish secure session with server. Exiting.")
            print("Could not establish secure session. Exiting.")
            return

        # Server might send an initial message after auth, handled by starting_sql_client's call
        # to receive_client_messages. Global `msg` has that response.

        arduino_conn = connect_to_robo_v3()
        if not arduino_conn:
            logging.error("Failed to connect to Arduino. Client will attempt to run but Arduino interaction will fail.")
            # Client will proceed, but send_stop_num_to_arduino and receive_massage_v3 will log errors.

        logging.info("Entering main communication loop...")
        while True:
            # Receive first command/number from server
            receive_client_messages(my_socket, aes_protocol_instance) # global `msg` now holds server data
            if msg == EXIT_CMD: break
            send_stop_num_to_arduino(msg, arduino_conn) # Send it to Arduino

            # Receive second command/number from server
            receive_client_messages(my_socket, aes_protocol_instance) # global `msg` updated
            if msg == EXIT_CMD: break
            send_stop_num_to_arduino(msg, arduino_conn) # Send it to Arduino

            # Send acknowledgment 'h' to server
            send_client_message(my_socket, aes_protocol_instance, arduino_conn) # This will set global `msg` to 'h'

            if msg == EXIT_CMD: # Check if the 'h' somehow became EXIT_CMD (unlikely here)
                logging.info(f"Received/Sent EXIT_CMD ('{EXIT_CMD}'). Exiting client.")
                print("Server/Client requested exit. Closing client.")
                break
            # Add a small delay if necessary: time.sleep(0.1)

    except socket.error as sock_err:
        logging.error(f"Socket error in client: {sock_err}")
        print(f"Socket error: {sock_err}")
    except serial.SerialException as ser_err:
        logging.error(f"Serial communication error in client: {ser_err}")
        print(f"Serial error: {ser_err}")
    except KeyboardInterrupt:
        logging.info("Client shutdown initiated by user (KeyboardInterrupt).")
        print("\nClient exiting...")
    except Exception as e:
        logging.error(f"An unexpected error occurred in client: {e}", exc_info=True)
        print(f"An error occurred: {e}")
    finally:
        if arduino_conn and arduino_conn.is_open:
            try:
                arduino_conn.close()
                logging.info("Arduino serial connection closed.")
                print("Arduino connection closed.")
            except Exception as e:
                logging.error(f"Error closing Arduino connection: {e}")
        if my_socket:
            try:
                my_socket.close()
                logging.info("Socket connection to server closed.")
                print("Socket closed.")
            except Exception as e:
                 logging.error(f"Error closing socket: {e}")
        logging.info("Client2 finished.")


if __name__ == '__main__':
    # Logging is configured at the top of the file
    run_client()
