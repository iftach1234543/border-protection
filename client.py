"""
Author: Iftach kasorla
Date: 3/6/25
Description: a simple TLS client (no GUI) for a sensor robot.
Connects to a server, authenticates, exchanges encrypted messages,
and interacts with an Arduino via serial communication.
"""
import logging
import socket
import protocol # Assuming protocol.py exists
from aes import MyAES # Assuming aes.py and MyAES class exist
from rsa import MyRSA # Assuming rsa.py and MyRSA class exist
import serial
import time

# Configure serial port (change 'COM3' to your Arduino's port if different)
arduino_port = 'COM3'
baud_rate = 9600

HOST_NAME = '127.0.0.1' # Server's hostname or IP address
PORT = 8443             # Server's port
EXIT_CMD = 'by by'      # Command from server that signals client to exit
# USER_INPUT = 'please enter a command: ' # Unused global variable
send_again = False # Flag to indicate if the last message needs to be resent
did_send = False   # Flag to indicate if a message was just sent (e.g., by receive_client_messages)
last_massage = ''  # Stores the last message sent by this client
IMAGE_FILENAME = "received_image.jpg" # Filename to save received images
DEFAULT_MSG = "DEFAULT" # Default message content, purpose unclear in current logic
msg = ''           # Holds the current message received from server or to be sent (from Arduino)

# Configure logging at the beginning
logging.basicConfig(
    format='%(asctime)s | %(levelname)s | CLIENT1 - %(message)s',
    datefmt='%m/%d/%Y %I:%M:%S %p',
    level=logging.INFO,
    filename='tls_client1.log', # Changed filename to be specific to client1
    filemode='w'
)

def connect_to_robo_v3() -> serial.Serial | None:
    """
    Establishes a serial connection to the Arduino (robot).
    Sends an initial 'a' byte to the Arduino.

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
            arduino.write(b'a')  # Start robot v3 communication / signal
            logging.debug("Sent initial 'a' byte to Arduino.")
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
    Typically used as a signal or keep-alive.

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


def receive_massage_v3(arduino: serial.Serial) -> str | None:
    """
    Receives two bytes from the Arduino and formats them as "byte1_ord@byte2_ord".
    This is a blocking call until two bytes are received or timeout occurs on read.

    Args:
        arduino (serial.Serial): The active serial connection object to the Arduino.

    Returns:
        str | None: The formatted string from Arduino data if successful, None on error or timeout.
    """
    if not (arduino and arduino.is_open):
        logging.warning("Arduino not connected or port not open. Cannot receive message.")
        print("Arduino not connected. Cannot receive message.")
        return None
    try:
        while True: # Loop to ensure we get the first byte
            temp1 = arduino.read(1)
            if temp1:
                # Now try to get the second byte
                temp2 = arduino.read(1)
                if temp2:
                    val1 = ord(temp1)
                    val2 = ord(temp2)
                    formatted_msg = f"{val1}@{val2}"
                    logging.debug(f"Received from Arduino: byte1={val1}, byte2={val2}. Formatted: '{formatted_msg}'")
                    return formatted_msg
                else:
                    logging.warning("Received first byte from Arduino, but timed out waiting for the second.")
                    # Potentially incomplete message, decide how to handle. Returning None for now.
                    return None
            # If temp1 is empty, the loop continues due to timeout=1 on Serial.
            # This could be problematic if Arduino never sends data.
            # Adding a counter or a more robust timeout mechanism might be needed for production.
            logging.debug("Waiting for data from Arduino...") # Log if read call returns empty
    except serial.SerialException as se:
        logging.error(f"Serial error receiving message from Arduino: {se}")
        print(f"Serial error receiving: {se}")
        return None
    except Exception as e:
        logging.error(f"Unexpected error receiving message from Arduino: {e}")
        print(f"Unexpected error receiving: {e}")
        return None

def receive_image(my_socket: socket.socket, aes_protocol: MyAES) -> None:
    """
    Receives an encrypted image file and its checksum from the server,
    decrypts it, verifies the checksum, and saves the image.

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

        # Loop for checksum verification and requesting resend
        retries = 0
        max_retries = 3 # To prevent infinite loops
        while not protocol.is_checksum(chk_decoded, encrypted_data) and retries < max_retries:
            logging.warning(f"Checksum mismatch for received image. Requesting resend (attempt {retries + 1}).")
            protocol.encrypt_and_send_msg("again".encode(), my_socket, aes_protocol)

            encrypted_data = protocol.recv_encrypted_msg(my_socket, aes_protocol)
            if not encrypted_data:
                logging.error(f"Failed to receive resent encrypted image data (attempt {retries + 1}).")
                return
            encrypted_chk = protocol.recv_encrypted_msg(my_socket, aes_protocol)
            if not encrypted_chk:
                logging.error(f"Failed to receive resent encrypted checksum (attempt {retries + 1}).")
                return
            chk_decoded = encrypted_chk.decode()
            retries += 1

        if not protocol.is_checksum(chk_decoded, encrypted_data):
            logging.error(f"Checksum mismatch after {max_retries} retries. Aborting image receive.")
            # Send a final "not ok" or just give up. Original sends "ok" only on success.
            protocol.encrypt_and_send_msg("error:checksum_failed".encode(), my_socket, aes_protocol) # Example error
            return

        logging.info("Image checksum verified. Sending 'ok' to server.")
        protocol.encrypt_and_send_msg("ok".encode(), my_socket, aes_protocol)

        try:
            with open(IMAGE_FILENAME, 'wb') as f:
                f.write(encrypted_data) # Original code writes encrypted_data, assumes it's decrypted by protocol.recv_encrypted_msg
                                      # If protocol.recv_encrypted_msg returns raw encrypted data, it needs decryption first.
                                      # The current protocol.py decrypts it, so this should be decrypted data.
            logging.info(f"Received and saved image as '{IMAGE_FILENAME}'")
            print(f"Received image: {IMAGE_FILENAME}")
        except IOError as e:
            logging.error(f"IOError saving image '{IMAGE_FILENAME}': {e}")
            print(f"Error saving image: {e}")
        except Exception as e:
            logging.error(f"Unexpected error saving image '{IMAGE_FILENAME}': {e}")
            print(f"Error saving image: {e}")

    except (socket.error, AttributeError) as e: # AttributeError for aes_protocol methods
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
        # Expecting "checksum{message_content}"
        try:
            chk, current_msg_content = full_msg_decoded.split('{', 1)
        except ValueError:
            logging.error(f"Received message from server in unexpected format: {full_msg_decoded}")
            msg = EXIT_CMD # Treat as critical error, trigger exit
            return

        chk = chk.lstrip("0") # Remove leading zeros from checksum string
        logging.debug(f"Received from server: chk='{chk}', content='{current_msg_content}'")
        msg = current_msg_content # Update global msg

        if not current_msg_content:
            logging.warning("Received empty message content from server.")
            # msg is already set to empty, loop might continue depending on EXIT_CMD check
            return

        if current_msg_content == "again":
            logging.info("Server requested resend ('again'). Preparing to resend last message.")
            did_send = True # Flag to resend last_massage by send_client_message
            # The original code sends last_massage here directly.
            # For consistency with send_client_message's logic, we'll let it handle it.
            # However, the server might expect an immediate response.
            # Let's send it here as original code implied.
            if last_massage: # Ensure there is a last message to send
                 protocol.encrypt_and_send_msg(last_massage.encode(), conn, aes_protocol)
            else:
                logging.warning("Server requested 'again', but no 'last_massage' to resend.")
                # Send a default or error? For now, do nothing more.
            # `msg` is "again", so the main loop won't process it as a data command.

        elif not protocol.is_checksum(chk, current_msg_content):
            logging.warning("Checksum mismatch for message from server. Requesting server resend.")
            protocol.encrypt_and_send_msg("again".encode(), conn, aes_protocol)
            did_send = True # To prevent send_client_message from sending the faulty `msg`
            # `msg` holds the faulty content, but `did_send` will make `send_client_message` skip.

        elif current_msg_content == "pic":
            logging.info("Received 'pic' command from server. Initiating image reception.")
            receive_image(conn, aes_protocol)
            # `msg` is "pic", main loop might act on this if not EXIT_CMD.

        else:
            # This is a general message from the server
            logging.info(f"Received from server: '{current_msg_content}'")
            print(f"Client received: {current_msg_content}")
            # `msg` is updated with this content for the main loop.

    except (socket.error, AttributeError) as e:
        logging.error(f"Socket or AES error receiving message from server: {e}")
        msg = EXIT_CMD # Assume critical error, trigger exit
    except UnicodeDecodeError as e:
        logging.error(f"Unicode decode error for message from server: {e}")
        msg = EXIT_CMD
    except Exception as e:
        logging.error(f"Unexpected error receiving message from server: {e}")
        msg = EXIT_CMD


def send_client_message(conn: socket.socket, aes_protocol: MyAES, arduino: serial.Serial | None) -> None:
    """
    Sends a message to the server. If `did_send` is True, it means a message
    was already handled by `receive_client_messages` (e.g. "again" response), so it skips.
    Otherwise, it reads a message from the Arduino and sends it.
    Updates global variables.

    Args:
        conn (socket.socket): The connected socket to the server.
        aes_protocol (MyAES): The AES protocol object for encryption.
        arduino (serial.Serial | None): The active serial connection to Arduino, or None.
    """
    global msg, last_massage, did_send

    if did_send: # If receive_client_messages already sent something (like an "again" confirmation)
        did_send = False
        logging.debug("send_client_message: did_send was true, skipping send from Arduino.")
        return

    if not arduino:
        logging.error("Arduino not available, cannot get message to send.")
        # Optionally, send a placeholder or error message to server
        # For now, we just don't send anything if Arduino is down.
        # This might break server's expectation of a message.
        return

    arduino_data = receive_massage_v3(arduino)
    if arduino_data is not None:
        msg_to_send = arduino_data
        last_massage = msg_to_send # Update last_massage with what we are about to send
        # The global `msg` is also updated, though its immediate use after this send is for server's response.
        msg = msg_to_send

        logging.info(f"Sending to server (from Arduino): '{msg_to_send}'")
        try:
            protocol.encrypt_and_send_msg(msg_to_send.encode(), conn, aes_protocol)
        except (socket.error, AttributeError) as e:
            logging.error(f"Socket or AES error sending message to server: {e}")
            # Potentially set global msg to EXIT_CMD or handle error to break main loop
        except Exception as e:
            logging.error(f"Unexpected error sending message to server: {e}")
    else:
        logging.warning("Failed to receive message from Arduino. Nothing sent to server.")
        # Server will eventually timeout or client might send a default heartbeat if implemented.


def starting_sql_client(my_socket: socket.socket) -> MyAES | None:
    """
    Performs the initial handshake with the server:
    1. Receives the server's public RSA key.
    2. Generates an AES key, encrypts it with the server's public RSA key, and sends it.
    3. Sends hardcoded authentication credentials.
    4. Receives an authentication response from the server.

    Args:
        my_socket (socket.socket): The connected socket to the server.

    Returns:
        MyAES | None: The established AES protocol object if successful, None otherwise.
    """
    try:
        # Receive the RSA public key
        public_key_data = protocol.recv_msg(my_socket)
        if not public_key_data:
            logging.error("Failed to receive public RSA key from server.")
            return None
        logging.info(f"Received public RSA key from server: {public_key_data.decode()[:30]}...") # Log snippet
        print("Received the server's public key.")

        # Create the AES key and send it encrypted with the RSA public key
        aes_protocol_instance = MyAES()
        encrypted_aes_key = MyRSA.encrypt_with_key(aes_protocol_instance.export_key(), public_key_data)

        logging.info("Sending encrypted AES key to server.")
        protocol.send_msg(encrypted_aes_key, my_socket)
        print("Sent the encrypted AES key.")

        # Authentication
        user_name = "iftach" # Hardcoded username
        password = "1234"  # Hardcoded password
        auth_msg_str = f"{user_name}!{password}"
        logging.info(f"Sending authentication credentials for user '{user_name}'.")
        protocol.encrypt_and_send_msg(auth_msg_str.encode(), my_socket, aes_protocol_instance)

        # Receive authentication response
        # This call updates global `msg`
        receive_client_messages(my_socket, aes_protocol_instance)
        logging.info(f"Authentication response from server: '{msg}'") # global msg was set by receive_client_messages

        if "connected" in msg: # Check if auth was successful based on server's response
            return aes_protocol_instance
        else:
            logging.error(f"Authentication failed. Server response: {msg}")
            return None

    except (socket.error, AttributeError) as e: # AttributeError for MyRSA/MyAES methods
        logging.error(f"Socket or crypto protocol error during initial handshake: {e}")
        return None
    except Exception as e:
        logging.error(f"Unexpected error during initial handshake: {e}")
        return None


def run_client() -> None:
    """
    Main function for the client.
    Establishes connection with the server, performs handshake and authentication,
    connects to Arduino, and then enters a loop to send Arduino data to the server
    and receive responses. Exits if the server sends EXIT_CMD or on error.
    """
    global msg # Used for EXIT_CMD check
    my_socket = socket.socket()
    aes_protocol_instance = None
    arduino_conn = None

    logging.info("Client1 starting...")

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

        # Initial message after authentication (server might send one)
        # The original code had a receive_client_messages here.
        # This is already handled at the end of starting_sql_client.
        # If an additional message is expected, uncomment:
        # receive_client_messages(my_socket, aes_protocol_instance)
        # logging.info(f"Post-authentication message from server: '{msg}'")


        arduino_conn = connect_to_robo_v3()
        if not arduino_conn:
            logging.error("Failed to connect to Arduino. Client will run without Arduino interaction.")
            # Decide if client should exit or run in a limited mode
            # For now, it will continue, and send_client_message will log errors.

        logging.info("Entering main communication loop...")
        while True:
            send_client_message(my_socket, aes_protocol_instance, arduino_conn)
            receive_client_messages(my_socket, aes_protocol_instance) # Updates global `msg`

            if arduino_conn: # Only send to Arduino if connected
                send_robo_v3(arduino_conn) # Send keep-alive or trigger

            if msg == EXIT_CMD:
                logging.info(f"Received EXIT_CMD ('{EXIT_CMD}') from server. Exiting client.")
                print("Server requested exit. Closing client.")
                break
            # Add a small delay to prevent busy-looping if desired, e.g., time.sleep(0.1)

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
        logging.info("Client1 finished.")


if __name__ == '__main__':
    # Logging is configured at the top of the file
    run_client()
