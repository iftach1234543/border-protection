"""
Author: iftach kasorla
Date: 3/6/25
Description: a server that uses encryption/decryption and SQLite user authentication
"""
import socket
import sqlite3
import hashlib
from rsa import MyRSA # Assuming rsa.py and MyRSA class exist
from aes import MyAES   # Assuming aes.py and MyAES class exist
import protocol         # Assuming protocol.py exists
import logging

IP_ADDR = '0.0.0.0'
PORT = 8443
QUEUE_LEN = 1
# MSG = 'have a nice day' # This global variable seems unused in the main logic
EXIT_CMD = 'exit' # This global variable seems unused in the main logic
EXIT_RES = 'by by'
# USER_INPUT = 'please enter a command: ' # This global variable seems unused
send_again = False
did_send = False
last_massage = '' # Stores the last message sent to a client, used to avoid re-sending identical data or sending "DEFULT"
msg = '' # Holds the current message to be processed or sent
IMAGE_FILENAME = 'my_pic.jpg'
IS_FIRST = True # Flag to indicate if it's the first set of interactions for authentication attempts
num1 = 0 # Counter for successful authentication attempts to eventually set IS_FIRST to False

DATABASE_NAME = "server_users.db"

# Configure logging at the beginning
logging.basicConfig(
    format='%(asctime)s | %(levelname)s | SERVER - %(message)s',
    datefmt='%m/%d/%Y %I:%M:%S %p',
    level=logging.INFO,
    filename='tls_server.log',
    filemode='w'
)

# ------------------- DATABASE FUNCTIONS -------------------

def hash_password(password: str) -> str:
    """
    Hash a password using SHA-256.

    Args:
        password (str): The password to hash.

    Returns:
        str: The hexadecimal representation of the hashed password.
    """
    return hashlib.sha256(str(password).encode()).hexdigest()

def init_database() -> None:
    """
    Initialize the SQLite database and create the 'users' table if it doesn't exist.
    Logs success or errors during database initialization.
    """
    conn = None
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username VARCHAR(50) UNIQUE NOT NULL,
                password_hash VARCHAR(64) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()
        logging.info(f"Database '{DATABASE_NAME}' initialized successfully.")
    except sqlite3.Error as e:
        logging.error(f"Error initializing database '{DATABASE_NAME}': {e}")
    finally:
        if conn:
            conn.close()

def add_user(username: str, password: str) -> bool:
    """
    Add a new user to the database with a hashed password.
    Uses 'INSERT OR IGNORE' to avoid errors if the username already exists.

    Args:
        username (str): The username for the new user.
        password (str): The password for the new user.

    Returns:
        bool: True if the user was added or already existed (due to IGNORE),
              False on other SQLite errors (though less likely with IGNORE for primary conflicts).
    """
    conn = None
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        password_hash = hash_password(password)
        cursor.execute(
            "INSERT OR IGNORE INTO users (username, password_hash) VALUES (?, ?)",
            (username, password_hash)
        )
        conn.commit()
        logging.info(f"User '{username}' processed for addition (added or already existed).")
        return True
    except sqlite3.Error as e: # Catches general SQLite errors beyond IntegrityError handled by IGNORE
        logging.error(f"Error adding user '{username}': {e}")
        return False
    finally:
        if conn:
            conn.close()

def populate_initial_users() -> None:
    """
    Populate the database with a predefined set of initial users.
    Calls add_user for each user in the initial_users dictionary.
    """
    initial_users = {"iftach": 1234, "gali": 1212, "yoav": 5647}
    logging.info("Populating initial users...")
    for username, password in initial_users.items():
        if add_user(username, str(password)): # Ensure password is treated as string for hashing
            logging.debug(f"Initial user '{username}' processed.")
        else:
            logging.warning(f"Failed to process initial user '{username}'.")
    logging.info("Finished populating initial users.")

def authenticate_user(username: str, password: str) -> bool:
    """
    Authenticate a user against the SQLite database using their username and password.

    Args:
        username (str): The username to authenticate.
        password (str): The password to authenticate.

    Returns:
        bool: True if authentication is successful, False otherwise.
    """
    conn = None
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        password_hash = hash_password(password)
        cursor.execute(
            "SELECT COUNT(*) FROM users WHERE username = ? AND password_hash = ?",
            (username, password_hash)
        )
        result = cursor.fetchone()
        if result and result[0] > 0:
            logging.info(f"User '{username}' authenticated successfully.")
            return True
        else:
            logging.warning(f"Authentication failed for user '{username}'.")
            return False
    except sqlite3.Error as e:
        logging.error(f"Database error during authentication for user '{username}': {e}")
        return False
    finally:
        if conn:
            conn.close()

# ------------------- SERVER LOGIC -------------------

def send_image(conn: socket.socket, aes_protocol: MyAES) -> None:
    """
    Sends an image file (IMAGE_FILENAME) to the connected client,
    encrypted with the provided AES protocol. Handles file not found
    and other exceptions during the process.

    Args:
        conn (socket.socket): The client's socket connection.
        aes_protocol (MyAES): The AES encryption/decryption object for this client.
    """
    try:
        with open(IMAGE_FILENAME, 'rb') as f:
            image_data = f.read()
        logging.debug(f"Read image file '{IMAGE_FILENAME}' for sending.")

        chk_sum = protocol.calculate_checksum(image_data)
        encrypted_image_data = aes_protocol.encrypt(image_data)
        protocol.send_msg(encrypted_image_data, conn)
        logging.debug(f"Sent encrypted image data to client {conn.getpeername()}.")

        encrypted_chk_sum = aes_protocol.encrypt(chk_sum.encode())
        protocol.send_msg(encrypted_chk_sum, conn)
        logging.debug(f"Sent encrypted checksum to client {conn.getpeername()}.")

        # Wait for client confirmation
        confirmation_data = protocol.recv_encrypted_msg(conn, aes_protocol)
        if not confirmation_data:
            logging.warning(f"No confirmation received from client {conn.getpeername()} after sending image.")
            return # Or handle error appropriately

        confirmation_msg_decoded = confirmation_data.decode()
        # Assuming protocol for confirmation is "checksum{status}"
        received_chk, status_msg = confirmation_msg_decoded.split('{', 1)

        # Loop for resending if confirmation is not "ok"
        # This loop structure assumes client sends "checksum{again}" or similar
        # if the image or checksum was not received correctly.
        retry_attempts = 0
        max_retries = 3 # Prevent infinite loop
        while not status_msg == "ok" and retry_attempts < max_retries:
            logging.warning(f"Client {conn.getpeername()} did not confirm image receipt with 'ok' (status: {status_msg}). Retrying...")
            protocol.send_msg(encrypted_image_data, conn) # Resend image
            protocol.send_msg(encrypted_chk_sum, conn)   # Resend checksum

            confirmation_data = protocol.recv_encrypted_msg(conn, aes_protocol)
            if not confirmation_data:
                logging.error(f"No confirmation received on retry {retry_attempts + 1} from {conn.getpeername()}. Aborting image send.")
                return
            confirmation_msg_decoded = confirmation_data.decode()
            received_chk, status_msg = confirmation_msg_decoded.split('{', 1)
            retry_attempts += 1

        if status_msg == "ok":
            logging.info(f"Successfully sent image '{IMAGE_FILENAME}' to client {conn.getpeername()} and received 'ok'.")
        else:
            logging.error(f"Failed to send image '{IMAGE_FILENAME}' to client {conn.getpeername()} after {max_retries} retries (final status: {status_msg}).")

    except FileNotFoundError:
        logging.error(f"Image file '{IMAGE_FILENAME}' not found on server.")
        try:
            protocol.encrypt_and_send_msg("Image not found".encode(), conn, aes_protocol)
        except (socket.error, Exception) as send_err:
            logging.error(f"Failed to send 'Image not found' error to client {conn.getpeername() if conn else 'N/A'}: {send_err}")
    except (socket.error, AttributeError) as e: # AttributeError for aes_protocol methods if not MyAES
        logging.error(f"Socket or AES protocol error sending image to client {conn.getpeername() if conn else 'N/A'}: {e}")
    except Exception as e:
        logging.error(f"Unexpected error sending image to client {conn.getpeername() if conn else 'N/A'}: {e}")
        try:
            if conn: # Ensure conn is valid before trying to send an error message
                protocol.encrypt_and_send_msg("Error sending image".encode(), conn, aes_protocol)
        except (socket.error, Exception) as send_err:
            logging.error(f"Failed to send 'Error sending image' to client {conn.getpeername() if conn else 'N/A'}: {send_err}")


def starting_sql(rsa_protocol_instance: MyRSA, conn: socket.socket) -> MyAES | None:
    """
    Performs the initial RSA key exchange with the client to establish a shared AES key.
    Sends the server's public RSA key and receives an AES key encrypted by the client.

    Args:
        rsa_protocol_instance (MyRSA): The server's RSA object (used to get the public key).
        conn (socket.socket): The client's socket connection.

    Returns:
        MyAES | None: An initialized MyAES object with the shared key if successful,
                      None otherwise.
    """
    try:
        public_key = rsa_protocol_instance.export_public_key()
        # temp_checksum = protocol.calculate_checksum(public_key) # Checksum of public key was calculated but not obviously used in original code
        protocol.send_msg(public_key, conn)
        logging.info(f"Sent public RSA key to client {conn.getpeername()}.")

        # Receive the AES key encrypted by the public key
        encrypted_aes_key = protocol.recv_encrypted_msg(conn, rsa_protocol_instance) # Decrypt with server's private RSA key
        if not encrypted_aes_key:
            logging.error(f"Failed to receive encrypted AES key from client {conn.getpeername()}.")
            return None

        logging.info(f"Received encrypted AES key from client {conn.getpeername()}.")
        aes_protocol_instance = MyAES(encrypted_aes_key)
        logging.info(f"AES protocol established with client {conn.getpeername()}. Starting encrypted communication.")
        return aes_protocol_instance
    except (socket.error, AttributeError) as e: # AttributeError for rsa/aes_protocol methods if not MyRSA/MyAES
        logging.error(f"Socket or crypto protocol error during key exchange with {conn.getpeername()}: {e}")
        return None
    except Exception as e:
        logging.error(f"Unexpected error during key exchange with {conn.getpeername()}: {e}")
        return None

def receive_server_messages(conn: socket.socket, aes_protocol: MyAES) -> bool:
    """
    Receives and processes messages from a client.
    Handles checksum verification, authentication for the first messages,
    and command processing for subsequent messages.

    Global variables modified: send_again, did_send, last_massage, msg, IS_FIRST, num1.

    Args:
        conn (socket.socket): The client's socket connection.
        aes_protocol (MyAES): The AES protocol object for this client.

    Returns:
        bool: True if a valid non-control message for further processing was received
              (after initial authentication phase), False otherwise.
    """
    global send_again, did_send, last_massage, msg, IS_FIRST, num1
    client_addr = conn.getpeername() if conn else "Unknown client"
    try:
        encrypted_msg_data = protocol.recv_encrypted_msg(conn, aes_protocol)
        if not encrypted_msg_data:
            logging.warning(f"No data received from client {client_addr}. Connection might be closed.")
            return False

        full_msg_decoded = encrypted_msg_data.decode()
        # Expecting "checksum{message_content}"
        try:
            chk, current_msg_content = full_msg_decoded.split('{', 1)
        except ValueError:
            logging.error(f"Received message from {client_addr} in unexpected format: {full_msg_decoded}")
            # Optionally send an error back to the client or handle as a protocol violation
            protocol.encrypt_and_send_msg("error:invalid message format".encode(), conn, aes_protocol)
            return False

        chk = chk.lstrip("0") # Remove leading zeros from checksum string
        logging.debug(f"Received from {client_addr}: chk='{chk}', content='{current_msg_content}'")
        # Update global msg here, so send_server_msg uses the latest
        msg = current_msg_content # This global `msg` will be used by send_server_msg if this function returns True

        if not current_msg_content: # Empty message content after splitting
            logging.warning(f"Received empty message content from {client_addr}.")
            # Decide how to handle: maybe an error, or just ignore.
            return False

        if current_msg_content == "again":
            logging.info(f"Client {client_addr} requested resend ('again').")
            did_send = True # Flag to resend last_massage
            # The original code sends last_massage here directly,
            # but the global `did_send` should trigger it in `send_server_msg`
            # For consistency, let's stick to the original flow and let send_server_msg handle it.
            # However, the client expects an immediate response.
            protocol.encrypt_and_send_msg(last_massage.encode(), conn, aes_protocol)
            return False # Not a message for further server logic processing

        elif not protocol.is_checksum(chk, current_msg_content):
            logging.warning(f"Checksum mismatch for message from {client_addr}. Requesting resend.")
            protocol.encrypt_and_send_msg("again".encode(), conn, aes_protocol)
            did_send = True # To prevent send_server_msg from sending the faulty `msg`
            return False # Not a message for further server logic processing

        elif IS_FIRST: # Authentication phase
            logging.info(f"Authentication attempt from {client_addr}: {current_msg_content}")
            try:
                user_name, password_str = current_msg_content.split("!", 1)
                # It's safer to expect password as string from client, then convert if necessary
                # The original code used int(password), which might fail if password is not purely numeric
                if authenticate_user(user_name, password_str): # Assuming authenticate_user can handle string password
                    response_msg = "you are now connected"
                    last_massage = response_msg # Update last_massage with the response we are sending
                    logging.info(f"User '{user_name}' from {client_addr} authenticated. Sending: '{response_msg}'")
                    protocol.encrypt_and_send_msg(response_msg.encode(), conn, aes_protocol)
                    did_send = True # To indicate a message was just sent, preventing send_server_msg from sending again immediately
                    num1 += 1
                    if num1 >= 3: # Assuming 3 successful authentications from *any* of the first clients
                        logging.info("Authentication phase completed (IS_FIRST = False).")
                        IS_FIRST = False
                else:
                    response_msg = "not existing user name or password"
                    last_massage = response_msg
                    logging.warning(f"Authentication failed for '{user_name}' from {client_addr}. Sending: '{response_msg}'")
                    protocol.encrypt_and_send_msg(response_msg.encode(), conn, aes_protocol)
                    did_send = True
            except ValueError: # If msg.split("!") fails
                response_msg = "invalid authentication format"
                last_massage = response_msg
                logging.error(f"Invalid authentication format from {client_addr}: '{current_msg_content}'. Sending: '{response_msg}'")
                protocol.encrypt_and_send_msg(response_msg.encode(), conn, aes_protocol)
                did_send = True
            except Exception as e: # Catch other potential errors during auth processing
                response_msg = f"server error during authentication: {str(e)}"
                last_massage = response_msg # Even server errors update last_massage for consistency
                logging.error(f"Server error processing authentication for {client_addr}: {e}")
                protocol.encrypt_and_send_msg(response_msg.encode(), conn, aes_protocol)
                did_send = True
            return False # Authentication messages are not for further server logic processing in main loop

        else: # Regular message after authentication
            logging.info(f"Received valid message from {client_addr} (post-auth): '{current_msg_content}'")
            # The global `msg` is already set to current_msg_content
            return True # Indicates a message for the main server logic

    except (socket.error, AttributeError) as e:
        logging.error(f"Socket or AES protocol error receiving/processing message from {client_addr}: {e}")
        return False
    except UnicodeDecodeError as e:
        logging.error(f"Unicode decode error for message from {client_addr}: {e}. Message might not be valid UTF-8 after decryption.")
        # Optionally, send an error message back to the client
        try:
            protocol.encrypt_and_send_msg("error:undecodable message".encode(), conn, aes_protocol)
        except Exception as send_err:
            logging.error(f"Failed to send undecodable message error to {client_addr}: {send_err}")
        return False
    except Exception as e:
        logging.error(f"Unexpected error receiving/processing message from {client_addr}: {e}")
        return False
    # Fallback if no other return path was hit (e.g. if msg was empty initially, though guarded)
    return False


def send_server_msg(conn: socket.socket, aes_protocol: MyAES) -> None:
    """
    Sends a message (held in global `msg`) to the client,
    handling potential resends or default messages.

    Global variables used: msg, last_massage, did_send.
    Global variables modified: did_send, last_massage.

    Args:
        conn (socket.socket): The client's socket connection.
        aes_protocol (MyAES): The AES protocol object for this client.
    """
    global msg, last_massage, did_send
    client_addr = conn.getpeername() if conn else "Unknown client"

    try:
        if did_send: # If a message was already sent by receive_server_messages (e.g., auth response, "again" response)
            did_send = False # Reset flag
            logging.debug(f"send_server_msg: did_send was true, message already sent by receiver for {client_addr}. Skipping send.")
            return

        # Current message to be sent is in global `msg` (set by caller or receive_server_messages)
        message_to_send = msg

        if message_to_send == last_massage and message_to_send != "DEFULT": # Avoid re-sending "DEFULT" if it was the last message
            logging.debug(f"Message to send ('{message_to_send}') is same as last_massage for {client_addr}. Sending 'DEFULT'.")
            message_to_send = "DEFULT"

        # Update last_massage with what we are about to send
        # This should happen regardless of whether it's the original msg or "DEFULT"
        # However, the original code did `last_massage = msg` which means `msg` itself was updated
        # Let's keep the global `msg` as what was intended to be sent, and `message_to_send` as what is actually sent.
        # And `last_massage` should be what was *actually* sent.

        logging.info(f"Sending to {client_addr}: '{message_to_send}' (original global msg was: '{msg}')")
        protocol.encrypt_and_send_msg(message_to_send.encode(), conn, aes_protocol)
        last_massage = message_to_send # Update last_massage to what was actually sent.

        if message_to_send == "pic": # Or should it be if global msg == "pic"? Original used global msg.
                                     # Let's assume if the *actual sent message* is "pic"
            logging.info(f"Message 'pic' sent to {client_addr}, calling send_image.")
            send_image(conn, aes_protocol)

    except (socket.error, AttributeError) as e:
        logging.error(f"Socket or AES protocol error sending message to {client_addr}: {e}")
    except Exception as e:
        logging.error(f"Unexpected error sending message to {client_addr}: {e}")


def main() -> None:
    """
    Main server function.
    Initializes the database, sets up the server socket, and handles client connections
    and communication in a sequential manner for three clients.
    The primary interaction loop involves client1 (conn), client2 (conn1), and client3 (conn2).
    """
    global send_again, did_send, last_massage, msg, IS_FIRST # num1 is also global but managed within receive_server_messages

    logging.info("Server starting...")
    init_database()
    populate_initial_users()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Allow address reuse
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Create RSA instances for each potential client connection early on
    # This way, if one connection fails, we don't re-generate for others unnecessarily
    # The original code created them inside the try block.
    rsa_main_client = MyRSA()
    rsa_client1_instance = MyRSA() # For 'conn1'
    rsa_client2_instance = MyRSA() # For 'conn2'

    conn = None
    conn1 = None
    conn2 = None

    try:
        server_socket.bind((IP_ADDR, PORT))
        server_socket.listen(QUEUE_LEN)
        logging.info(f"Server listening on {IP_ADDR}:{PORT}")

        # Client 1 (conn)
        logging.info("Waiting for client 1 (conn)...")
        conn, addr = server_socket.accept()
        logging.info(f"Client 1 (conn) connected from {addr}")
        aes_protocol_main = starting_sql(rsa_main_client, conn)
        if not aes_protocol_main:
            logging.error(f"AES setup failed for client 1 {addr}. Closing connection.")
            if conn: conn.close()
            return # Critical failure

        # Initial message exchange with client 1
        receive_server_messages(conn, aes_protocol_main) # Handles auth, updates globals
        # send_server_msg will use global `msg` set by receive_server_messages or its default logic
        send_server_msg(conn, aes_protocol_main)

        # Client 2 (conn1)
        logging.info("Waiting for client 2 (conn1)...")
        conn1, addr1 = server_socket.accept()
        logging.info(f"Client 2 (conn1) connected from {addr1}")
        aes_protocol_client1 = starting_sql(rsa_client1_instance, conn1)
        if not aes_protocol_client1:
            logging.error(f"AES setup failed for client 2 {addr1}. Closing connection.")
            if conn1: conn1.close()
            if conn: conn.close() # Close previous connections too on critical failure
            return
        receive_server_messages(conn1, aes_protocol_client1) # Auth for client 2

        # Client 3 (conn2)
        logging.info("Waiting for client 3 (conn2)...")
        conn2, addr2 = server_socket.accept()
        logging.info(f"Client 3 (conn2) connected from {addr2}")
        aes_protocol_client2 = starting_sql(rsa_client2_instance, conn2)
        if not aes_protocol_client2:
            logging.error(f"AES setup failed for client 3 {addr2}. Closing connection.")
            if conn2: conn2.close()
            if conn1: conn1.close()
            if conn: conn.close()
            return
        receive_server_messages(conn2, aes_protocol_client2) # Auth for client 3
        # The original code had another receive_server_messages for conn2 here.
        # This implies client3 sends two messages back-to-back for its initial setup.
        # Or it was an oversight. Assuming client3 sends only one auth message for now.
        # If two are needed, uncomment:
        # receive_server_messages(conn2, aes_protocol_client2)

        # Some initial messages to client 1 again?
        # The global `msg` might still hold the last response from client3's auth.
        # This logic is a bit obscure due to globals.
        send_server_msg(conn, aes_protocol_main)
        send_server_msg(conn, aes_protocol_main)

        # Main communication loop
        logging.info("All clients connected. Starting main communication loop.")
        msg = "start" # Initialize global msg for the loop condition
        while msg != EXIT_RES: # EXIT_RES is 'by by'
            # Receive from client 1 (conn)
            logging.debug(f"Main loop: Waiting for message from client 1 {addr}")
            is_message_for_logic = receive_server_messages(conn, aes_protocol_main)
            # `msg` global is updated by receive_server_messages with client1's message content if valid

            if is_message_for_logic: # A valid data message was received from client 1
                logging.info(f"Main loop: Processing logic for message from client 1: '{msg}'")
                original_client1_msg = msg # Save it before it's potentially modified

                try:
                    # Assuming client1's message is "value1@value2"
                    part1, part2_trash = original_client1_msg.split('@', 1)
                except ValueError:
                    logging.error(f"Message from client 1 '{original_client1_msg}' not in 'value1@value2' format. Skipping logic.")
                    # Send the original (potentially faulty) message back or an error
                    send_server_msg(conn, aes_protocol_main) # This will send original_client1_msg or DEFULT
                    continue # Go to next iteration of while loop

                temp_part1_for_client2 = part1 # Store part1 for client2 (conn1)

                # Send part1 to client 3 (conn2)
                msg = part1 # Set global msg to what client3 should receive
                did_send = False # Ensure send_server_msg actually sends
                logging.debug(f"Main loop: Sending '{msg}' to client 3 {addr2}")
                send_server_msg(conn2, aes_protocol_client2)

                # Receive decision from client 3 (conn2)
                logging.debug(f"Main loop: Waiting for decision from client 3 {addr2}")
                receive_server_messages(conn2, aes_protocol_client2) # Updates global `msg` with client3's decision
                client3_decision = msg # Store client3's decision

                if client3_decision == "kill":
                    logging.info(f"Main loop: Client 3 decided 'kill'. Relaying to client 2 {addr1}.")
                    # Send temp_part1_for_client2 (part1 from client1) to client 2 (conn1)
                    msg = temp_part1_for_client2
                    last_massage = "hi" # Original code hardcoded this, purpose unclear
                    did_send = False
                    logging.debug(f"Main loop: Sending '{msg}' (part1) to client 2 {addr1}")
                    send_server_msg(conn1, aes_protocol_client1)

                    # Send part2_trash (part2 from client1) to client 2 (conn1)
                    msg = part2_trash
                    did_send = False
                    logging.debug(f"Main loop: Sending '{msg}' (part2) to client 2 {addr1}")
                    send_server_msg(conn1, aes_protocol_client1)

                    # Receive ack from client 2 (conn1)
                    logging.debug(f"Main loop: Waiting for ack from client 2 {addr1}")
                    receive_server_messages(conn1, aes_protocol_client1) # Updates global `msg` with client2's ack
                    logging.info(f"Main loop: Received ack '{msg}' from client 2 {addr1} after 'kill' sequence.")

                    while True:
                        pass # This will make the server unresponsive
                else: # Client 3 did not decide 'kill' (e.g., "no")
                    # Send client3's decision back to client 1 (conn)
                    # `msg` global already holds client3_decision
                    did_send = False
                    logging.debug(f"Main loop: Client 3 decision was '{client3_decision}'. Sending to client 1 {addr}.")
                    send_server_msg(conn, aes_protocol_main)
            else: # No new data message from client 1, or it was a control message ("again", auth)
                  # Send a response to client 1 based on current global `msg` or `last_massage`
                logging.debug(f"Main loop: No new data message from client 1, or it was control. Sending current/last msg to client 1 {addr}.")
                # `did_send` might be true if receive_server_messages handled an "again" or auth response.
                # `send_server_msg` will respect `did_send`.
                # If `receive_server_messages` returned False because connection closed, this send might fail.
                if conn: # Check if conn is still valid
                    send_server_msg(conn, aes_protocol_main)
                else:
                    logging.warning(f"Main loop: Client 1 (conn) seems to be closed. Cannot send message.")
                    break # Exit while loop if primary client is gone

            # Check if global msg became EXIT_RES due to a client message
            if msg == EXIT_RES:
                logging.info(f"EXIT_RES ('{EXIT_RES}') detected. Preparing to exit main loop.")
                break

        logging.info("Exiting main communication loop.")

    except socket.error as sock_err:
        logging.error(f"Socket error in main server operation: {sock_err}")
    except KeyboardInterrupt:
        logging.info("Server shutting down due to KeyboardInterrupt.")
    except Exception as e:
        logging.error(f"An unexpected error occurred in main server operation: {e}", exc_info=True)
    finally:
        logging.info("Closing client connections...")
        if conn:
            try:
                conn.close()
                logging.info(f"Closed connection with client 1 (conn).")
            except socket.error as e:
                logging.error(f"Error closing connection conn: {e}")
        if conn1:
            try:
                conn1.close()
                logging.info(f"Closed connection with client 2 (conn1).")
            except socket.error as e:
                logging.error(f"Error closing connection conn1: {e}")
        if conn2:
            try:
                conn2.close()
                logging.info(f"Closed connection with client 3 (conn2).")
            except socket.error as e:
                logging.error(f"Error closing connection conn2: {e}")

        if server_socket:
            try:
                server_socket.close()
                logging.info("Server socket closed.")
            except socket.error as e:
                logging.error(f"Error closing server socket: {e}")
        logging.info("Server shutdown complete.")

if __name__ == '__main__':
    # Logging is configured at the top of the file now
    main()
