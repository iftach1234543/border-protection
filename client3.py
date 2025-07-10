"""
Author: Iftach Kasorla
Date: 3/6/25
Description: GUI TLS Client with Login and Interactive Interface.
Allows a user to connect to the server, authenticate, and make decisions
based on messages received from the server.
"""
import tkinter as tk
from tkinter import messagebox, ttk
import logging
import socket
import protocol  # Assuming protocol.py exists
from aes import MyAES    # Assuming aes.py and MyAES class exist
from rsa import MyRSA    # Assuming rsa.py and MyRSA class exist
import threading
import queue

HOST_NAME = '127.0.0.1'  # Server's hostname or IP address
PORT = 8443             # Server's port
EXIT_CMD = 'by by'      # Command from server that might signal client to exit (not explicitly handled here)
IMAGE_FILENAME = "received_image.jpg" # Not used in this client's current logic
MSG_DISPLAY_TIME = 5000  # 5 seconds in milliseconds for how long a message might be highlighted or screen stays

class ClientGUI:
    """
    Manages the GUI application for the secure client, including login,
    displaying server messages, and sending user decisions.
    """
    def __init__(self):
        """
        Initializes the main Tkinter window, network components, GUI frames,
        and starts the message queue processor.
        """
        self.root = tk.Tk()
        self.root.title("Secure Client GUI") # More descriptive title
        self.root.geometry("450x350") # Slightly larger for better layout

        logging.info("Initializing ClientGUI application.")

        # Network components
        self.socket: socket.socket | None = None
        self.aes_protocol: MyAES | None = None
        self.message_queue = queue.Queue() # Thread-safe queue for communication between network thread and GUI thread

        # GUI frames
        self.frames = {}
        self._create_frames()
        self.show_frame("LoginScreen")

        # Handle window close event
        self.root.protocol("WM_DELETE_WINDOW", self._on_closing)

        # Start queue handler to process messages from network threads in the main GUI thread
        self.root.after(100, self.process_queue)
        logging.info("ClientGUI initialized and queue processor started.")

    def _create_frames(self) -> None:
        """
        Creates all the different frames (screens) used in the application
        and stores them in the self.frames dictionary.
        """
        logging.debug("Creating GUI frames.")
        # Login Screen
        login_frame = ttk.Frame(self.root, padding="10")
        self._setup_login_screen(login_frame)
        self.frames["LoginScreen"] = login_frame

        # Main Screen
        main_frame = ttk.Frame(self.root, padding="10")
        self._setup_main_screen(main_frame)
        self.frames["MainScreen"] = main_frame

        # Wait Screen
        wait_frame = ttk.Frame(self.root, padding="10")
        self._setup_wait_screen(wait_frame)
        self.frames["WaitScreen"] = wait_frame

        # Decision Screen
        decision_frame = ttk.Frame(self.root, padding="10")
        self._setup_decision_screen(decision_frame)
        self.frames["DecisionScreen"] = decision_frame

        for frame_name, frame_obj in self.frames.items():
            frame_obj.grid(row=0, column=0, sticky="nsew")
            logging.debug(f"Frame '{frame_name}' created and gridded.")
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)


    def _setup_login_screen(self, frame: ttk.Frame) -> None:
        """Sets up the widgets for the login screen."""
        ttk.Label(frame, text="Username:").pack(pady=5)
        self.username_entry = ttk.Entry(frame, width=30)
        self.username_entry.pack(pady=5)
        self.username_entry.focus_set() # Set focus to username entry

        ttk.Label(frame, text="Password:").pack(pady=5)
        self.password_entry = ttk.Entry(frame, show="*", width=30)
        self.password_entry.pack(pady=5)

        ttk.Button(frame, text="Connect", command=self._attempt_login, style="Accent.TButton").pack(pady=20)
        # Allow Enter key to trigger login from password field
        self.password_entry.bind("<Return>", lambda event: self._attempt_login())


    def _setup_main_screen(self, frame: ttk.Frame) -> None:
        """Sets up the widgets for the main control screen."""
        ttk.Label(frame, text="Main Control Panel", font=("Arial", 16)).pack(pady=20)
        ttk.Button(frame, text="START System Process", command=self._send_start, style="Accent.TButton").pack(pady=20, ipadx=10, ipady=5)
        ttk.Button(frame, text="Logout / Disconnect", command=self._logout).pack(pady=10)


    def _setup_wait_screen(self, frame: ttk.Frame) -> None:
        """Sets up the widgets for the waiting screen."""
        self.status_label = ttk.Label(frame, text="Waiting for server message...", font=("Arial", 12), anchor="center")
        self.status_label.pack(pady=50, expand=True)


    def _setup_decision_screen(self, frame: ttk.Frame) -> None:
        """Sets up the widgets for the decision-making screen."""
        ttk.Label(frame, text="Server Request:", font=("Arial", 14)).pack(pady=10)
        self.request_label = ttk.Label(frame, text="", font=("Arial", 12, "bold"), foreground="blue", wraplength=380)
        self.request_label.pack(pady=10)

        button_frame = ttk.Frame(frame)
        ttk.Button(button_frame, text="Send Killer Robot",
                  command=lambda: self._send_decision("kill"), style="Danger.TButton").pack(side=tk.LEFT, padx=20, ipadx=5, ipady=5)
        ttk.Button(button_frame, text="Don't Send",
                  command=lambda: self._send_decision("no"), style="Success.TButton").pack(side=tk.RIGHT, padx=20, ipadx=5, ipady=5)
        button_frame.pack(pady=20)

    def show_frame(self, name: str) -> None:
        """
        Raises the specified frame (screen) to be visible.

        Args:
            name (str): The key name of the frame to show.
        """
        try:
            if name in self.frames:
                frame = self.frames[name]
                frame.tkraise()
                logging.info(f"Showing frame: {name}")
            else:
                logging.warning(f"Attempted to show non-existent frame: {name}")
        except Exception as e:
            logging.error(f"Error showing frame '{name}': {e}")


    def _attempt_login(self) -> None:
        """
        Retrieves username and password from entry fields and starts
        the server connection process in a new thread.
        """
        username = self.username_entry.get()
        password = self.password_entry.get()
        logging.info(f"Login attempt for username: {username}")

        if not username or not password:
            messagebox.showwarning("Login Error", "Username and password cannot be empty.")
            logging.warning("Login attempt with empty username or password.")
            return

        # Disable button to prevent multiple clicks while connecting
        # This would require access to the button widget, e.g., self.login_button
        # For simplicity, this is omitted here but is good practice.

        threading.Thread(target=self._connect_to_server, args=(username, password), daemon=True).start()


    def _connect_to_server(self, username: str, password: str) -> None:
        """
        Connects to the server, performs RSA/AES key exchange, and authenticates.
        This method is designed to run in a separate thread.
        Puts results or errors into the message_queue.

        Args:
            username (str): The username for authentication.
            password (str): The password for authentication.
        """
        logging.info(f"Thread '{threading.current_thread().name}': Attempting to connect to server {HOST_NAME}:{PORT}.")
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(10) # 10-second timeout for connection
            self.socket.connect((HOST_NAME, PORT))
            logging.info("Socket connected to server.")

            # RSA Key Exchange
            logging.debug("Receiving public RSA key from server...")
            public_key = protocol.recv_msg(self.socket)
            if not public_key:
                raise ConnectionError("Failed to receive public RSA key from server.")
            logging.info("Public RSA key received.")

            self.aes_protocol = MyAES() # Client generates its AES key
            encrypted_aes_key = MyRSA.encrypt_with_key(self.aes_protocol.export_key(), public_key)
            logging.debug("Sending encrypted AES key to server...")
            protocol.send_msg(encrypted_aes_key, self.socket)
            logging.info("Encrypted AES key sent.")

            # Send credentials
            auth_msg_str = f"{username}!{password}"
            logging.debug(f"Sending encrypted credentials for user '{username}'...")
            protocol.encrypt_and_send_msg(auth_msg_str.encode(), self.socket, self.aes_protocol)
            logging.info("Credentials sent.")

            # Verify authentication
            logging.debug("Waiting for authentication response from server...")
            response_data = protocol.recv_encrypted_msg(self.socket, self.aes_protocol)
            if not response_data:
                raise ConnectionError("No authentication response from server.")

            response_str = response_data.decode()
            # Assuming server sends "checksum{message}"
            _, auth_response_content = response_str.split('{', 1)
            logging.info(f"Authentication response received: '{auth_response_content}'")

            if "connected" in auth_response_content:
                logging.info(f"User '{username}' authenticated successfully.")
                self.message_queue.put(("show_main", None))
            else:
                logging.warning(f"Authentication failed for user '{username}': {auth_response_content}")
                self.message_queue.put(("error", f"Invalid credentials or server error: {auth_response_content}"))
                if self.socket: self.socket.close(); self.socket = None # Close on auth failure
                self.aes_protocol = None

        except socket.timeout:
            logging.error("Connection to server timed out.")
            self.message_queue.put(("error", "Connection failed: Timed out"))
        except socket.error as se:
            logging.error(f"Socket error during connection/handshake: {se}")
            self.message_queue.put(("error", f"Connection failed: {se}"))
        except ConnectionError as ce: # Custom for logical connection steps
            logging.error(f"Connection process error: {ce}")
            self.message_queue.put(("error", f"Connection process error: {ce}"))
        except Exception as e:
            logging.error(f"Unexpected error in _connect_to_server: {e}", exc_info=True)
            self.message_queue.put(("error", f"Connection failed: An unexpected error occurred ({type(e).__name__})"))
        finally:
            # If socket exists but AES protocol was not set (meaning full success wasn't reached)
            if self.socket and not self.aes_protocol:
                try:
                    self.socket.close()
                    self.socket = None
                except Exception as e_close:
                    logging.error(f"Error closing socket in _connect_to_server finally block: {e_close}")


    def _send_start(self) -> None:
        """
        Sends a "start" command to the server and transitions to the WaitScreen.
        Initiates message receiving in a new thread.
        """
        if self.socket and self.aes_protocol:
            try:
                logging.info("Sending 'start' command to server.")
                protocol.encrypt_and_send_msg("start".encode(), self.socket, self.aes_protocol)
                self.show_frame("WaitScreen")
                threading.Thread(target=self._receive_messages, daemon=True).start()
            except (socket.error, AttributeError) as e: # AttributeError if socket/aes_protocol is None
                logging.error(f"Error sending 'start' command: {e}")
                self.message_queue.put(("error", f"Failed to send 'start': {e}. Please reconnect."))
            except Exception as e:
                logging.error(f"Unexpected error in _send_start: {e}", exc_info=True)
                self.message_queue.put(("error", f"Unexpected error: {e}"))
        else:
            logging.warning("Attempted to send 'start' but not connected.")
            self.message_queue.put(("error", "Not connected to server. Please login again."))


    def _receive_messages(self) -> None:
        """
        Continuously listens for messages from the server in a loop (original broke after one).
        Puts received messages or errors into the message_queue.
        This method is designed to run in a separate thread.
        """
        logging.info(f"Thread '{threading.current_thread().name}': Starting to listen for server messages.")
        # The original code had `while True` but then `break`.
        # If it's meant to receive only one message then transition, the `break` is fine.
        # If it's meant to be a continuous listener until an error or explicit stop, the `break` should be conditional.
        # For this server logic, it seems one message comes, then user decision, then another wait.
        # So, receiving one message then stopping the thread is appropriate.
        if self.socket and self.aes_protocol:
            try:
                logging.debug("Waiting to receive encrypted message from server...")
                encrypted_msg_data = protocol.recv_encrypted_msg(self.socket, self.aes_protocol)
                if not encrypted_msg_data:
                    # This indicates server closed connection or an issue with recv_encrypted_msg
                    logging.warning("No data received from server in _receive_messages, server might have closed connection.")
                    self.message_queue.put(("error", "Connection lost with server."))
                    return # Exit thread

                msg_decoded = encrypted_msg_data.decode()
                 # Assuming server sends "checksum{message}"
                _, msg_content = msg_decoded.split('{', 1)
                logging.info(f"Message received from server: '{msg_content}'")
                self.message_queue.put(("show_message", msg_content))
                # Original had break here, which is fine if only one message is expected before next user action.
            except (socket.error, AttributeError) as e:
                logging.error(f"Socket or AES error in _receive_messages: {e}")
                self.message_queue.put(("error", f"Network error: {e}. Connection may be lost."))
            except UnicodeDecodeError as e:
                logging.error(f"Unicode decode error in _receive_messages: {e}")
                self.message_queue.put(("error", "Received undecodable message from server."))
            except Exception as e:
                logging.error(f"Unexpected error in _receive_messages: {e}", exc_info=True)
                self.message_queue.put(("error", f"Error receiving data: {e}"))
        else:
            logging.warning("_receive_messages called but not connected.")
            self.message_queue.put(("error", "Not connected. Cannot receive messages."))


    def _send_decision(self, decision: str) -> None:
        """
        Sends the user's decision ("kill" or "no") to the server.
        Transitions to WaitScreen and starts listening for more messages.

        Args:
            decision (str): The decision made by the user.
        """
        if self.socket and self.aes_protocol:
            try:
                logging.info(f"Sending decision '{decision}' to server.")
                protocol.encrypt_and_send_msg(decision.encode(), self.socket, self.aes_protocol)
                self.show_frame("WaitScreen")
                # Start a new thread to listen for the next server message
                threading.Thread(target=self._receive_messages, daemon=True).start()
            except (socket.error, AttributeError) as e:
                logging.error(f"Error sending decision '{decision}': {e}")
                self.message_queue.put(("error", f"Failed to send decision: {e}. Please reconnect."))
            except Exception as e:
                logging.error(f"Unexpected error in _send_decision: {e}", exc_info=True)
                self.message_queue.put(("error", f"Unexpected error: {e}"))
        else:
            logging.warning(f"Attempted to send decision '{decision}' but not connected.")
            self.message_queue.put(("error", "Not connected to server. Please login again."))


    def process_queue(self) -> None:
        """
        Periodically checks the message_queue for messages from network threads
        and updates the GUI accordingly. This runs in the main Tkinter thread.
        """
        try:
            # Process all available messages in the queue without blocking
            while True:
                msg_type, content = self.message_queue.get_nowait()
                logging.debug(f"Processing queue message: type='{msg_type}', content='{content}'")
                if msg_type == "show_main":
                    self.show_frame("MainScreen")
                elif msg_type == "show_message":
                    self._display_message(content) # This will show DecisionScreen
                elif msg_type == "error":
                    logging.error(f"Displaying error from queue: {content}")
                    messagebox.showerror("Error", content)
                    # Attempt to clean up and reset
                    if self.socket:
                        try:
                            self.socket.close()
                        except Exception as e_close:
                            logging.error(f"Error closing socket in process_queue after error: {e_close}")
                    self.socket = None
                    self.aes_protocol = None
                    self.show_frame("LoginScreen")
                self.message_queue.task_done() # Signal that a message was processed
        except queue.Empty:
            pass # No messages in the queue, which is normal
        except Exception as e:
            logging.error(f"Unexpected error in process_queue: {e}", exc_info=True)
        finally:
            # Reschedule this method to run again after 100ms
            self.root.after(100, self.process_queue)


    def _display_message(self, message: str) -> None:
        """
        Displays the received message on the DecisionScreen.
        The original code had a timer to re-show the DecisionScreen, which is
        redundant if it's already shown.

        Args:
            message (str): The message from the server to display.
        """
        try:
            self.show_frame("DecisionScreen")
            self.request_label.config(text=message)
            logging.info(f"Displayed message on DecisionScreen: '{message}'")
            # The original self.root.after(MSG_DISPLAY_TIME, self.show_frame, "DecisionScreen")
            # would just re-raise the same screen. If the intent was to timeout the decision,
            # it should transition to a different screen or take a default action.
            # For now, removing the confusing `after` call here. If a timeout is needed:
            # self.root.after(MSG_DISPLAY_TIME, self._handle_decision_timeout)
        except Exception as e:
            logging.error(f"Error displaying message '{message}': {e}")

    def _logout(self) -> None:
        """Handles user logout: closes socket and returns to login screen."""
        logging.info("Logout requested by user.")
        if self.socket:
            try:
                # Optionally send a "disconnect" message to the server
                # protocol.encrypt_and_send_msg("disconnecting".encode(), self.socket, self.aes_protocol)
                self.socket.close()
                logging.info("Socket closed during logout.")
            except Exception as e:
                logging.error(f"Error closing socket during logout: {e}")
        self.socket = None
        self.aes_protocol = None
        self.username_entry.delete(0, tk.END) # Clear username
        self.password_entry.delete(0, tk.END) # Clear password
        self.show_frame("LoginScreen")
        logging.info("User logged out, returned to LoginScreen.")


    def _on_closing(self) -> None:
        """Handles the event when the main window is closed."""
        logging.info("Main window closing event triggered.")
        if messagebox.askokcancel("Quit", "Do you want to quit the Secure Client?"):
            logging.info("User confirmed quit. Shutting down.")
            if self.socket:
                try:
                    # Consider sending a graceful disconnect message to the server here if protocol supports it
                    # protocol.encrypt_and_send_msg(EXIT_CMD.encode(), self.socket, self.aes_protocol)
                    self.socket.close()
                    logging.info("Socket closed on application exit.")
                except Exception as e:
                    logging.error(f"Error closing socket on application exit: {e}")
            self.root.destroy()
            logging.info("Application window destroyed. Exiting.")
        else:
            logging.info("User cancelled quit.")


    def run(self) -> None:
        """Starts the Tkinter main event loop."""
        logging.info("Starting ClientGUI main loop.")
        # Apply some ttk styles for a slightly more modern look
        style = ttk.Style()
        style.configure("Accent.TButton", foreground="white", background="#0078D7") # Example accent button
        style.configure("Danger.TButton", foreground="white", background="#DC3545") # Example danger button
        style.configure("Success.TButton", foreground="white", background="#28A745") # Example success button

        self.root.mainloop()
        logging.info("ClientGUI main loop exited.")

if __name__ == '__main__':
    logging.basicConfig(
        format='%(asctime)s | %(levelname)s | GUI_CLIENT - %(message)s', # Log identifier
        datefmt='%m/%d/%Y %I:%M:%S %p',
        level=logging.INFO, # Use logging.DEBUG for more verbose output during development
        filename='gui_client.log',
        filemode='w'
    )
    try:
        client_app = ClientGUI()
        client_app.run()
    except Exception as e:
        logging.critical(f"Critical error starting GUI client: {e}", exc_info=True)
        # Fallback if GUI itself fails to initialize, print to console
        print(f"A critical error occurred: {e}")
