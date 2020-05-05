from netinterface import network_interface
from Crypto.Util import Padding
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto import Random
from getpass import getpass
import time
import sys
import threading
import shlex
import readline
from termcolor import colored, cprint
from colorama import Fore, Style

# ------------------------------------------------ CONSTANTS -----------------------------------------------------

NET_ADDR = "../network/"
SERVER_ID_TUNNEL = 'T'
SERVER_ID_HANDSHAKE = 'H'
SERVER_INFO_FILE = "./server_pub_key.txt"
MAX_TRIALS = 3
MAC_LEN = 16
ACK_MSG_LEN = 46
NONCE_LEN = 16
SQN_LEN = 10
# Header length is 23 bytes (2 version number + 4 length + 1 user ID + 16 nonce)
HEADER_LEN = 7 + NONCE_LEN

COMMANDS = {
    "MKD": {
        "output_nums": [1, 2]
    },
    "RMD": {
        "output_nums": [1, 2]
    },
    "GWD": {
        "output_nums": [1, 2]
    },
    "CWD": {
        "output_nums": [1, 2]
    },
    "LST": {
        "output_nums": ['*']
    },
    "UPL": {
        "output_nums": [1, 2]
    },
    "DNL": {
        "output_nums": [2]
    },
    "RMF": {
        "output_nums": [1, 2]
    },
    "END": {
        "output_nums": [0, 2]
    }
}

# ---------------------------------------------- HELPER FUNCTIONS ------------------------------------------------


def get_millis(timestamp):
    return int(round(timestamp * 1000))


def timestamp_valid(millis):
    now = get_millis(time.time())
    diff = now - millis
    if (diff > 0 and diff < 60 * 1000):
        return True
    return False

# --------------------------------------------- HANDSHAKE PROTOCOL -----------------------------------------------


def handshake():
    # Get server public key
    pub_key = RSA.importKey(open(SERVER_INFO_FILE).read())
    public_cipher = PKCS1_OAEP.new(pub_key)

    session_active = False
    while (not session_active):

        # Get user ID
        user_id = input(Fore.CYAN + Style.BRIGHT + "Please enter your ID: " +
                        Style.RESET_ALL).rstrip().lstrip().upper()
        if (len(user_id) > 1):
            user_id = user_id[0]

        # create network interface netif
        netif = network_interface(NET_ADDR, user_id)

        # Get password
        password = getpass(Fore.CYAN + Style.BRIGHT +
                           "Please enter your password: " + Style.RESET_ALL).rstrip().lstrip()

        response_valid = False
        trials = 0
        while ((not session_active or not response_valid) and trials < MAX_TRIALS):
            cprint("Starting a new session...", "cyan", attrs=[])
            response_valid = True

            # -------------------------------- Initiate protocol  -------------------------------

            # get session key
            session_key = Random.get_random_bytes(32)

            # construct initiation message
            initiation_msg = b''
            initiation_msg += user_id.encode('utf-8')
            initiation_msg += Padding.pad(password.encode("utf-8"),
                                          32, 'pkcs7')
            initiation_msg += session_key
            now = get_millis(time.time())  # get timestamp in millisecond
            initiation_msg += now.to_bytes(32, 'big')

            # encrypt initiation message
            ciphertext = public_cipher.encrypt(initiation_msg)

            # send initiation message
            netif.send_msg(SERVER_ID_HANDSHAKE, ciphertext)

            # ---------------------------- Wait for server response  ---------------------------
            cprint("Waiting for server response...", "cyan", attrs=[])
            _status, ack_msg = netif.receive_msg(blocking=True)

            # ---------------------------- Validate server response  ---------------------------
            cprint("Checking server response...", "cyan", attrs=[])

            if (len(ack_msg) < MAC_LEN + NONCE_LEN):
                response_valid = False
                continue

            nonce = ack_msg[:NONCE_LEN]
            encrypted_payload = ack_msg[NONCE_LEN:-MAC_LEN]
            auth_tag = ack_msg[-MAC_LEN:]

            # Authenticate message
            cipher = AES.new(session_key, AES.MODE_GCM,
                             nonce=nonce, mac_len=MAC_LEN)
            cipher.update(nonce)
            try:
                payload = cipher.decrypt_and_verify(
                    encrypted_payload, auth_tag)
            except Exception:
                response_valid = False
                trials += 1
                cprint("Bad response. Trying again... ", "yellow", attrs=[])
                continue

            if (len(payload) != ACK_MSG_LEN):
                response_valid = False
                trials += 1
                cprint("Bad response. Trying again... ", "yellow", attrs=[])
                continue

            # Deconstruct message
            index = 0
            response_id_bytes = payload[index:index+1]
            response_id = response_id_bytes.decode("utf-8")
            index += 1

            ack_bytes = payload[index:index + 13]
            ack = ack_bytes.decode("utf-8")
            index += 13

            time_bytes = payload[index: index + 32]
            timestamp = int.from_bytes(time_bytes, byteorder="big")
            index += 32

            # Validate message
            received_sqn = int.from_bytes(nonce[0:8], byteorder="big")
            expected_sqn = 1
            if (received_sqn != expected_sqn):
                response_valid = False
                trials += 1
                cprint("Bad response. Trying again...", "yellow", attrs=[])
                continue
            if (response_id != user_id):
                response_valid = False
                trials += 1
                cprint("Bad response. Trying again...", "yellow", attrs=[])
                continue
            if (ack != "session_start"):
                response_valid = False
                trials += 1
                cprint("Bad response. Trying again...", "yellow", attrs=[])
                continue

            if (not timestamp_valid(timestamp)):
                response_valid = False
                trials += 1
                cprint("Bad response. Trying again...", "yellow", attrs=[])
                continue

            # -------------------------------- Start session  -------------------------------
            if (response_valid):
                cprint("Successfully logged in!", "green", attrs=[])
                session_active = True

        if (not session_active):
            print(
                "After {} trials, no valid server response. Try again!".format(MAX_TRIALS))

    return user_id, session_key

# --------------------------------------------- END OF HANDSHAKE PROTOCOL -----------------------------------------------


# -------------------------------------------------- TUNNEL PROTOCOL -----------------------------------------------------
def tunnel(user_id, session_key):
    # -------------------------------- Setup  ----------------------------------
    cprint("Start typing commands!", "green", attrs=[])
    send_sqn = 0
    receive_sqn = 1
    wd = "/"
    session_active = True
    netif = network_interface(NET_ADDR, user_id)
    while (session_active):
        # Get command and args
        print(Fore.MAGENTA + Style.BRIGHT + Style.DIM, end="")
        raw_command = input(
            "~" + wd + "$ " + Style.RESET_ALL).rstrip().lstrip()
        commands = shlex.split(raw_command)
        command = commands[0].upper()
        args = commands[1:]

        if (command not in COMMANDS):
            cprint("Unknown command {}".format(command), "red", attrs=["bold"])
            continue

        # ------------------------- Construct command message  ----------------------------
        # payload
        payload = b""
        arg_num = len(commands)
        payload += arg_num.to_bytes(1, byteorder="big")
        payload += command.encode("utf-8")
        for arg in args:
            arg_bytes = arg.encode("utf-8")
            arg_len_bytes = len(arg_bytes).to_bytes(8, byteorder="big")
            payload += arg_len_bytes + arg_bytes

        # header
        version_bytes = b'\x01\x00'  # version 1.0
        send_sqn += 1
        rnd = Random.get_random_bytes(NONCE_LEN - SQN_LEN)
        nonce = send_sqn.to_bytes(SQN_LEN, byteorder="big") + rnd
        msg_len = HEADER_LEN + len(payload) + MAC_LEN
        msg_len_bytes = msg_len.to_bytes(4, byteorder="big")
        user_id_bytes = user_id.encode("utf-8")
        header = version_bytes + msg_len_bytes + user_id_bytes + nonce

        # encrypt message
        cipher = AES.new(session_key, AES.MODE_GCM,
                         nonce=nonce, mac_len=MAC_LEN)
        cipher.update(header)
        encrypted_payload, auth_tag = cipher.encrypt_and_digest(
            payload)

        # ---------------------------- Send command message  -------------------------------
        netif.send_msg(SERVER_ID_TUNNEL, header + encrypted_payload + auth_tag)

        # if the command was END, end the session, regardless of server response
        if (command == "END"):
            cprint("Logging out...", "cyan", attrs=[])
            session_active = False

        # -------------------- Wait for server acknowledgment message  ----------------------
        _status, msg = netif.receive_msg(blocking=True)

        # ----------------------- Validate acknowledgement message  ----------------------------
        if (len(msg) < HEADER_LEN + MAC_LEN):
            cprint("Error receiving response from server: Message length too short.",
                   "red", attrs=["bold"])
            cprint("This may indicate an attack on your session. If the error persists, please consider logging out and in again.",
                   "red", attrs=["bold"])
            continue

        # Deconstruct message
        header = msg[0:HEADER_LEN]
        encrypted_payload = msg[HEADER_LEN:-MAC_LEN]
        auth_tag = msg[-MAC_LEN:]
        index = 0
        version = header[0:2]
        index += 2
        msg_len = int.from_bytes(header[index:index+4], byteorder="big")
        index += 4
        resp_id = header[index:index+1].decode("utf-8")
        index += 1
        nonce = header[index:index+NONCE_LEN]
        new_sqn = int.from_bytes(nonce[0:SQN_LEN], byteorder="big")

        # Validate message
        if (version != b'\x01\x00'):
            cprint("Error receiving response from server: Unsupported protocol version.",
                   "red", attrs=["bold"])
            cprint("This may indicate an attack on your session. If the error persists, please consider logging out and in again.",
                   "red", attrs=["bold"])
            continue
        if (new_sqn <= receive_sqn):
            cprint("Error receiving response from server: Sequence number too small.",
                   "red", attrs=["bold"])
            cprint("This may indicate an attack on your session. If the error persists, please consider logging out and in again.",
                   "red", attrs=["bold"])
            continue
        else:
            receive_sqn = new_sqn
        if (resp_id != SERVER_ID_TUNNEL):
            cprint("Error receiving response from server: Wrong ID.",
                   "red", attrs=["bold"])
            cprint("This may indicate an attack on your session. If the error persists, please consider logging out and in again.",
                   "red", attrs=["bold"])
            continue

        # Decrypt message
        cipher = AES.new(session_key, AES.MODE_GCM,
                         nonce=nonce, mac_len=MAC_LEN)
        cipher.update(header)
        try:
            payload = cipher.decrypt_and_verify(encrypted_payload, auth_tag)
        except Exception:
            cprint("Error receiving response from server: Authentication failed.",
                   "red", attrs=["bold"])
            cprint("This may indicate an attack on your session. If the error persists, please consider logging out and in again.",
                   "red", attrs=["bold"])
            continue

        if (len(payload) + HEADER_LEN + MAC_LEN != msg_len):
            cprint("Error receiving response from server: Message format corrupted.",
                   "red", attrs=["bold"])
            cprint("This may indicate an attack on your session. If the error persists, please consider logging out and in again.",
                   "red", attrs=["bold"])
            continue

        # ------------------------------ Parse command message  ---------------------------------

        # Destructure payload
        try:
            index = 0
            arg_num = int.from_bytes(payload[index:index+1], byteorder="big")
            index += 1
            ack = payload[index:index+len("acknowledged")].decode("utf-8")
            index += len("acknowledged")
            outputs_raw = payload[index:]
            outputs = []
            index = 0
            for _i in range(arg_num-1):
                output_len = int.from_bytes(
                    outputs_raw[index:index+8], byteorder="big")
                index += 8
                output = outputs_raw[index:index+output_len]
                index += output_len
                outputs.append(output.decode("utf-8"))

        except Exception:
            cprint("Error receiving response from server: Message format corrupted.",
                   "red", attrs=["bold"])
            cprint("This may indicate an attack on your session. If the error persists, please consider logging out and in again.",
                   "red", attrs=["bold"])
            continue

        # Validate command message
        if (ack != "acknowledged"):
            cprint("Error receiving response from server: Message format corrupted.",
                   "red", attrs=["bold"])
            cprint("This may indicate an attack on your session. If the error persists, please consider logging out and in again.",
                   "red", attrs=["bold"])
            continue
        if (arg_num < 1 or (arg_num - 1 not in COMMANDS[command]["output_nums"] and "*" not in COMMANDS[command]["output_nums"]) or len(outputs_raw) != index):
            cprint("Error receiving response from server: Message format corrupted.",
                   "red", attrs=["bold"])
            cprint("This may indicate an attack on your session. If the error persists, please consider logging out and in again.",
                   "red", attrs=["bold"])
            continue

        # -------------------------------- Display output  -----------------------------------
        # Exit from session if command was END
        if (command == "END"):
            session_active = False
            session_key = b""
            cprint("Logged out.", "green", attrs=["bold"])

        # if command was CWD, display output in the shell
        if (command == "CWD" and len(outputs) == 1):
            wd = outputs[0]
        else:
            # print outputs
            print(Fore.CYAN + Style.BRIGHT, end="")
            for output in outputs:
                if (output == "success"):
                    print(Fore.GREEN + "Success!")
                elif (output == "failure"):
                    print(Fore.RED + "Failure: ", end="")
                else:
                    print(output)
            print(Style.RESET_ALL, end="")

        # Exit session if reached maximum number of messages
        if (send_sqn == 2 ** SQN_LEN - 1):
            cprint(
                "Reached maximum number of messages in one session. Logging out...", "yellow", attrs=["bold"])
            session_active = False
            session_key = b""


# ---------------------------------------------- END OF TUNNEL PROTOCOL ------------------------------------------------


# --------------------------------------------------- MAIN CLIENT -------------------------------------------------------

# Intiate client
cprint("Welcome to the FAST Protocol client!", "yellow", attrs=["bold"])
while (True):
    cprint("Please login to start using FAST!", "yellow", attrs=["bold"])

    # Use Handshake protocol to establish session
    user_id, session_key = handshake()

    # Use established session protocol to communicate over Tunnel
    tunnel(user_id, session_key)

    # Clear memory of session key
    session_key = b""
