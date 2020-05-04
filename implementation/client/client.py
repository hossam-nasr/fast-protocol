from netinterface import network_interface
from Crypto.Util import Padding
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto import Random
from getpass import getpass
import time
import sys


# ------------------------------------------------ CONSTANTS -----------------------------------------------------

NET_ADDR = "../network/"
SERVER_ID = 'S'
SERVER_INFO_FILE = "./server_pub_key.txt"
MAX_TRIALS = 3
MAC_LEN = 16
ACK_MSG_LEN = 46
NONCE_LEN = 16

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
        "output_nums": [0]
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


print("Welcome to the FAST Protocol client!")

# Get server public key
pub_key = RSA.importKey(open(SERVER_INFO_FILE).read())
public_cipher = PKCS1_OAEP.new(pub_key)

session_active = False
while (not session_active):

    # Get user ID
    user_id = input("Please enter your ID: ").rstrip().lstrip().upper()
    if (len(user_id) > 1):
        user_id = user_id[0]

    # create network interface netif
    netif = network_interface(NET_ADDR, user_id)

    # Get password
    password = getpass("Please enter your password: ").rstrip().lstrip()

    response_valid = False
    trials = 0
    while ((not session_active or not response_valid) and trials < MAX_TRIALS):
        print("Starting a new session...")
        response_valid = True

        # -------------------------------- Initiate protocol  -------------------------------

        # get session key
        session_key = Random.get_random_bytes(32)

        # construct initiation message
        initiation_msg = b''
        initiation_msg += user_id.encode('utf-8')
        initiation_msg += Padding.pad(password.encode("utf-8"), 32, 'pkcs7')
        initiation_msg += session_key
        now = get_millis(time.time())  # get timestamp in millisecond
        initiation_msg += now.to_bytes(32, 'big')

        # encrypt initiation message
        ciphertext = public_cipher.encrypt(initiation_msg)

        # send initiation message
        netif.send_msg(SERVER_ID, ciphertext)

        # ---------------------------- Wait for server response  ---------------------------
        print("Waiting for server response...")
        status, ack_msg = netif.receive_msg(blocking=True)

        # ---------------------------- Validate server response  ---------------------------
        print("Checking server response...")

        if (len(ack_msg) < MAC_LEN):
            response_valid = False
            continue

        encrypted_payload = ack_msg[:-MAC_LEN]
        auth_tag = ack_msg[-MAC_LEN:]

        # Authenticate message
        nonce = 1
        nonce_bytes = nonce.to_bytes(16, byteorder="big")
        cipher = AES.new(session_key, AES.MODE_GCM,
                         nonce=nonce_bytes, mac_len=MAC_LEN)

        try:
            payload = cipher.decrypt_and_verify(encrypted_payload, auth_tag)
        except Exception as e:
            response_valid = False
            trials += 1
            print("Bad response. Trying again... ")
            continue

        if (len(payload) != ACK_MSG_LEN):
            response_valid = False
            trials += 1
            print("Bad response. Trying again... ")
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

        # TODO: check here that there isn't more to the message

        # Validate message
        if (response_id != user_id):
            response_valid = False
            trials += 1
            print("Bad response. Trying again...")
            continue

        if (ack != "session_start"):
            response_valid = False
            trials += 1
            print("Bad response. Trying again...")
            continue

        if (not timestamp_valid(timestamp)):
            response_valid = False
            trials += 1
            print("Bad response. Trying again...")
            continue

        # -------------------------------- Start session  -------------------------------
        if (response_valid):
            print("Successfully logged in...")
            session_active = True

    if (not session_active):
        print("After {} trials, no valid server response. Try again!".format(MAX_TRIALS))

# --------------------------------------------- END OF HANDSHAKE PROTOCOL -----------------------------------------------


# -------------------------------------------------- TUNNEL PROTOCOL -----------------------------------------------------
print("Start typing commands!")
send_sqn = 0
receive_sqn = 1
wd = "/"
while (session_active):
    # Get command and args
    raw_command = input("~" + wd + "$ ").rstrip().lstrip()
    commands = raw_command.split()
    command = commands[0].upper()
    args = commands[1:]

    if (command not in COMMANDS):
        print("Unknown command {}".format(command))
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
    rnd = Random.get_random_bytes(8)
    nonce = send_sqn.to_bytes(8, byteorder="big") + rnd
    # Header length is 24 bytes (2 version number + 4 length + 16 nonce)
    msg_len = 22 + len(payload) + MAC_LEN
    msg_len_bytes = msg_len.to_bytes(4, byteorder="big")
    header = version_bytes + msg_len_bytes + nonce

    # encrypt message
    cipher = AES.new(session_key, AES.MODE_GCM,
                     nonce=nonce, mac_len=MAC_LEN)
    cipher.update(header)
    encrypted_payload, auth_tag = cipher.encrypt_and_digest(
        payload)

    # ---------------------------- Send command message  -------------------------------
    netif.send_msg(SERVER_ID, header + encrypted_payload + auth_tag)

    # if the command was END, end the session, regardless of server response
    if (command == "END"):
        print("Logging out...")
        session_active = False

    # -------------------- Wait for server acknowledgment message  ----------------------
    status, msg = netif.receive_msg(blocking=True)

    # ----------------------- Validate acknowledgement message  ----------------------------
    header_len = 22
    if (len(msg) < header_len + MAC_LEN):
        print("Error receiving response from server: Message length too short.")
        print("This may indicate an attack on your session. If the error persists, please consider logging out and in again.")
        continue

    # Deconstruct message
    header = msg[0:header_len]
    encrypted_payload = msg[header_len:-MAC_LEN]
    auth_tag = msg[-MAC_LEN:]
    index = 0
    version = header[0:2]
    index += 2
    msg_len = int.from_bytes(header[index:index+4], byteorder="big")
    index += 4
    nonce = header[index:index+NONCE_LEN]
    new_sqn = int.from_bytes(nonce[0:8], byteorder="big")

    # Validate message
    if (version != b'\x01\x00'):
        print("Error receiving response from server: Unsupported protocol version.")
        print("This may indicate an attack on your session. If the error persists, please consider logging out and in again.")
        continue
    if (new_sqn <= receive_sqn):
        print("Error receiving response from server: Sequence number too small.")
        print("This may indicate an attack on your session. If the error persists, please consider logging out and in again.")
        continue
    else:
        receive_sqn = new_sqn

    # Decrypt message
    cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce, mac_len=MAC_LEN)
    cipher.update(header)
    try:
        payload = cipher.decrypt_and_verify(encrypted_payload, auth_tag)
    except Exception as e:
        print("Error receiving response from server: Authentication failed with error: ", e)
        print("This may indicate an attack on your session. If the error persists, please consider logging out and in again.")
        continue

    if (len(payload) + header_len + MAC_LEN != msg_len):
        print("Error receiving response from server: Message format corrupted.")
        print("This may indicate an attack on your session. If the error persists, please consider logging out and in again.")
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
        for i in range(arg_num-1):
            output_len = int.from_bytes(
                outputs_raw[index:index+8], byteorder="big")
            index += 8
            output = outputs_raw[index:index+output_len]
            index += output_len
            outputs.append(output.decode("utf-8"))

    except Exception as e:
        print("Error receiving response from server: Message format corrupted.")
        print("This may indicate an attack on your session. If the error persists, please consider logging out and in again.")
        continue

    # Validate command message
    if (ack != "acknowledged"):
        print("Error receiving response from server: Message format corrupted.")
        print("This may indicate an attack on your session. If the error persists, please consider logging out and in again.")
        continue
    if (arg_num < 1 or (arg_num - 1 not in COMMANDS[command]["output_nums"] and "*" not in COMMANDS[command]["output_nums"]) or len(outputs_raw) != index):
        print("Error receiving response from server: Message format corrupted.")
        print("This may indicate an attack on your session. If the error persists, please consider logging out and in again.")
        continue

    # -------------------------------- Display output  -----------------------------------
    # Exit from session if command was END
    if (command == "END"):
        session_active = False
        session_key = b""
        print("Logged out.")

    if (command == "CWD" and len(outputs) == 1):
        wd = outputs[0]
    else:
        for output in outputs:
            print(output)
