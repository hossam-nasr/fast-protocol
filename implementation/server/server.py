from netinterface import network_interface
from Crypto.Util import Padding
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Hash import SHA224
from Crypto import Random
from ast import literal_eval
import time
import re
import os
import sys

# ------------------------------------------------- CONSTANTS ----------------------------------------------------

NET_ADDR = "../network/"
OWN_ID = "S"
DATA_FILE = "./data.txt"
PRIVATE_KEY_FILE = "./private_key.pem"
USER_FILES_DIR = "./user_files"
INIT_MSG_LEN = 97
MAC_LEN = 16
NONCE_LEN = 16

# create network interface netif
netif = network_interface(NET_ADDR, OWN_ID)


# ---------------------------------------------- HELPER FUNCTIONS ------------------------------------------------

def get_millis(timestamp):
    return int(round(timestamp * 1000))


def timestamp_valid(millis):
    now = get_millis(time.time())
    diff = now - millis
    if (diff > 0 and diff < 60 * 1000):
        return True
    return False


def password_valid(password):
    return (len(password) >= 8 and len(password) <= 32
            and re.search("(?=.*[a-z])", password)
            and re.search("(?=.*[A-Z])", password)
            and re.search("(?=.*[!@#$%^&*])", password))


# --------------------------------------------- HANDSHAKE PROTOCOL -----------------------------------------------

# -------------------------------- Setup  -------------------------------

# Get private key
priv_key = RSA.importKey(open(PRIVATE_KEY_FILE).read())
cipher = PKCS1_OAEP.new(priv_key)

# Get user data
contents = open(DATA_FILE).read()
user_data = literal_eval(contents)


message_valid = False
session_active = False
session_key = b''
while(not message_valid and not session_active):

    # -------------------------------- Wait for Initiation   -------------------------------
    # wait for initiation message
    print("Waiting for initiation message...")
    status, ciphertext = netif.receive_msg(blocking=True)

    # ---------------------------- Validate Initiation  Message -----------------------------
    print("Received initiation message. Checking...")
    message_valid = True

    # Decrypt message
    message = cipher.decrypt(ciphertext)
    if (len(message) != INIT_MSG_LEN):
        print("Invalid message length. Restarting..")
        message_valid = False
        continue

    # Deconstruct message
    index = 0
    user_id_bytes = message[index:index+1]
    user_id = user_id_bytes.decode("utf-8")
    index += 1

    password_bytes_raw = message[index:index + 32]
    index += 32
    try:
        password_bytes = Padding.unpad(password_bytes_raw, 32, 'pkcs7')
        password = password_bytes.decode("utf-8")
    except:
        message_valid = False
        print("Invalid password padding. Restarting..")
        continue

    key = message[index: index + 32]
    index += 32

    time_bytes = message[index: index + 32]
    index += 32
    timestamp = int.from_bytes(time_bytes, byteorder="big")

    # Validate message
    if (not user_id in user_data):
        print("Invalid user ID. Restarting..")
        message_valid = False
        continue
    if (not timestamp_valid(timestamp)):
        print("Invalid timestamp. Restarting..")
        message_valid = False
        continue
    if (not password_valid(password)):
        print("Invalid timestamp. Restarting..")
        message_valid = False
        continue

    h = SHA224.new()
    h.update(password_bytes)
    password_hash = h.digest()

    if (password_hash != user_data[user_id]["pass_hash"]):
        message_valid = False

    # -------------------------------- Start Session ----------------------------------
    # Accept key and start new session
    print("Message accepted. Starting session...")
    session_active = True
    session_key = key

    # Construct acknowledgment message
    ack_msg = user_id_bytes
    ack_msg += b'session_start'
    ack_msg += get_millis(time.time()).to_bytes(32, byteorder="big")

    # Encrypt acknowledgment message with session key
    nonce = 1
    nonce_bytes = nonce.to_bytes(16, byteorder="big")
    cipher = AES.new(session_key, AES.MODE_GCM,
                     nonce=nonce_bytes, mac_len=MAC_LEN)
    ciphertext, tag = cipher.encrypt_and_digest(ack_msg)

    # send acknowledgement message
    netif.send_msg(user_id, ciphertext + tag)


# --------------------------------------------- END OF HANDSHAKE PROTOCOL -----------------------------------------------


# -------------------------------------------------- TUNNEL PROTOCOL -----------------------------------------------------

# -------------------------------- Setup  -------------------------------
# Get Directories
if (USER_FILES_DIR[-1] != "/" and USER_FILES_DIR[-1] != '\\'):
    USER_FILES_DIR += "/"
USER_ROOT_DIR = USER_FILES_DIR + user_id + "/"

# Create directories if they don't exist
if not (os.path.exists(USER_FILES_DIR)):
    print("Creating folder " + USER_FILES_DIR + " ...")
    os.mkdir(USER_FILES_DIR)
if not (os.path.exists(USER_ROOT_DIR)):
    print("Creating folder " + USER_ROOT_DIR + " ...")
    os.mkdir(USER_ROOT_DIR)

# Ensure access
if not os.access(USER_FILES_DIR, os.F_OK):
    print('Error: Cannot access path ' + USER_FILES_DIR)
    sys.exit(1)

# Current Working Directory
cwd = USER_ROOT_DIR


# start accepting messages
print("Accepting messages...")
send_sqn = 2
receive_sqn = 0
while (session_active):
    # ------------------------- Wait for command message  ----------------------------
    status, msg = netif.receive_msg(blocking=True)
    print("Command message received.")

    # ------------------------- Validate command message  ----------------------------
    header_len = 22
    if (len(msg) < header_len + MAC_LEN):
        print("Message length too short. Discarding message...")
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
        print("Unsupported protocol version. Restarting...")
        continue
    if (new_sqn <= receive_sqn):
        print("Sequence number too small. Restarting...")
        continue
    else:
        receive_sqn = new_sqn

    # Decrypt message
    cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce, mac_len=MAC_LEN)
    cipher.update(header)
    try:
        payload = cipher.decrypt_and_verify(encrypted_payload, auth_tag)
    except Exception as e:
        print(e)
        print("Decryption failed. Restarting... ")
        continue

    print(msg_len)
    print(len(payload) + header_len + MAC_LEN)
    if (len(payload) + header_len + MAC_LEN != msg_len):
        print("Message length incorrect. Restarting...")
        continue

    # --------------------------- Parse command message  ------------------------------
    print("Received command message: ", payload)
