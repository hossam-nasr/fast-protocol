from netinterface import network_interface
from Crypto.Util import Padding
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Hash import SHA224
from Crypto import Random
from ast import literal_eval
import time
import re

# ------------------------------------------------- CONSTANTS ----------------------------------------------------

NET_ADDR = "../network/"
OWN_ID = "S"
DATA_FILE = "./data.txt"
PRIVATE_KEY_FILE = "./private_key.pem"
INIT_MSG_LEN = 97

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
    client_id_bytes = message[index:index+1]
    client_id = client_id_bytes.decode("utf-8")
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
    if (not client_id in user_data):
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

    if (password_hash != user_data[client_id]["pass_hash"]):
        message_valid = False

    # -------------------------------- Start Session ----------------------------------
    # Accept key and start new session
    print("Message accepted. Starting session...")
    session_active = True
    session_key = key

    # Construct acknowledgment message
    ack_msg = client_id_bytes
    ack_msg += b'session_start'
    ack_msg += get_millis(time.time()).to_bytes(32, byteorder="big")

    # Encrypt acknowledgment message with session key
    nonce = 1
    nonce_bytes = nonce.to_bytes(16, byteorder="big")
    cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce_bytes, mac_len=16)
    ciphertext, tag = cipher.encrypt_and_digest(ack_msg)

    # send acknowledgement message
    netif.send_msg(client_id, ciphertext + tag)


# --------------------------------------------- END OF HANDSHAKE PROTOCOL -----------------------------------------------


# -------------------------------------------------- TUNNEL PROTOCOL -----------------------------------------------------
