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
import shutil
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


COMMANDS = {
    "MKD": {
        "arg_num": 1
    },
    "RMD": {
        "arg_num": 1
    },
    "GWD": {
        "arg_num": 0
    },
    "CWD": {
        "arg_num": 1
    },
    "LST": {
        "arg_num": 0
    },
    "UPL": {
        "arg_num": 2
    },
    "DNL": {
        "arg_num": 1
    },
    "RMF": {
        "arg_num": 1
    },
    "END": {
        "arg_num": 0
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


def password_valid(password):
    return (len(password) >= 8 and len(password) <= 32
            and re.search("(?=.*[a-z])", password)
            and re.search("(?=.*[A-Z])", password)
            and re.search("(?=.*[!@#$%^&*])", password))


# ---------------------------------------------- FILE HANDLING FUNCTIONS ------------------------------------------------

def get_user_rel_path(path):
    global USER_ROOT_DIR
    abs_root_path = os.path.abspath(USER_ROOT_DIR)
    abs_path = os.path.abspath(path)
    offset = len(os.path.commonpath([abs_path, abs_root_path]))
    if (offset == len(abs_path)):
        return "/"
    return abs_path[offset:]


def get_path(path):
    global wd
    global USER_ROOT_DIR

    # Get path relative to current working directory, or the user root being the "/"
    if (os.path.isabs(path)):
        path = USER_ROOT_DIR + path
    else:
        path = wd + "/" + path
    return path


def path_allowed(path):
    global USER_ROOT_DIR
    abs_root_path = os.path.abspath(USER_ROOT_DIR)
    abs_path = os.path.abspath(path)
    return os.path.commonpath([abs_path, abs_root_path]) == abs_root_path


def mkd(dir_name):
    path = get_path(dir_name)
    if (os.path.exists(path)):
        return False, "A folder with the name {} already exists".format(dir_name)
    if (not path_allowed(path)):
        return False, "Access Denied"
    try:
        os.mkdir(path)
        return True, None
    except Exception as e:
        return False, e


def rmd(dir_name):
    path = get_path(dir_name)
    if (not os.path.exists(path)):
        return False, "The directory {} doesn't exist".format(dir_name)
    if (not path_allowed(dir_name)):
        return False, "Access Denied"
    if (not os.path.isdir(path)):
        return False, "{} is not a directory".format(dir_name)
    try:
        shutil.rmtree(path)
        return True, None
    except Exception as e:
        return False, e


def gwd():
    global wd
    return True, get_user_rel_path(wd)


def cwd(path):
    global wd

    # Get path relative to current working directory, or the user root being the "/"
    path = get_path(path)

    # Make sure path is valid and exists
    abs_path = os.path.abspath(path)
    if (not path_allowed(path)):
        return False, "Access Denied"
    if (not os.path.isdir(abs_path)):
        return False, "Directory {} does not exist".format(get_user_rel_path(path))

    wd = abs_path
    return True, get_user_rel_path(wd)


def lst():
    global wd
    try:
        return True, os.listdir(wd)
    except Exception as e:
        return False, e


def upl(file_name, file_content):
    path = get_path(file_name)
    if (not path_allowed(path)):
        return False, "Access Denied"
    try:
        with open(path, "wb") as f:
            f.write(file_content)
        return True, None
    except Exception as e:
        return False, e


def dnl(file_name):
    path = get_path(file_name)
    if (not path_allowed(path)):
        return False, "Access Denied"
    if (not os.path.exists(path)):
        return False, "File {} does not exist".format(file_name)
    if (not os.path.isfile(path)):
        return False, "{} is not a file".format(file_name)
    try:
        with open(path, "rb") as f:
            return True, [get_user_rel_path(path), f.read()]
    except Exception as e:
        return False, e


def rmf(file_name):
    path = get_path(file_name)
    if (not path_allowed(path)):
        return False, "Access Denied"
    if (not os.path.exists(path)):
        return False, "File {} does not exist".format(file_name)
    if (not os.path.isfile(path)):
        return False, "{} is not a file".format(file_name)
    try:
        os.remove(path)
        return True, None
    except Exception as e:
        return False, e


def execute_command(command, args):
    if (command == "MKD"):
        dir_name = args[0].decode("utf-8")
        if (len(dir_name) > 120):
            return False, "Directory name too long"
        return mkd(dir_name)
    if (command == "RMD"):
        dir_name = args[0].decode("utf-8")
        if (len(dir_name) > 120):
            return False, "Directory name too long"
        return rmd(dir_name)
    if (command == "GWD"):
        return gwd()
    if (command == "CWD"):
        path = args[0].decode("utf-8")
        if (len(path) > 120):
            return False, "Directory name too long"
        return cwd(path)
    if (command == "LST"):
        return lst()
    if (command == "UPL"):
        file_name = args[0].decode("utf-8")
        if (len(file_name) > 120):
            return False, "File name too long"
        file_content = args[1]
        return upl(file_name, file_content)
    if (command == "DNL"):
        file_name = args[0].decode("utf-8")
        if (len(file_name) > 120):
            return False, "File name too long"
        return dnl(file_name)
    if (command == "RMF"):
        file_name = args[0].decode("utf-8")
        if (len(file_name) > 120):
            return False, "File name too long"
        return rmf(file_name)
    return False, "Invalid command"


def get_outputs(command, status, output):
    new_outputs = []
    if (command == "MKD" or command == "RMD" or command == "UPL" or command == "RMF"):
        if (status):
            new_outputs.append("success")
        else:
            new_outputs.append("failure")
            new_outputs.append(output)
    if (command == "GWD" or command == "CWD"):
        if (status):
            new_outputs.append(output)
        else:
            new_outputs.append("failure")
            new_outputs.append(output)
    if (command == "LST" or command == "DNL"):
        if (status):
            new_outputs = output
        else:
            new_outputs.append("failure")
            new_outputs.append(output)
    else:
        new_outputs.append("failure")
        new_outputs.append(output)
    return new_outputs


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

# Working Directory
wd = USER_ROOT_DIR


# start accepting messages
print("Accepting messages...")
send_sqn = 1
receive_sqn = 0
while (session_active):
    # ------------------------- Wait for command message  ----------------------------
    status, msg = netif.receive_msg(blocking=True)
    print("Command message received.")

    # ------------------------- Validate command message  ----------------------------
    print("Validating message...")
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

    if (len(payload) + header_len + MAC_LEN != msg_len):
        print("Message length incorrect. Restarting...")
        continue

    print("Message valdidation successful...")

    # ------------------------------ Parse command message  ---------------------------------

    print("Parsing message...")

    # Destructure payload
    try:
        index = 0
        arg_num = int.from_bytes(payload[index:index+1], byteorder="big")
        index += 1
        command = payload[index:index+3].decode("utf-8")
        index += 3
        args_raw = payload[index:]
        args = []
        index = 0
        for i in range(arg_num-1):
            arg_len = int.from_bytes(args_raw[index:index+8], byteorder="big")
            index += 8
            arg = args_raw[index:index+arg_len]
            index += arg_len
            args.append(arg)

    except Exception as e:
        print(e)
        print("Command parsing failed. Invalid command or argument length")
        # TODO: SEND A FAILURE MESSAGE HERE
        continue

    # Validate command message
    if (command not in COMMANDS):
        print("Invalid command {}. Restarting...".format(command))
        # TODO: SEND A FAILURE MESSAGE HERE
        continue
    if (arg_num < 1 or arg_num != COMMANDS[command]["arg_num"] + 1 or len(args_raw) != index):
        print("Invalid argument number. Restarting...")
        # TODO: SEND A FAILURE MESSAGE HERE
        continue

    print("Received command: ", command)
    print("Received arguments: ", args)

    # -------------------------------- Execute commands  -----------------------------------
    print("Executing command...")
    if (command == 'END'):
        print("Ending session...")
        session_active = False
        status = True
        output = None
    else:
        status, output = execute_command(command, args)

    print("Command executed.")
    outputs = get_outputs(command, status, output)

    # ------------------------- Construct acknowledgment message  --------------------------------
    print("Sending acknowledgment message...")
    # Add 1 extra arguments to account for "acknowledged"
    arg_num = len(outputs) + 1

    # construct payload
    payload = b""
    payload += arg_num.to_bytes(1, byteorder="big")
    payload += b"acknowledged"
    for output in outputs:
        if (not type(output) == type(b"")):
            output = output.encode("utf-8")
        len_bytes = len(output).to_bytes(8, byteorder="big")
        payload += len_bytes + output

    # construct header
    version_bytes = b'\x01\x00'  # version 1.0
    send_sqn += 1
    rnd = Random.get_random_bytes(8)
    nonce = send_sqn.to_bytes(8, byteorder="big") + rnd
    # Header length is 22 bytes (2 version number + 4 length + 16 nonce)
    msg_len = 22 + len(payload) + MAC_LEN
    msg_len_bytes = msg_len.to_bytes(4, byteorder="big")
    header = version_bytes + msg_len_bytes + nonce

    # encrypt message
    cipher = AES.new(session_key, AES.MODE_GCM,
                     nonce=nonce, mac_len=MAC_LEN)
    cipher.update(header)
    encrypted_payload, auth_tag = cipher.encrypt_and_digest(
        payload)

    # ---------------------------- Send acknowledgment message  --------------------------------------
    netif.send_msg(user_id, header + encrypted_payload + auth_tag)
    print("Acknowledgment message sent.")

if (not session_active):
    session_key = b""
