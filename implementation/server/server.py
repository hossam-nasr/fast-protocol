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
import getopt

# ------------------------------------------------- CONSTANTS ----------------------------------------------------

NET_ADDR = "../network/"
DATA_FILE = "./user_data.txt"
PRIVATE_KEY_FILE = "./private_key.pem"
USER_FILES_DIR = "./user_files"

OWN_ID_HANDSHAKE = "H"
OWN_ID_TUNNEL = "T"
USER_ROOT_DIR = None
wd = None
INIT_MSG_LEN = 97
MAC_LEN = 16
NONCE_LEN = 16
SQN_LEN = 10
HEADER_LEN = 7 + NONCE_LEN


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
    return (is_ascii(password) and
            len(password) >= 8 and len(password) <= 32
            and re.search("(?=.*[a-z])", password)
            and re.search("(?=.*[A-Z])", password)
            and re.search("(?=.*[!@#$%^&*])", password))


def is_ascii(s):
    return all(ord(c) < 128 for c in s)


def dir_name_valid(name):
    return len(name) > 0 and len(name) <= 120 and is_ascii(name)


def get_tunnel_error_message(session_key, send_sqn, error):
    # 3 arguments: "acknowledged", "failure", error message
    arg_num = 3

    # construct payload
    payload = b""
    payload += arg_num.to_bytes(1, byteorder="big")
    payload += b"acknowledged"
    arg_1_len = len("failure")
    payload += arg_1_len.to_bytes(8, byteorder="big")
    payload += b"failure"
    arg_2_len = len(error)
    payload += arg_2_len.to_bytes(8, byteorder="big")
    payload += error.encode("utf-8")

    # construct header
    version_bytes = b'\x01\x00'  # version 1.0
    rnd = Random.get_random_bytes(NONCE_LEN - SQN_LEN)
    nonce = send_sqn.to_bytes(SQN_LEN, byteorder="big") + rnd
    msg_len = HEADER_LEN + len(payload) + MAC_LEN
    msg_len_bytes = msg_len.to_bytes(4, byteorder="big")
    own_id_bytes = OWN_ID_TUNNEL.encode("utf-8")
    header = version_bytes + msg_len_bytes + own_id_bytes + nonce

    # encrypt message
    cipher = AES.new(session_key, AES.MODE_GCM,
                     nonce=nonce, mac_len=MAC_LEN)
    cipher.update(header)
    encrypted_payload, auth_tag = cipher.encrypt_and_digest(payload)
    return header + encrypted_payload + auth_tag

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
    abs_root_path = os.path.abspath(USER_ROOT_DIR)
    abs_path = os.path.abspath(path)
    return os.path.commonpath([abs_path, abs_root_path]) == abs_root_path


def mkd(dir_name):
    path = get_path(dir_name)
    if (os.path.exists(path) and os.path.isdir(path)):
        return False, "A folder with the name {} already exists".format(dir_name)
    if (not path_allowed(path)):
        return False, "Access Denied"
    try:
        os.mkdir(path)
        return True, None
    except Exception:
        return False, "Couldn't create directory."


def rmd(dir_name):
    path = get_path(dir_name)
    if (not os.path.exists(path)):
        return False, "The directory {} doesn't exist".format(dir_name)
    if (not path_allowed(path)):
        return False, "Access Denied"
    if (not os.path.isdir(path)):
        return False, "{} is not a directory".format(dir_name)
    try:
        shutil.rmtree(path)
        return True, None
    except Exception:
        return False, "Delete failed."


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
    except Exception:
        return False, "Unknown error occured."


def upl(file_name, file_content):
    path = get_path(file_name)
    if (not path_allowed(path)):
        return False, "Access Denied"
    try:
        with open(path, "wb") as f:
            f.write(file_content)
        return True, None
    except Exception:
        return False, "Upload failed."


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
    except Exception:
        return False, "Download failed."


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
    except Exception:
        return False, "Delete failed."


def execute_command(command, args):
    if (command == "MKD"):
        dir_name = args[0].decode("utf-8")
        if (not dir_name_valid(dir_name)):
            return False, "Directory name invalid"
        return mkd(dir_name)
    if (command == "RMD"):
        dir_name = args[0].decode("utf-8")
        if (not dir_name_valid(dir_name)):
            return False, "Directory name invalid"
        return rmd(dir_name)
    if (command == "GWD"):
        return gwd()
    if (command == "CWD"):
        path = args[0].decode("utf-8")
        if (not dir_name_valid(path)):
            return False, "Path name invalid"
        return cwd(path)
    if (command == "LST"):
        return lst()
    if (command == "UPL"):
        file_name = args[0].decode("utf-8")
        if (not dir_name_valid(file_name)):
            return False, "File name invalid"
        file_content = args[1]
        return upl(file_name, file_content)
    if (command == "DNL"):
        file_name = args[0].decode("utf-8")
        if (not dir_name_valid(file_name)):
            return False, "File name invalid"
        return dnl(file_name)
    if (command == "RMF"):
        file_name = args[0].decode("utf-8")
        if (not dir_name_valid(file_name)):
            return False, "File name invalid"
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
    return new_outputs


# --------------------------------------------- HANDSHAKE PROTOCOL -----------------------------------------------

def handshake():
    # -------------------------------- Setup  -------------------------------
    print("Entering Handshake Protocol...")

    # create network interface netif
    netif = network_interface(NET_ADDR, OWN_ID_HANDSHAKE)

    # Get private key
    priv_key = RSA.importKey(open(PRIVATE_KEY_FILE).read())
    cipher = PKCS1_OAEP.new(priv_key)

    # Create user file if it doesn't exist
    if not (os.path.exists(DATA_FILE)):
        try:
            print("Creating file " + DATA_FILE + " ...")
            with open(DATA_FILE, "wt") as f:
                f.write("{ }")
            user_data = {}
        except Exception:
            print("Couldn't create file {}".format(DATA_FILE))
            sys.exit(1)
    else:
        contents = open(DATA_FILE).read()
        user_data = literal_eval(contents)

    message_valid = False
    session_active = False
    session_key = b''
    while(not message_valid or not session_active):

        # -------------------------------- Wait for Initiation   -------------------------------
        # wait for initiation message
        print("Waiting for initiation message...")
        _status, ciphertext = netif.receive_msg(blocking=True)

        # ---------------------------- Validate Initiation  Message -----------------------------
        print("Received initiation message. Checking...")
        message_valid = True

        # Decrypt message
        cipher = PKCS1_OAEP.new(priv_key)
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
        if (not timestamp_valid(timestamp)):
            print("Invalid timestamp. Restarting..")
            message_valid = False
            continue
        if (not password_valid(password)):
            print("Invalid password. Restarting..")
            message_valid = False
            continue

        # Get password hash
        h = SHA224.new()
        h.update(password_bytes)
        password_hash = h.digest()

        # Create new user with this password if they don't exist
        if (not user_id in user_data):
            print("User with ID {} doesn't exist. Creating it...".format(user_id))
            user_data[user_id] = {}
            user_data[user_id]["pass_hash"] = password_hash
            # Write new data to file
            with open(DATA_FILE, "wt") as f:
                f.write("{}".format(user_data))

        if (password_hash != user_data[user_id]["pass_hash"]):
            print("Invalid password. Restarting..")
            message_valid = False
            continue

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
        sqn = 1
        rnd = Random.get_random_bytes(8)
        nonce = sqn.to_bytes(8, byteorder="big") + rnd
        cipher = AES.new(session_key, AES.MODE_GCM,
                         nonce=nonce, mac_len=MAC_LEN)
        cipher.update(nonce)
        ciphertext, tag = cipher.encrypt_and_digest(ack_msg)

        # send acknowledgement message
        netif.send_msg(user_id, nonce + ciphertext + tag)

    # Return established session credentials
    print("Exiting Handshake protocol...")
    return user_id, session_key


# --------------------------------------------- END OF HANDSHAKE PROTOCOL -----------------------------------------------


# -------------------------------------------------- TUNNEL PROTOCOL -----------------------------------------------------

def tunnel(user_id, session_key):
    # -------------------------------- Setup  -------------------------------
    print("Entering Tunnel protocol...")

    # create network interface netif
    netif = network_interface(NET_ADDR, OWN_ID_TUNNEL)

    # Get Directories
    global USER_ROOT_DIR
    global wd
    USER_ROOT_DIR = os.path.abspath(USER_FILES_DIR + "/" + user_id)
    wd = USER_ROOT_DIR

    # Create directories if they don't exist
    try:
        if not (os.path.exists(USER_FILES_DIR)):
            print("Creating folder " + USER_FILES_DIR + " ...")
            os.mkdir(USER_FILES_DIR)
        if not (os.path.exists(USER_ROOT_DIR)):
            print("Creating folder " + USER_ROOT_DIR + " ...")
            os.mkdir(USER_ROOT_DIR)
    except Exception:
        print("Error: cannot access directories")
        sys.exit(1)

    # start accepting messages
    print("Accepting messages...")
    send_sqn = 1
    receive_sqn = 0
    session_active = True
    while (session_active):
        # ------------------------- Wait for command message  ----------------------------
        status, msg = netif.receive_msg(blocking=True)
        print("Command message received.")

        # ------------------------- Validate command message  ----------------------------
        print("Validating message...")
        if (len(msg) < HEADER_LEN + MAC_LEN):
            print("Message length too short. Discarding message...")
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

        # Only look at messages from the current user
        if (resp_id != user_id):
            continue

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
        cipher = AES.new(session_key, AES.MODE_GCM,
                         nonce=nonce, mac_len=MAC_LEN)
        cipher.update(header)
        try:
            payload = cipher.decrypt_and_verify(encrypted_payload, auth_tag)
        except Exception:
            print("Decryption failed. Restarting... ")
            continue

        if (len(payload) + HEADER_LEN + MAC_LEN != msg_len):
            print("Message length incorrect. Restarting...")
            continue

        print("Message valdidation successful.")

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
            for _i in range(arg_num-1):
                arg_len = int.from_bytes(
                    args_raw[index:index+8], byteorder="big")
                index += 8
                arg = args_raw[index:index+arg_len]
                index += arg_len
                args.append(arg)

        except Exception:
            error = "Command parsing failed. Invalid command or argument length"
            print(error)
            send_sqn += 1
            msg = get_tunnel_error_message(session_key, send_sqn, error)
            netif.send_msg(user_id, msg)
            continue

        # Validate command message
        if (command not in COMMANDS):
            error = "Invalid command {}.".format(command)
            print(error + " Restarting...")
            send_sqn += 1
            msg = get_tunnel_error_message(session_key, send_sqn, error)
            netif.send_msg(user_id, msg)
            continue
        if (arg_num < 1 or arg_num != COMMANDS[command]["arg_num"] + 1 or len(args_raw) != index):
            error = "Invalid argument number."
            print(error + " Restarting...")
            send_sqn += 1
            msg = get_tunnel_error_message(session_key, send_sqn, error)
            netif.send_msg(user_id, msg)
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
        rnd = Random.get_random_bytes(NONCE_LEN - SQN_LEN)
        nonce = send_sqn.to_bytes(SQN_LEN, byteorder="big") + rnd
        msg_len = HEADER_LEN + len(payload) + MAC_LEN
        msg_len_bytes = msg_len.to_bytes(4, byteorder="big")
        own_id_bytes = OWN_ID_TUNNEL.encode("utf-8")
        header = version_bytes + msg_len_bytes + own_id_bytes + nonce

        # encrypt message
        cipher = AES.new(session_key, AES.MODE_GCM,
                         nonce=nonce, mac_len=MAC_LEN)
        cipher.update(header)
        encrypted_payload, auth_tag = cipher.encrypt_and_digest(payload)

        # ---------------------------- Send acknowledgment message  --------------------------------------
        netif.send_msg(user_id, header + encrypted_payload + auth_tag)
        print("Acknowledgment message sent.")

        # End session if reached maximum number of allowed messages
        if (send_sqn == 2 ** SQN_LEN - 2):
            error = "Reached maximum number of messages per session."
            print(error + " Logging out user...")
            send_sqn += 1
            msg = get_tunnel_error_message(session_key, send_sqn, error)
            netif.send_msg(user_id, msg)
            session_key = b""
            session_active = False

    # End of Tunnel protocol
    print("Exiting Tunnel Protocol...")

# ---------------------------------------------- END OF TUNNEL PROTOCOL ------------------------------------------------


# --------------------------------------------------- MAIN SERVER --------------------------------------------------------

# get commandline arguments
try:
    opts, args = getopt.getopt(sys.argv[1:], shortopts='hp:n:u:f:', longopts=[
                               'help', 'priv=', 'network=', 'users=', 'files='])
except getopt.GetoptError:
    print('Usage: python3 server.py -p <private key path> -n <network path> -u <user data file path> -f <user files path>')
    sys.exit(1)

# Execute command line arguments
for opt, arg in opts:
    if opt == '-h' or opt == '--help':
        print('Usage: python3 server.py -p <private key path> -n <network path> -u <user data file path> -f <user files path>')
        sys.exit(0)
    elif opt == '-p' or opt == '--priv':
        if (not os.path.exists(arg) or not os.path.isfile(arg)):
            print("Error: File {} does not exist".format(arg))
            sys.exit(1)
        PRIVATE_KEY_FILE = arg
    elif opt == '-n' or opt == '--network':
        if (arg[-1] != "/" or arg[-1] != "\\"):
            arg += "/"
        if (not os.path.exists(arg) or not os.path.isdir(arg)):
            print("Error: Directory {} does not exist".format(arg))
            sys.exit(1)
        NET_ADDR = arg
    elif opt == '-u' or opt == '--users':
        DATA_FILE = arg
    elif opt == '-f' or opt == '--files':
        USER_FILES_DIR = arg

# Start up server
print("Starting up the FAST Server...")
while True:

    # Establish new session using Handshake
    user_id, session_key = handshake()

    # Fork a new process to handle the session
    newpid = os.fork()
    if (newpid == 0):
        # Child process handles Tunnel protocol
        tunnel(user_id, session_key)
        # Exit successfully upon completion
        sys.exit(0)
    else:
        # Parent process continues to accept messages and forgets the session key
        session_key = b""
