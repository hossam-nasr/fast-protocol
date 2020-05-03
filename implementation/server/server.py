from netinterface import network_interface
# create network interface netif
netif = network_interface("../network/", 'S')

msg = b"Hello Client!"
print("Server sending message: ", msg)
netif.send_msg('C', msg)

status, msg = netif.receive_msg(blocking=True)
print("I'm the server, and I received the following message: ", msg)
