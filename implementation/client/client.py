from netinterface import network_interface
netif = network_interface("../network", 'C')		# create network interface netif

status, msg = netif.receive_msg(blocking=True)
print("I'm the client, and I received the following message: ", msg)

msg = b'Hello server'
print("Client sent message: ", msg)
netif.send_msg("S", msg)
