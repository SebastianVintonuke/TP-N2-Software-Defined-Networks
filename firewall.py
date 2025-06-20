#Coursera :
#- Software Defined Networking ( SDN ) course
#-- Programming Assignment : Layer -2 Firewall Application Professor : Nick Feamster
#Teaching Assistant : Arpit Gupta

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.addresses import EthAddr
from collections import namedtuple
import os

# Add your imports here ...
log = core.getLogger()

# Add your global variables here ...

class Firewall (EventMixin) :
	def __init__(self) :
		self.listenTo(core.openflow)
		log.debug("Enabling Redes Firewall Module")

	def _handle_ConnectionUp(self,event) :
		# Add your logic here ...
		log.debug("-------> CONNECTION UP {0}".format(event.connection))


	def _handle_ConnectionDown(self,event) :
		# Add your logic here ...
		log.debug("-------> CONNECTION Down: {0}".format(event))

	def _handle_PacketIn(self,event) :
		# Add your logic here ...
		log.debug("-------> Packet In: {0}".format(event))

	def _handle_FlowRemoved(self,event) :
		# Add your logic here ...
		log.debug("-------> Flow Removed? {0}".format(event))

		
def launch():
	# Starting the Firewall module
	log.debug("-------> Registering Redes TP2 Firewall")
	core.registerNew(Firewall)


"""
core.openflow.addListenerByName("PacketIn",_handle_PacketIn)

// Eventos
ConnectionUp
ConnectionDown
PortStatus
FlowRemoved
Statistics
Events
PacketIn
ErrorIn
BarrierIn


// Enviar mensaje??
msg = of.ofp_packet_out()
msg.actions.append(of.ofp_action_output(port=outport))
msg.buffer_id=<some_buffer_id , if_any>
connection.send(msg)

"""