#Coursera :
#- Software Defined Networking ( SDN ) course
#-- Programming Assignment : Layer -2 Firewall Application Professor : Nick Feamster
#Teaching Assistant : Arpit Gupta

from pox.core import core
import pox.openflow.libopenflow_01 as of

from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.ipv6 import ipv6

from pox.lib.packet.tcp import tcp
from pox.lib.packet.udp import udp

#import pox.lib.packet as pkt

from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.addresses import EthAddr
from collections import namedtuple
import os
from . import rule_loader


# Add your imports here ...
log = core.getLogger()

def logger_debug(*args, **kwargs):
    format_str = " ".join((["%s"] * len(args)))
    log.debug(format_str,*args)

def logger_info(*args, **kwargs):
    format_str = " ".join((["%s"] * len(args)))
    log.debug(format_str,*args)

rule_loader.logger = logger_debug
rule_loader.logger_info = logger_info


module_dir = os.path.dirname(os.path.abspath(__file__))
file_path = os.path.join(module_dir, "config.json") # On the same folder as this firewall.py

FIREWALL_RULES = rule_loader.load_rules(file_path)

MAC_EXAMPLE = "00:00:00:00:00:01"

TCP_STR = "tcp"
UDP_STR = "udp"


TCP_PROTOCOL = 6
UDP_PROTOCOL = 17

ICMP_PROTOCOL = 1
GRE_PROTOCOL = 47 # Generic Routing Encapsulation
ESP_PROTOCOL = 50 # Encapsulating Security Payload
AH_PROTOCOL = 51 # 	Authentication Header

ICMPV6_PROTOCOL =58

def not_valid_protocol(protocol):
	return (protocol != ICMP_PROTOCOL 
			and protocol != GRE_PROTOCOL)

def parse_protocol(type):
	return "ICMP" if type == ICMP_PROTOCOL else str(type)

# Add your global variables here ...

def load_ipv4_info(dto_packet, ip):
	dto_packet.red_protocol = "ipv4"
	proto = ip.protocol  # 6 for TCP, 17 for UDP

	dto_packet.src.ip = ip.srcip
	dto_packet.dst.ip = ip.dstip
	# TCP or UDP layer
	l4 = ip.find(TCP_STR)
	if not l4:
		l4 = ip.find(UDP_STR)
		if l4:
			dto_packet.protocol = UDP_STR
	else:
		dto_packet.protocol = TCP_STR

	if l4:
		dto_packet.src.port = l4.srcport
		dto_packet.dst.port = l4.dstport
		return True
	elif not_valid_protocol(proto):
		log.info("Blocked non TCP/UDP ipv4 packet %s", proto);
		log.info("dto: %s", dto_packet)
		return False


	log.debug("Should never block, VALID IP PROT %s", parse_protocol(proto));
	#Valid protocol ICMP or something....
	return True

def load_ipv6_info(dto_packet, ip):
	dto_packet.red_protocol = "ipv6"
	dto_packet.src.ip = ip.srcip
	dto_packet.dst.ip = ip.dstip

	l4 = ip.find(TCP_STR)
	if not l4:
		l4 = ip.find(UDP_STR)
		if l4:
			dto_packet.protocol = UDP_STR
	else:
		dto_packet.protocol = TCP_STR


	if l4:
		dto_packet.src.port = l4.srcport
		dto_packet.dst.port = l4.dstport
		return True

	#proto_num = ip.nxt #ip.next_header
	
	#if proto_num == ICMPV6_PROTOCOL:
	#	return True

	#log.info("Blocked non TCP/UDP ipv6 packet %s", proto_num);
	return False


def parsed_ip(dto_packet, ethernet_packet):
	ip = ethernet_packet.find('ipv4')

	if not ip:
		ip = ethernet_packet.find('ipv6') # Try ipv6
		return ip and load_ipv6_info(dto_packet, ip)

	return ip and load_ipv4_info(dto_packet, ip)


def block_packet(packet, event):
    fm = of.ofp_flow_mod()
    fm.match = of.ofp_match.from_packet(packet, event.port)
    fm.actions = []  # No actions = drop
    fm.priority = 100  # Higher than default rules
    fm.idle_timeout = 10  # Optional
    fm.hard_timeout = 30  # Optional

    event.connection.send(fm)    

class Firewall (EventMixin) :
	def __init__(self, connection) :
		#self.listenTo(core.openflow)
		self.connection = connection
		connection.addListeners(self)

		log.debug("Added Redes Firewall to connection")

	def _handle_PacketIn (self, event):
		packet = event.parsed
		dto_packet = rule_loader.PacketData()

		# Extract MAC
		dto_packet.src.mac = str(packet.src)
		dto_packet.dst.mac = str(packet.dst)


		if not parsed_ip(dto_packet, packet):
			if dto_packet.red_protocol == None:
				log.debug("Not ipv4/ipv6 packet type %s", ethernet.getNameForType(packet.type))
			#else:
			#	log.debug("blocked invalid transport protocol red prot: %s",dto_packet.red_protocol)

			return
		
		if dto_packet.protocol != None: # Not defined protocol at this point is assumed as invalid
			
			if dto_packet.is_blocked_by(FIREWALL_RULES):
				log.info("Blocked packet %s", dto_packet)
				block_packet(packet, event)
				return
			log.info("Rules wise not blocked %s", dto_packet)
		#else:
		#	log.debug("Blocked unrecognized packet eth type %s :: packet dto:\n%s",ethernet.getNameForType(packet.type), dto_packet)

		# If not blocked, flood or forward
		msg = of.ofp_packet_out()
		msg.data = event.ofp
		msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
		msg.in_port = event.port
		self.connection.send(msg)

	#def _handle_ConnectionUp(self,event) :
		# Add your logic here ...
	#	log.debug("-------> CONNECTION UP {0}".format(event.__dict__))

	#def _handle_ConnectionDown(self,event) :
		# Add your logic here ...
	#	log.debug("-------> CONNECTION Down: {0}".format(event))

	#def _handle_PacketIn(self,event) :
		# Add your logic here ...
		#log.debug("-------> Packet In: {0}".format(event.__dict__))
		#packet = event.parsed
		#inport = event.port

		# Extract MAC
		#src_mac = str(packet.src)		
		#log.debug("----> packet {0} in port {1} ... {2}".format(packet, inport, src_mac))

	#def _handle_FlowRemoved(self,event) :
	# Add your logic here ...
	#	log.debug("-------> Flow Removed? {0}".format(event))


"""
def launch():
	# Starting the Firewall module
	log.debug("-------> Registering Redes TP2 Firewall")
	core.registerNew(Firewall)
"""

def launch():
	def start_switch(event):
		log.info("Attaching Redes Firewall to switch: %s", event.connection)
		Firewall(event.connection)
	core.openflow.addListenerByName("ConnectionUp", start_switch)


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