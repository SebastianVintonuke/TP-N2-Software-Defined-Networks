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

from pox.lib.util import dpid_to_str
#import pox.lib.packet as pkt

from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.addresses import IPAddr, IPAddr6, EthAddr
from collections import namedtuple
import os
from . import rule_loader

class FlowRuleBuilder:
	def __init__(self):
        self.fm = of.ofp_flow_mod()
        self.fm.priority = 100
        self.fm.idle_timeout = 0  # Permanent rule
        self.fm.hard_timeout = 0  # Permanent rule
        self.fm.match = of.ofp_match()
        self.is_ipv6 = False

    def filter_by_src_mac(self, mac):
    	self.fm.match.dl_src = EthAddr(mac)
    def filter_by_dst_mac(self, mac):
    	self.fm.match.dl_dest = EthAddr(mac)

    def filter_by_src_ip(self, ip):
    	self.fm.match.nw_src = IPAddr6(ip) if self.is_ipv6 else IPAddr(ip)

    def filter_by_dst_ip(self, ip):
    	self.fm.match.nw_dst = IPAddr6(ip) if self.is_ipv6 else IPAddr(ip)

    def filter_by_src_port(self, port):
        self.fm.match.tp_src = port

    def filter_by_dst_port(self, port):
        self.fm.match.tp_dst = port

    def filter_by_protocol(self, protocol):
    	prot_code = MAP_TRANSPORT_PROTOCOLS.get(protocol, None)
    	if prot_code != None:
	        self.fm.match.nw_proto = prot_code

    def filter_by_red_protocol(self, red_protocol):
    	prot_code = MAP_RED_PROTOCOLS.get(red_protocol, None)
    	self.is_ipv6 = prot_code == IPV6_TYPE

    	if prot_code != None:
	        self.fm.match.dl_type = prot_code




# Add your imports here ...
log = core.getLogger()

def logger_debug(*args, **kwargs):
    format_str = " ".join((["%s"] * len(args)))
    log.debug(format_str,*args)

def logger_info(*args, **kwargs):
    format_str = " ".join((["%s"] * len(args)))
    log.info(format_str,*args)

rule_loader.logger = logger_debug
rule_loader.logger_info = logger_info


module_dir = os.path.dirname(os.path.abspath(__file__))
file_path = os.path.join(module_dir, "config.json") # On the same folder as this firewall.py

FIREWALL_RULES = rule_loader.load_rules(file_path, FlowRuleBuilder)

TARGET_SWITCH = "00-00-00-00-00-01"
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
	return "icmp" if type == ICMP_PROTOCOL else str(type)

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

	#dto_packet.protocol = parse_protocol(proto)

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


IPV6_TYPE = 0x86DD
MAP_RED_PROTOCOLS = {
	"ipv4": 0x0800,
	"ipv6":IPV6_TYPE,
}

MAP_TRANSPORT_PROTOCOLS = {
	"tcp": TCP_PROTOCOL,
	"udp": UDP_PROTOCOL,
	"icmp": ICMP_PROTOCOL,
}


def add_flow_rules(connection):

        fm = of.ofp_flow_mod()
        fm.priority = 100
        fm.idle_timeout = 0  # Permanent rule
        fm.hard_timeout = 0  # Permanent rule

        fm.match = of.ofp_match()
        fm.match.dl_type = IPV4_PROTOCOL
        fm.match.nw_proto = TCP_PROTOCOL
        #fm.match.tp_dst = 80            # Destination TCP port
        connection.send(fm)


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
		add_flow_rules(connection)


	def _handle_PacketIn (self, event):
		packet = event.parsed
		dto_packet = rule_loader.PacketData()

		# Extract MAC
		dto_packet.src.mac = str(packet.src)
		dto_packet.dst.mac = str(packet.dst)


		if not parsed_ip(dto_packet, packet):
			if dto_packet.red_protocol == None:
				log.info("Not ipv4/ipv6 packet type %s", ethernet.getNameForType(packet.type))
			else:
				log.info("blocked invalid transport protocol red prot: %s",dto_packet.red_protocol)

			return
		
		if dto_packet.protocol != None: # Not defined protocol at this point is assumed as invalid
			
			if dto_packet.is_blocked_by(FIREWALL_RULES):
				log.info("Blocked packet %s", dto_packet)
				block_packet(packet, event)
				return
			log.info("Rules wise not blocked %s", dto_packet)
		else:
			log.info("None protocol, packet allow by default")

		block_packet(packet, event)

		# If not blocked, flood or forward
		#msg = of.ofp_packet_out()
		#msg.data = event.ofp
		#msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
		#msg.in_port = event.port
		#self.connection.send(msg)

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
		dpid = event.dpid  

		if dpid_to_str(dpid) == TARGET_SWITCH:
			log.info("Attaching Redes Firewall to switch: id:%s conn:%s", dpid_to_str(dpid) ,event.connection)
			Firewall(event.connection)
		else:
			log.info("Do not attach Redes Firewall to switch: id:%s conn:%s", dpid_to_str(dpid) ,event.connection)
			
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