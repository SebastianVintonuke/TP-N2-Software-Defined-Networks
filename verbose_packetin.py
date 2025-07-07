from pox.core import core
import pox.openflow.libopenflow_01 as of

from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.ipv6 import ipv6

from pox.lib.packet.tcp import tcp
from pox.lib.packet.udp import udp

from pox.lib.revent import *
from .dtos import packet as dtos

#from pox.lib.addresses import EthAddr


def log_debug(*args, **kwargs):
	pass
def log_info(*args, **kwargs):
	pass

TCP_STR = "tcp"
UDP_STR = "udp"
ICMP_STR = "icmp"


IPV4_STR = "ipv4"
IPV6_STR = "ipv6"

IPV6_TYPE = 0x86DD
IPV4_TYPE = 0x0800


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


def log_packet(label,packet):
	log_info(label,": ", packet.parse_protocols())
	log_info("src: ", packet.src)
	log_info("dst: ", packet.dst)

def load_ipv4_info(dto_packet, ip):
	dto_packet.red_protocol = IPV4_STR
	proto = ip.protocol 

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
		log_info("Non TCP/UDP ipv4 prot: %s", proto);
		
		log_packet("packet",dto_packet)
		return False


	log_debug("Should never block, VALID IP PROT %s", parse_protocol(proto));
	#Valid protocol ICMP or something....
	return True

def load_ipv6_info(dto_packet, ip):
	dto_packet.red_protocol = IPV6_STR
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

	#log_debug("Blocked non TCP/UDP ipv6 packet %s", proto_num);
	return False


def parsed_ip(dto_packet, ethernet_packet):
	ip = ethernet_packet.find('ipv4')

	if not ip:
		ip = ethernet_packet.find('ipv6') # Try ipv6
		return ip and load_ipv6_info(dto_packet, ip)

	return ip and load_ipv4_info(dto_packet, ip)


def verbose_packetin(event):
	packet = event.parsed
	dto_packet = dtos.PacketData()

	# Extract MAC
	dto_packet.src.mac = str(packet.src)
	dto_packet.dst.mac = str(packet.dst)

	if not parsed_ip(dto_packet, packet):
		if dto_packet.red_protocol == None:
			log_debug("Not ipv4/ipv6 packet type %s", ethernet.getNameForType(packet.type))
		return
	
	if dto_packet.protocol != None: # Not defined protocol at this point is assumed as invalid or not important.
		log_packet("Allowed Packet",dto_packet)