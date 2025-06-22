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
import copy
# Add your imports here ...
log = core.getLogger()


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

IPV6_TYPE = 0x86DD
IPV4_TYPE = 0x0800
MAP_RED_PROTOCOLS = {
	"ipv4": IPV4_TYPE,
	"ipv6":IPV6_TYPE,
}

MAP_TRANSPORT_PROTOCOLS = {
	"tcp": TCP_PROTOCOL,
	"udp": UDP_PROTOCOL,
	"icmp": ICMP_PROTOCOL,
}

class FlowRuleBuilder (rule_loader.RuleBuilder):
	def __init__(self):
		self.fm = of.ofp_flow_mod()
		self.fm.priority = 100
		self.fm.idle_timeout = 0  # Permanent rule
		self.fm.hard_timeout = 0  # Permanent rule
		self.fm.match = of.ofp_match()

		self.fm.match.dl_type = IPV4_TYPE
		self.has_filter_port = False
		self.has_filter_protocol = False

	def is_ipv6(self):
		return self.fm.match.dl_type == IPV6_TYPE

	def filter_by_src_mac(self, mac):
		try:
			self.fm.match.dl_src = EthAddr(mac)
			log.info("src mac: %s",mac)
		except Exception as e:
			log.info("FAILED src mac: %s .. %s",mac, e)


	def filter_by_dst_mac(self, mac):
		try:
			self.fm.match.dl_dest = EthAddr(mac)
			log.info("dst mac: %s",mac)
		except Exception as e:
			log.info("FAILED dst mac: %s .. %s",mac, e)

	def filter_by_src_ip(self, ip):
		try:
			self.fm.match.nw_src = IPAddr6(ip) if self.is_ipv6() else IPAddr(ip)
			log.info("src ip: %s",ip)
		except Exception as e:
			log.info("FAILED src ip: %s .. %s",ip, e)

	def filter_by_dst_ip(self, ip):
		try:
			self.fm.match.nw_dst = IPAddr6(ip) if self.is_ipv6() else IPAddr(ip)
			log.info("dst ip: %s",ip)
		except Exception as e:
			log.info("FAILED dst ip: %s .. %s",ip, e)

	def filter_by_src_port(self, port):
		log.info("src port: %s",port)
		self.fm.match.tp_src = port
		self.has_filter_port = True

	def filter_by_dst_port(self, port):
		log.info("dst port: %s",port)
		self.fm.match.tp_dst = port
		self.has_filter_port = True

	def filter_by_protocol(self, protocol):
		log.info("transport protocol: %s",protocol)
		prot_code = MAP_TRANSPORT_PROTOCOLS.get(protocol, None)
		if prot_code != None:
			self.fm.match.nw_proto = prot_code
			self.has_filter_protocol  = True

	def filter_by_red_protocol(self, red_protocol):
		log.info("red protocol: %s",red_protocol)
		prot_code = MAP_RED_PROTOCOLS.get(red_protocol, None)

		if prot_code != None:
			self.fm.match.dl_type = prot_code


	def add_to_connection(self, connection):

		if (self.has_filter_port or self.has_filter_protocol) and self.is_ipv6():
			log.warning("Specified a port filter or protocol filter, which for this version of openflow 1.0, is incompatible with ipv6.")
			return;

		if not self.has_filter_port or self.has_filter_protocol:
			connection.send(self.fm)
			return;

		log.info("Not specified transport protocol adding both TCP/UDP")

		fm = copy.deepcopy(self.fm)
		
		fm.match.nw_proto = TCP_PROTOCOL
		connection.send(fm)

		fm.match.nw_proto = UDP_PROTOCOL
		connection.send(fm)




def logger_debug(*args, **kwargs):
    format_str = " ".join((["%s"] * len(args)))
    log.debug(format_str,*args)

def logger_info(*args, **kwargs):
    format_str = " ".join((["%s"] * len(args)))
    log.info(format_str,*args)

rule_loader.logger = logger_debug
rule_loader.logger_info = logger_info


module_dir = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(module_dir, "config.json") # On the same folder as this firewall.py

FIREWALL_RULES = None

class Firewall (EventMixin) :
	def __init__(self, connection) :
		#self.listenTo(core.openflow)
		self.connection = connection
		connection.addListeners(self)

		log.info("Adding Redes Firewall Rules to connection")
		for rule in FIREWALL_RULES:
			rule.add_to_connection(connection)

	#def _handle_PacketIn (self, event):
	#	log.info("----> HANDLE PACKET IN? %s", event)
	def _handle_FlowRemoved (self, event):
		log.debug("---->FlowRemoved")
	def _handle_PortStatus (self, event):
		log.debug("---->PortStatus")
	def _handle_BarrierIn (self, event):
		log.debug("---->BarrierIn")
	def _handle_ErrorIn (self, event):
		log.debug("---->ErrorIn")
	def _handle_Statistics (self, event):
		log.debug("---->Statistics")
	def _handle_Events (self, event):
		log.debug("---->Events")

def launch():
	def start_switch(event):
		global FIREWALL_RULES
		dpid = event.dpid

		if FIREWALL_RULES == None:
			FIREWALL_RULES= rule_loader.load_rules(CONFIG_PATH, FlowRuleBuilder)


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