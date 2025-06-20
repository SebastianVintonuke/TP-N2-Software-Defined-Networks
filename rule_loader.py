import json
import os


FIELD_SRC_MAC = "mac_src"
FIELD_DST_MAC = "mac_dst"

FIELD_DST_PORT = "dst_port"
FIELD_SRC_PORT = "src_port"
FIELD_PROTOCOL = "protocol"

FIELD_BIDIRECCIONAL = "bidireccional"

class Peer :
	def __init__(self, mac, port):
		self.mac = mac
		self.port = port

class PacketData :
	def __init__(self, protocol):
		self.protocol = protocol
		self.src = Peer("", 0)
		self.dst = Peer("", 0)



def CHECK_PORT(constraint, host):
	print("------> CHECKING PORT {0} is not {1}".format(host.port, constraint))
	return constraint == host.port

def CHECK_MAC(constraint, host):
	print("------> CHECKING MAC {0} is not {1}".format(host.mac, constraint))
	return constraint == host.mac

def CHECK_PROTOCOL(constraint, connection):
	print("------> CHECKING PROTOCOL '{0}'' is not '{1}'".format(connection.protocol, constraint))
	return constraint == connection.protocol


class Rule:

	def __init__(self, constraints):
		print("-------> constraints",constraints);

		self.constraints = constraints
		self.bidireccional = constraints.get(FIELD_BIDIRECCIONAL, False)

		self.connection_checks = []

		self.add_check(FIELD_PROTOCOL, self.connection_checks, CHECK_PROTOCOL)

		self.src_checks = []
		self.dst_checks = []

		self.add_check(FIELD_SRC_MAC, self.src_checks, CHECK_MAC)
		self.add_check(FIELD_SRC_PORT, self.src_checks, CHECK_PORT)

		self.add_check(FIELD_DST_MAC, self.dst_checks, CHECK_MAC)
		self.add_check(FIELD_DST_PORT, self.dst_checks, CHECK_PORT)

	def add_check(self, field, checks, validator):
		constraint = self.constraints.get(field, None)
		if constraint != None:
			#print("---------> ADDING CHECK", field, "!=", constraint)
			checks.append(lambda value: validator(constraint, value))


	def verify_checks(self, data, checks):
		for check in checks:
			if not check(data):
				return False
	
		return len(checks) > 0

	def verify_direccional_checks(self, src,dst):
		if len(self.src_checks) > 0 and not self.verify_checks(src, self.src_checks):
			return False

		return len(self.src_checks) > 0 and (len(self.dst_checks) == 0 
		or self.verify_checks(dst, self.dst_checks))

	def should_block(self, packet):
		if len(self.connection_checks) > 0 and not self.verify_checks(packet, self.connection_checks):
			return False
		
		if self.verify_direccional_checks(packet.src, packet.dst):
			return True

		if self.bidireccional and self.verify_direccional_checks(packet.dst, packet.src):
			return True

		return False


"""
return (
	self.verify_checks(packet, self.connection_checks)
	and 
	(
	self.verify_direccional_checks(packet.src, packet.dst)
	or
	(
		self.bidireccional and self.verify_direccional_checks(packet.dst, packet.src)
	)
	)
)
"""

def load_rules_from(file, out):

	if not os.path.isfile(file) :
		print("-----> File ",file, "does not exists or is not a file");
		return


	with open(file, "r") as reader:
		loaded = json.load(reader)

		for itm in loaded:
			out.append(Rule(itm))


	print("---------> LOAD RULES FROM ", file)



	print("To output", out)