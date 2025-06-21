import json
import os


FIELD_SRC_MAC = "mac_src"
FIELD_DST_MAC = "mac_dst"

FIELD_DST_PORT = "dst_port"
FIELD_SRC_PORT = "src_port"
FIELD_PROTOCOL = "protocol"

FIELD_BIDIRECTIONAL = "bidireccional"

class Peer :
	def __init__(self, mac, port):
		self.mac = mac
		self.port = port
		self.ip = None

	def __repr__(self):
		if self.ip :
			return "mac:{0} ip:{1} port: {2}".format(self.mac,self.ip, self.port)
		return "mac:{0} port: {1}".format(self.mac, self.port)

class PacketData :
	def __init__(self, protocol = None):
		self.protocol = protocol
		self.red_protocol = None
		self.src = Peer(None, None)
		self.dst = Peer(None, None)

	def __repr__(self):
		return "red:{0} proto:{1}\nsrc=> {2}\ndst=> {3}".format(self.red_protocol,self.protocol, self.src, self.dst)



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
		self.bidirectional = constraints.get(FIELD_BIDIRECTIONAL, False)

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
	
		return True#len(checks) > 0

	def verify_direccional_checks(self, src,dst):
		if len(self.src_checks) > 0:
			
			if not self.verify_checks(src, self.src_checks):
				return False
			
			return (len(self.dst_checks) == 0 or self.verify_checks(dst, self.dst_checks))

		return len(self.dst_checks) > 0 and self.verify_checks(dst, self.dst_checks)

	def check_bidireccional_checks(self, packet):
		if self.verify_direccional_checks(packet.src, packet.dst):
			return True

		if self.bidirectional and self.verify_direccional_checks(packet.dst, packet.src):
			return True

		return False

	def should_block(self, packet):
		if len(self.connection_checks) > 0:
			if not self.verify_checks(packet, self.connection_checks):
				return False

			# Hay checks de coxion y se cumplieron todos
			if len(self.dst_checks) == 0 and len(self.src_checks) == 0:
				return True

		return self.check_bidireccional_checks(packet)	

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