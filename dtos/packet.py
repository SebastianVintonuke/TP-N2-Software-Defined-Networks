from .rule_blocker import RuleBlocker

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

	def parse_protocols(self):
		return "red:{0} proto:{1}".format(self.red_protocol,self.protocol)
	def __repr__(self):
		return "red:{0} proto:{1}\nsrc=> {2}\ndst=> {3}".format(self.red_protocol,self.protocol, self.src, self.dst)


	def src_port_is(self, vl):
		return vl == self.src.port
	def dst_port_is(self, vl):
		return vl == self.dst.port

	def src_mac_is(self, vl):
		return vl == self.src.mac
	def dst_mac_is(self, vl):
		return vl == self.dst.mac

	def src_ip_is(self, vl):
		return vl == self.src.ip
	def dst_ip_is(self, vl):
		return vl == self.dst.ip

	def prot_is(self, vl):
		return vl == self.protocol

	def red_prot_is(self, vl):
		return vl == self.red_protocol





class BlockResult:
	def __init__(self, blocked, field, value, constraint):
		self.do_block = blocked
		self.log = field+ " '"+str(value)+"'"+(" is " if blocked else " is not ") + str(constraint)

	def add_to(self, vec):
		vec.append(self.log)


class VerbosePacket(PacketData):
	def __init__(self, protocol = None):
		super().__init__(protocol)

	def src_port_is(self, vl):
		return BlockResult(super().src_port_is(vl), "src port",self.src.port, vl)

	def dst_port_is(self, vl):
		return BlockResult(super().dst_port_is(vl), "dst port",self.dst.port, vl)


	def src_mac_is(self, vl):
		return BlockResult(super().src_mac_is(vl), "src mac",self.src.mac, vl)
	def dst_mac_is(self, vl):
		return BlockResult(super().dst_mac_is(vl), "dst mac",self.dst.mac, vl)


	def src_ip_is(self, vl):
		return BlockResult(super().src_ip_is(vl), "src ip",self.src.ip, vl)
	def dst_ip_is(self, vl):
		return BlockResult(super().dst_ip_is(vl), "dst ip",self.dst.ip, vl)


	def prot_is(self, vl):
		return BlockResult(super().prot_is(vl), "transport protocol",self.protocol, vl)
	def red_prot_is(self, vl):
		return BlockResult(super().red_prot_is(vl), "red protocol",self.red_protocol, vl)












class PacketBlockRule(RuleBlocker):

	def __init__(self):
		self.block_conditions = []
		#self.check_builder = check_builder

	def add_check(self, check):
		self.block_conditions.append(check)
		#self.block_conditions.append(self.check_builder(check))

	def filter_by_src_mac(self, mac):
		self.add_check(lambda pkt: pkt.src_mac_is(mac))
	def filter_by_src_ip(self, ip):
		self.add_check(lambda pkt: pkt.src_ip_is(ip))
	def filter_by_src_port(self, port):
		self.add_check(lambda pkt: pkt.src_port_is(port))

	def filter_by_dst_mac(self, mac):
		self.add_check(lambda pkt: pkt.dst_mac_is(mac))
	def filter_by_dst_ip(self, ip):
		self.add_check(lambda pkt: pkt.dst_ip_is(ip))
	def filter_by_dst_port(self, port):
		self.add_check(lambda pkt: pkt.dst_port_is(port))

	def filter_by_protocol(self, protocol):
		self.add_check(lambda pkt: pkt.prot_is(protocol))
	def filter_by_red_protocol(self, red_protocol):
		self.add_check(lambda pkt: pkt.red_prot_is(red_protocol))

	def should_block(self, packet):
		for block_condition in self.block_conditions:
			if not block_condition(packet):
				return False
		return len(self.block_conditions) > 0

	def should_block_verbose(self, packet):
		logs = []

		for block_condition in self.block_conditions:
			res= block_condition(packet)
			res.add_to(logs)

			if not res.do_block:
				return (False, logs)
		return (len(logs) > 0 , logs)



def is_blocked_by(pkt, rules):
    for rule in rules:
        if rule.should_block(pkt):
            return True
    return False    