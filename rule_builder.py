import json
import os



def logger(*args, **kwargs):
	pass

def logger_info(*args, **kwargs):
	pass

FIELD_SRC_MAC = "mac_src"
FIELD_DST_MAC = "mac_dst"

FIELD_SRC_IP = "ip_src"
FIELD_DST_IP = "ip_dst"

FIELD_DST_PORT = "dst_port"
FIELD_SRC_PORT = "src_port"


FIELD_PROTOCOL = "protocol"
FIELD_RED_PROTOCOL = "red_protocol"

FIELD_BIDIRECTIONAL = "bidireccional"

def FILTER_SRC_MAC(rule, vl):
	rule.filter_by_src_mac(vl)

def FILTER_SRC_IP(rule, vl):
	rule.filter_by_src_ip(vl)

def FILTER_SRC_PORT(rule, vl):
	rule.filter_by_src_port(vl)


def FILTER_DST_MAC(rule, vl):
	rule.filter_by_dst_mac(vl)

def FILTER_DST_IP(rule, vl):
	rule.filter_by_dst_ip(vl)

def FILTER_DST_PORT(rule, vl):
	rule.filter_by_dst_port(vl)

def FILTER_TRANSPORT_PROTOCOL(rule, vl):
	rule.filter_by_protocol(vl)
def FILTER_RED_PROTOCOL(rule, vl):
	rule.filter_by_red_protocol(vl)


class RuleBuilder:

	def __init__(self, constraints, invert= False):
		self.constraints = constraints
		self.checks = []
		
		self.add_check(FIELD_PROTOCOL, FILTER_TRANSPORT_PROTOCOL)
		self.add_check(FIELD_RED_PROTOCOL, FILTER_RED_PROTOCOL)


		if invert:
			self.add_check(FIELD_SRC_MAC, FILTER_DST_MAC)
			self.add_check(FIELD_SRC_IP,FILTER_DST_IP)
			self.add_check(FIELD_SRC_PORT, FILTER_DST_PORT)

			self.add_check(FIELD_DST_MAC, FILTER_SRC_MAC)
			self.add_check(FIELD_DST_IP, FILTER_SRC_IP)
			self.add_check(FIELD_DST_PORT, FILTER_SRC_PORT)
		else:
			self.add_check(FIELD_SRC_MAC, FILTER_SRC_MAC)
			self.add_check(FIELD_SRC_IP,FILTER_SRC_IP)
			self.add_check(FIELD_SRC_PORT, FILTER_SRC_PORT)

			self.add_check(FIELD_DST_MAC, FILTER_DST_MAC)
			self.add_check(FIELD_DST_IP, FILTER_DST_IP)
			self.add_check(FIELD_DST_PORT, FILTER_DST_PORT)
	
	def add_check(self, field, adder):
		constraint = self.constraints.get(field, None)
		if constraint != None:
			self.checks.append(lambda rule: adder(rule, constraint))



	def attach_checks(self, matcher):
		for check in self.checks:
			check(matcher)

	def build_new(self, rule_constructor):
		rule = rule_constructor()
		self.attach_checks(rule)
		return rule	



def load_rules_from(file, out, rule_constructor):

	if not os.path.isfile(file) :
		logger_info("File ",file, "does not exists or is not a file");
		return

	with open(file, "r") as reader:
		loaded = json.load(reader)

		for itm in loaded:
			logger_info("")
			logger_info("Creating new block rule:")
			out.append(RuleBuilder(itm).build_new(rule_constructor))

			if itm.get(FIELD_BIDIRECTIONAL, False):
				logger_info("Adding inverted rule:")
				out.append(RuleBuilder(itm, invert= True).build_new(rule_constructor))

	logger_info("Loaded Rules got rules count ",len(out))

def load_rules(rules_file, rule_constructor):
    rules = []
    load_rules_from(rules_file, rules, rule_constructor)
    return rules    


def silent_load_rules_from(file, out, rule_constructor):
	if not os.path.isfile(file) :
		logger_info("File ",file, "does not exists or is not a file");
		return

	with open(file, "r") as reader:
		loaded = json.load(reader)

		for itm in loaded:
			out.append(RuleBuilder(itm).build_new(rule_constructor))

			if itm.get(FIELD_BIDIRECTIONAL, False):
				out.append(RuleBuilder(itm, invert= True).build_new(rule_constructor))

def silent_load_rules(rules_file, rule_constructor):
    rules = []
    silent_load_rules_from(rules_file, rules, rule_constructor)
    return rules    








FIELD_TARGETS = "target_switches"
FIELD_RULES = "block_rules"

def load_config_rules(rules_spec, out, rule_constructor):
	for itm in rules_spec:
		logger_info("")
		logger_info("Creating new block rule:")
		out.append(RuleBuilder(itm).build_new(rule_constructor))

		if itm.get(FIELD_BIDIRECTIONAL, False):
			logger_info("Adding inverted rule:")
			out.append(RuleBuilder(itm, invert= True).build_new(rule_constructor))

	logger_info("Loaded Rules got rules count ",len(out))

def load_config(config_file, targets, rule_constructor):
	if not os.path.isfile(config_file) :
		logger_info("File ",config_file, "does not exists or is not a file");
		return []

	rules = []

	with open(config_file, "r") as reader:
		loaded = json.load(reader)

		for target in loaded.get(FIELD_TARGETS, []):
			targets.append(str(target))

		load_config_rules(loaded[FIELD_RULES], rules, rule_constructor)
		#logger_info("RULES JSON", )
		#load_rules_from(, rules, rule_constructor)
	return rules    
