import rule_builder
import dtos.packet as dtos
import sys


import unittest



def load_block_rules(file):
    return rule_builder.silent_load_rules(file, dtos.PacketBlockRule)
#    format_str = " ".join((["%s"] * len(args)))
def logger_debug(*args, **kwargs):
    pass
    #print(*args, **kwargs)

def logger_info(*args, **kwargs):
    print("[INFO] ",*args, **kwargs)

rule_builder.logger = logger_debug
rule_builder.logger_info = logger_info





def packet_data_checker(rules, packet):
    for rule in rules:
        if rule.should_block(packet):
            return True
    return False    

def verbose_checker(rules, packet):
    ind = 0

    for rule in rules:
        (blocked, logs)= rule.should_block_verbose(packet)
        rule_builder.logger_info("CHECK RULE", ind, "blocked:",blocked)

        for log in logs:
            rule_builder.logger_info(log)

        rule_builder.logger_info("")

        if blocked:
            return True
        
        ind+=1
    return False    




PACKET_TYPE = dtos.PacketData 
is_packet_blocked = packet_data_checker




class BlockingTests(unittest.TestCase):
    def test_01_protocol_block_rule(self):
        rules = load_block_rules("test_rules/simple_connection_rule.json")
        packet = PACKET_TYPE("tcp")
        packet.src = dtos.Peer("MAC1", 5001)
        packet.dst = dtos.Peer("MAC2", 5002)

        self.assertEqual(is_packet_blocked(rules, packet),True, "Packet should be blocked")

        packet.src = dtos.Peer("MAC4", 5004)

        self.assertEqual(is_packet_blocked(rules, packet),True, "Packet should be blocked")

        packet.protocol = "udp" 
        self.assertEqual(is_packet_blocked(rules, packet),False, "Packet should not be blocked")


    def test_02_dest_port_block_rule(self):
        rules = load_block_rules("test_rules/dest_port_rule.json")
        packet = PACKET_TYPE("tcp")
        packet.src = dtos.Peer("MAC1", 5001)
        packet.dst = dtos.Peer("MAC2", 5002)

        self.assertEqual(is_packet_blocked(rules, packet),False, "Packet should not be blocked")

        packet.src = dtos.Peer("MAC4", 5004)

        self.assertEqual(is_packet_blocked(rules, packet),False, "Packet should not be blocked")

        packet.dst.port = 5010
        self.assertEqual(is_packet_blocked(rules, packet),True, "Packet should be blocked")

    def test_03_traffic_between_hosts(self):
        rules = load_block_rules("test_rules/traffic_between_hosts.json")
        packet = PACKET_TYPE("tcp")
        packet.src = dtos.Peer("MAC1", 5001)
        packet.dst = dtos.Peer("MAC2", 5002)

        self.assertEqual(is_packet_blocked(rules, packet),False, "Packet should not be blocked")

        packet.src = dtos.Peer("MAC4", 5004)

        self.assertEqual(is_packet_blocked(rules, packet),False, "Packet should not be blocked")

        packet.src = dtos.Peer("MAC2", 5001)
        packet.dst = dtos.Peer("MAC5", 5002)
        self.assertEqual(is_packet_blocked(rules, packet),True, "Packet should be blocked")

        packet.dst = dtos.Peer("MAC2", 5001)
        packet.src = dtos.Peer("MAC5", 5002)
        self.assertEqual(is_packet_blocked(rules, packet),True, "Packet should be blocked")

    def test_04_from_host_to_port(self):
        rules = load_block_rules("test_rules/general_rules.json")
        packet = PACKET_TYPE("tcp")
        packet.src = dtos.Peer("MAC1", 5001)
        packet.dst = dtos.Peer("MAC2", 5002)

        self.assertEqual(is_packet_blocked(rules, packet),False, "Packet should not be blocked")

        packet.src = dtos.Peer("MAC4", 5004)
        packet.dst = dtos.Peer("MAC3", 5002)

        self.assertEqual(is_packet_blocked(rules, packet),False, "Packet should not be blocked")

        packet.src = dtos.Peer("MAC8", 5004)

        self.assertEqual(is_packet_blocked(rules, packet),False, "Packet should not be blocked")

        packet.dst.port = 5001

        self.assertEqual(is_packet_blocked(rules, packet),True, "Packet should be blocked")

    def test_05_more_complex_case(self):
        rules = load_block_rules("test_rules/caso_borde_1.json")
        packet = PACKET_TYPE("tcp")
        packet.src = dtos.Peer("MAC1", 5001)
        packet.dst = dtos.Peer("MAC2", 5002)

        self.assertEqual(is_packet_blocked(rules, packet),True, "Packet should be blocked")

    def test_06_more_complex_case_no_bidireccional(self):
        rules = load_block_rules("test_rules/caso_borde_1_no_bidireccional.json")
        packet = PACKET_TYPE("tcp")
        packet.src = dtos.Peer("MAC1", 5001)
        packet.dst = dtos.Peer("MAC2", 5002)

        self.assertEqual(is_packet_blocked(rules, packet),False, "Packet should not be blocked")

if __name__ == "__main__":
    
    if '-v' in sys.argv:
        print("-------> Running tests! verbose");
        PACKET_TYPE = dtos.VerbosePacket
        is_packet_blocked = verbose_checker
    else:
        print("-------> Running tests! Not verbose");

    unittest.main()


"""
def run_test(index, label, test):

    print(">Test",index,label);
    try:
        test()
        print(">PASS")
        return True
    except Exception as e:
        print(">TEST FAIL",e)
        return False


to_run = [
    ("protocol block rule", test_01_protocol_block_rule),
    ("destination port block rule", test_02_dest_port_block_rule),
    ("check block traffic between hosts",test_03_traffic_between_hosts),
    ("check block from src to port",test_04_from_host_to_port),
    ("more_complex_case",test_05_more_complex_case),
    ("more_complex_case_no_bidireccional",test_06_more_complex_case_no_bidireccional),
]

passed = 0
ind = 0
for test in to_run:
    ind+=1
    if run_test(ind, *test):
        passed+=1

print(">PASSED [{0}/{1}]".format(passed, ind))
"""