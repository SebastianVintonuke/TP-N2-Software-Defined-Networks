from rule_loader import *
def is_packet_blocked(rules, packet):
    ind = 0

    for rule in rules:
        print("-----> CHECK RULE", ind)
        if rule.should_block(packet):
            return True
        ind+=1
    return False    


def load_rules(rules_file):
    rules = []
    load_rules_from(rules_file, rules)
    return rules    


def test_01_protocol_block_rule():
    rules = load_rules("test_rules/simple_connection_rule.json")
    packet = PacketData("tcp")
    packet.src = Peer("MAC1", 5001)
    packet.dst = Peer("MAC2", 5002)

    assert is_packet_blocked(rules, packet) == True

    packet.src = Peer("MAC4", 5004)

    assert is_packet_blocked(rules, packet) == True

    packet.protocol = "udp" 
    assert is_packet_blocked(rules, packet) == False


def test_02_dest_port_block_rule():
    rules = load_rules("test_rules/dest_port_rule.json")
    packet = PacketData("tcp")
    packet.src = Peer("MAC1", 5001)
    packet.dst = Peer("MAC2", 5002)

    assert is_packet_blocked(rules, packet) == False

    packet.src = Peer("MAC4", 5004)

    assert is_packet_blocked(rules, packet) == False

    packet.dst.port = 5010
    assert is_packet_blocked(rules, packet) == True

def test_03_traffic_between_hosts():
    rules = load_rules("test_rules/traffic_between_hosts.json")
    packet = PacketData("tcp")
    packet.src = Peer("MAC1", 5001)
    packet.dst = Peer("MAC2", 5002)

    assert is_packet_blocked(rules, packet) == False

    packet.src = Peer("MAC4", 5004)

    assert is_packet_blocked(rules, packet) == False

    packet.src = Peer("MAC2", 5001)
    packet.dst = Peer("MAC5", 5002)
    assert is_packet_blocked(rules, packet) == True

    packet.dst = Peer("MAC2", 5001)
    packet.src = Peer("MAC5", 5002)
    assert is_packet_blocked(rules, packet) == True

def test_04_from_host_to_port():
    rules = load_rules("test_rules/general_rules.json")
    packet = PacketData("tcp")
    packet.src = Peer("MAC1", 5001)
    packet.dst = Peer("MAC2", 5002)

    assert is_packet_blocked(rules, packet) == False

    packet.src = Peer("MAC4", 5004)
    packet.dst = Peer("MAC3", 5002)

    assert is_packet_blocked(rules, packet) == False

    packet.src = Peer("MAC8", 5004)

    assert is_packet_blocked(rules, packet) == False

    packet.dst.port = 5001

    assert is_packet_blocked(rules, packet) == True

def test_05_more_complex_case():
    rules = load_rules("test_rules/caso_borde_1.json")
    packet = PacketData("tcp")
    packet.src = Peer("MAC1", 5001)
    packet.dst = Peer("MAC2", 5002)

    assert is_packet_blocked(rules, packet) == True

def test_06_more_complex_case_no_bidireccional():
    rules = load_rules("test_rules/caso_borde_1_no_bidireccional.json")
    packet = PacketData("tcp")
    packet.src = Peer("MAC1", 5001)
    packet.dst = Peer("MAC2", 5002)

    assert is_packet_blocked(rules, packet) == False


def run_test(label, test):

    print("-------> Running TEST",label);
    test()
    print("-------> PASSED");

if __name__ == "__main__":
    print("-------> Running test loader!");
    run_test("01, protocol block rule", test_01_protocol_block_rule);
    run_test("02, destination port block rule", test_02_dest_port_block_rule);
    run_test("03, check block traffic between hosts",test_03_traffic_between_hosts)
    run_test("04, check block from src to port",test_04_from_host_to_port)
    run_test("05",test_05_more_complex_case)
    run_test("06",test_06_more_complex_case_no_bidireccional)



