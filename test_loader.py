import rule_loader

#    format_str = " ".join((["%s"] * len(args)))
def logger_debug(*args, **kwargs):
    pass
    #print(*args, **kwargs)

def logger_info(*args, **kwargs):
    print("[INFO] ",*args, **kwargs)

rule_loader.logger = logger_debug
rule_loader.logger_info = logger_info

def is_packet_blocked(rules, packet):
    ind = 0

    for rule in rules:
        rule_loader.logger("-----> CHECK RULE", ind)
        if rule.should_block(packet):
            return True
        ind+=1
    return False    


def test_01_protocol_block_rule():
    rules = rule_loader.load_rules("test_rules/simple_connection_rule.json")
    packet = rule_loader.PacketData("tcp")
    packet.src = rule_loader.Peer("MAC1", 5001)
    packet.dst = rule_loader.Peer("MAC2", 5002)

    assert is_packet_blocked(rules, packet) == True

    packet.src = rule_loader.Peer("MAC4", 5004)

    assert is_packet_blocked(rules, packet) == True

    packet.protocol = "udp" 
    assert is_packet_blocked(rules, packet) == False


def test_02_dest_port_block_rule():
    rules = rule_loader.load_rules("test_rules/dest_port_rule.json")
    packet = rule_loader.PacketData("tcp")
    packet.src = rule_loader.Peer("MAC1", 5001)
    packet.dst = rule_loader.Peer("MAC2", 5002)

    assert is_packet_blocked(rules, packet) == False

    packet.src = rule_loader.Peer("MAC4", 5004)

    assert is_packet_blocked(rules, packet) == False

    packet.dst.port = 5010
    assert is_packet_blocked(rules, packet) == True

def test_03_traffic_between_hosts():
    rules = rule_loader.load_rules("test_rules/traffic_between_hosts.json")
    packet = rule_loader.PacketData("tcp")
    packet.src = rule_loader.Peer("MAC1", 5001)
    packet.dst = rule_loader.Peer("MAC2", 5002)

    assert is_packet_blocked(rules, packet) == False

    packet.src = rule_loader.Peer("MAC4", 5004)

    assert is_packet_blocked(rules, packet) == False

    packet.src = rule_loader.Peer("MAC2", 5001)
    packet.dst = rule_loader.Peer("MAC5", 5002)
    assert is_packet_blocked(rules, packet) == True

    packet.dst = rule_loader.Peer("MAC2", 5001)
    packet.src = rule_loader.Peer("MAC5", 5002)
    assert is_packet_blocked(rules, packet) == True

def test_04_from_host_to_port():
    rules = rule_loader.load_rules("test_rules/general_rules.json")
    packet = rule_loader.PacketData("tcp")
    packet.src = rule_loader.Peer("MAC1", 5001)
    packet.dst = rule_loader.Peer("MAC2", 5002)

    assert is_packet_blocked(rules, packet) == False

    packet.src = rule_loader.Peer("MAC4", 5004)
    packet.dst = rule_loader.Peer("MAC3", 5002)

    assert is_packet_blocked(rules, packet) == False

    packet.src = rule_loader.Peer("MAC8", 5004)

    assert is_packet_blocked(rules, packet) == False

    packet.dst.port = 5001

    assert is_packet_blocked(rules, packet) == True

def test_05_more_complex_case():
    rules = rule_loader.load_rules("test_rules/caso_borde_1.json")
    packet = rule_loader.PacketData("tcp")
    packet.src = rule_loader.Peer("MAC1", 5001)
    packet.dst = rule_loader.Peer("MAC2", 5002)

    assert is_packet_blocked(rules, packet) == True

def test_06_more_complex_case_no_bidireccional():
    rules = rule_loader.load_rules("test_rules/caso_borde_1_no_bidireccional.json")
    packet = rule_loader.PacketData("tcp")
    packet.src = rule_loader.Peer("MAC1", 5001)
    packet.dst = rule_loader.Peer("MAC2", 5002)

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



