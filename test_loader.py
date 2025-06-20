from rule_loader import *
def should_block(rules, packet):
    ind = 0
    for rule in rules:
        print("+++++++++++++++++++++++ CHECKING RULE",ind, rule)
        if rule.should_block(packet):
            return True
        ind+=1
    return False    

if __name__ == "__main__":
    print("-------> Running test loader!");
    rules = []

    load_rules_from("config.json", rules)

    print("----->FINAL LEN", len(rules))

    packet = PacketData("tcp")

    packet.src.mac = "MAC1"
    packet.src.port = 5001

    packet.dst.mac = "MAC2"
    packet.dst.port = 5002

    print("Should block first packet? ", should_block(rules, packet))
