from mininet . topo import Topo

DEF_NUM_SWITCHES = 3
class DynamicTopology (Topo) :
	def build(self, number_switches = DEF_NUM_SWITCHES) :
		#Create switch
		switch_left = self.addSwitch('s0')
		switch_right = self.addSwitch(f's{DEF_NUM_SWITCHES+1}')

		# Create hosts
		h1 = self.addHost('host_1')
		h2 = self.addHost('host_2')
		h3 = self.addHost('host_3')
		h4 = self.addHost('host_4')

		# Add links between switches and hosts self . addLink ( switch_left , switch_right )

		self.addLink(switch_left,h1)
		self.addLink(switch_left,h2)


		# Add variable ammount of intermediate switches
		prev = switch_left

		for i in range(1, number_switches+1):
			switch_dinamico = self.addSwitch(f'switch_{i}')

			self.addLink(prev, switch_dinamico)
			prev = switch_dinamico

		self.addLink(prev,switch_right)
		self.addLink(switch_right,h3)
		self.addLink(switch_right,h4)
	
"""
topos = {
    "linends": (
        lambda client_number=DEFAULT_CLIENT_NUMBER,
        mtu=DO_NOT_MODIFY_MTU: LinearEndsTopo(client_number, mtu)
    )
}
"""

#topos = { 'customTopo': DynamicTopology }#Topo

topos = {
    'dynamicTopology': (
    	lambda n=DEF_NUM_SWITCHES: DynamicTopology(number_switches=int(n))
    )
}