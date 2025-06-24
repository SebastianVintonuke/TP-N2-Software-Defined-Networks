
#Mututal exclusive
xterm h1, h4
h1
iperf3 -s -p 5200

h4
iperf3 -c 10.0.0.1 -p 5200



#Dest Port 80
xterm h1, h2
h1
iperf3 -s -p 80

h2
iperf3 -c 10.0.0.1 -p 80


#Dst port 5001, udp
xterm h1, h3
h1
iperf3 -s -p 5001

h3
iperf3 -c 10.0.0.1 -p 5001 -u


#On s1 not exlusion
xterm h3, h4
h3
iperf3 -s -p 5200

h4
iperf3 -c 10.0.0.3 -p 5200