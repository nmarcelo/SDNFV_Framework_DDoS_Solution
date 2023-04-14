#!/usr/bin/python
# data center based topology

from mininet.net import Containernet
from mininet.topo import Topo
from mininet.cli import CLI
from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.link import TCLink
import time
from mininet.util import dumpNodeConnections

# sudo mn -c
# sudo python3 exampleTopology_traffic.py

REMOTE_CONTROLLER_IP = '172.17.0.2'

class CustomTopo(Topo):
    def __init__(self, **opts):
        super(CustomTopo, self).__init__(**opts)

        # add switches
        ssw = [self.addSwitch('s%d' % n, protocols='OpenFlow13', cls=OVSKernelSwitch) for n in range(1, 7)] # add six switches

        # add hosts
        h = [self.addHost('h%d' % n, ip = '10.0.0.%d/24' % n) for n in range(1, 5)] # add four hosts
        

        
        # create topology

        # set bandwidth
        spine_bw = 1*1000 #Gbps
        leaf_bw = 0.25*1000 #Gbps
        
        # connect monitor
        SW101 = self.addSwitch('s101', protocols='OpenFlow13', cls=OVSKernelSwitch)
        h200  = self.addHost( 'h200', ip = '10.0.0.200/24')
        self.addLink(SW101, h200, bw = spine_bw) 
        [self.addLink(ssw[n], SW101, bw = spine_bw) for n in range(len(ssw))]
	
        # Connect switches
        self.addLink(ssw[0], ssw[1], bw = spine_bw) 
        self.addLink(ssw[0], ssw[2], bw = spine_bw) 
        self.addLink(ssw[0], ssw[3], bw = spine_bw) 
        self.addLink(ssw[1], ssw[2], bw = spine_bw) 
        self.addLink(ssw[1], ssw[4], bw = spine_bw)
        self.addLink(ssw[2], ssw[3], bw = spine_bw) 
        self.addLink(ssw[2], ssw[5], bw = spine_bw) 
        self.addLink(ssw[3], ssw[5], bw = spine_bw) 
        self.addLink(ssw[4], ssw[5], bw = spine_bw) 
        
        
        
        
        #  connect hosts
        self.addLink(ssw[0], h[0], bw = spine_bw) # h1 legitimate
        self.addLink(ssw[0], h[2], bw = spine_bw) # h3 legitimate
        self.addLink(ssw[1], h[1], bw = spine_bw) # h2 attacker
        self.addLink(ssw[1], h[3], bw = spine_bw) # h4 attacker

        #[self.addLink(ssw[indx], h[indx], bw = leaf_bw) for indx in range(0,6)] # 

        

if __name__ == '__main__':
    net = Containernet(topo=CustomTopo(),
                  controller=None,
                  cleanup=True,
                  autoSetMacs=True,
                  link=TCLink)
    net.addController("c0",
        controller=RemoteController,
        ip=REMOTE_CONTROLLER_IP,
        port=6653)
    net.start()
    
    leaf_bw = 0.25*1000 #Gbps

    # normal traffic
    normal_hosts_by_sw = 9
    start_normal_sw = 13
   
    # severs
    # add original server
    s4 = net.get('s4')
    h250 = net.addDocker('h250', ports=[80], port_bindings={80: 8080}, dimage="my-ubuntu:latest")
    net.addLink(h250, s4, params1={"ip": "10.0.0.250/24"},addr1="00:00:00:00:00:FA")
    h250.popen('systemctl restart apache2')
    h250.popen('iperf -s')

    # add shadow server 1
    s5 = net.get('s5')
    h251 = net.addDocker('h251', ports=[80], port_bindings={80: 8081}, dimage="my-ubuntu:latest")
    net.addLink(h251, s5, params1={"ip": "10.0.0.251/24"},addr1="00:00:00:00:00:FB")
    h251.popen('systemctl restart apache2')
    h251.popen('iperf -s')

    # add shadow server 2
    s6 = net.get('s6')
    h252 = net.addDocker('h252', ports=[80], port_bindings={80: 8082}, dimage="my-ubuntu:latest")
    net.addLink(h252, s6, params1={"ip": "10.0.0.252/24"},addr1="00:00:00:00:00:FC")
    h252.popen('systemctl restart apache2')
    h252.popen('iperf -s')


    #net.addLink(ssw[0], server, bw = leaf_bw)
        
    #hnr = [net.get('h%d' % i) for i in range(1,4)]
    #pnr = [hnr[i].popen('iperf -s') for i in range(len(hnr))]

    # clients

    #hns = [net.get('h%d' % i) for i in range(4,7)]
    #pns = [hns[i].popen('iperf -c 10.0.0.%s -t 800 -b 1M' % str(i+1)) for i in range(len(hns))]

    CLI(net)    
    net.stop()


