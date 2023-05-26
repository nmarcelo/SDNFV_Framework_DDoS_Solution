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

file1 = "/home/marcelo/Documents/FlowCollectionDataset/TimeExperiment.txt"

class CustomTopo(Topo):
    def __init__(self, **opts):
        super(CustomTopo, self).__init__(**opts)

        # add switches
        ssw = [self.addSwitch('s%d' % n, protocols='OpenFlow13', cls=OVSKernelSwitch) for n in range(1, 21)] # add twenty switches

        # add hosts
        h = [self.addHost('h%d' % n, ip = '10.0.0.%d/24' % n) for n in range(1, 46)] # add four hosts
        

        
        # create topology

        # set bandwidth
        bw_ = 0.5*1000 #Gbps
        
        # connect monitor
        SW101 = self.addSwitch('s101', protocols='OpenFlow13', cls=OVSKernelSwitch)
        h200  = self.addHost( 'h200', ip = '10.0.0.200/24')
        self.addLink(SW101, h200, bw = bw_) 

        # connect to mirroring SWs
        self.addLink(SW101, ssw[0], bw = bw_) 
        self.addLink(SW101, ssw[1], bw = bw_) 
        self.addLink(SW101, ssw[2], bw = bw_) 
        self.addLink(SW101, ssw[6], bw = bw_) 
        self.addLink(SW101, ssw[13], bw = bw_)
        self.addLink(SW101, ssw[14], bw = bw_) 
        self.addLink(SW101, ssw[16], bw = bw_) 
        self.addLink(SW101, ssw[17], bw = bw_) 
        self.addLink(SW101, ssw[18], bw = bw_) 
        self.addLink(SW101, ssw[19], bw = bw_) 

	
        # Connect switches
        self.addLink(ssw[0], ssw[1], bw = bw_) 
        self.addLink(ssw[0], ssw[3], bw = bw_) 
        self.addLink(ssw[0], ssw[4], bw = bw_) 

        self.addLink(ssw[1], ssw[2], bw = bw_) 
        self.addLink(ssw[1], ssw[4], bw = bw_) 
        self.addLink(ssw[1], ssw[5], bw = bw_) 

        self.addLink(ssw[2], ssw[5], bw = bw_) 
        self.addLink(ssw[2], ssw[6], bw = bw_) 

        self.addLink(ssw[3], ssw[4], bw = bw_) 
        self.addLink(ssw[3], ssw[7], bw = bw_) 

        self.addLink(ssw[4], ssw[5], bw = bw_) 
        self.addLink(ssw[4], ssw[7], bw = bw_) 

        self.addLink(ssw[5], ssw[6], bw = bw_) 
        self.addLink(ssw[5], ssw[8], bw = bw_) 
        self.addLink(ssw[5], ssw[9], bw = bw_) 

        self.addLink(ssw[6], ssw[9], bw = bw_) 

        self.addLink(ssw[7], ssw[8], bw = bw_) 
        self.addLink(ssw[7], ssw[10], bw = bw_) 
        self.addLink(ssw[7], ssw[11], bw = bw_) 

        self.addLink(ssw[8], ssw[9], bw = bw_) 
        self.addLink(ssw[8], ssw[10], bw = bw_) 

        self.addLink(ssw[10], ssw[11], bw = bw_) 
        self.addLink(ssw[10], ssw[12], bw = bw_) 
        self.addLink(ssw[10], ssw[13], bw = bw_) 

        self.addLink(ssw[11], ssw[12], bw = bw_) 
        self.addLink(ssw[11], ssw[14], bw = bw_) 

        self.addLink(ssw[12], ssw[13], bw = bw_) 
        self.addLink(ssw[12], ssw[14], bw = bw_) 
        self.addLink(ssw[12], ssw[15], bw = bw_) 

        self.addLink(ssw[13], ssw[15], bw = bw_) 
        self.addLink(ssw[13], ssw[16], bw = bw_) 

        self.addLink(ssw[14], ssw[15], bw = bw_) 
        self.addLink(ssw[14], ssw[17], bw = bw_) 

        self.addLink(ssw[15], ssw[16], bw = bw_) 
        self.addLink(ssw[15], ssw[18], bw = bw_) 

        self.addLink(ssw[16], ssw[19], bw = bw_) 

        self.addLink(ssw[17], ssw[18], bw = bw_) 

        self.addLink(ssw[18], ssw[19], bw = bw_) 

        
        
        #  connect hosts
        [self.addLink(ssw[13], h[indx], bw = bw_) for indx in range(0,10)] # 
        [self.addLink(ssw[16], h[indx], bw = bw_) for indx in range(10,20)] # 
        [self.addLink(ssw[19], h[indx], bw = bw_) for indx in range(20,30)] # 
        [self.addLink(ssw[14], h[indx], bw = bw_) for indx in range(30,35)] # 
        [self.addLink(ssw[17], h[indx], bw = bw_) for indx in range(35,40)] # 
        [self.addLink(ssw[18], h[indx], bw = bw_) for indx in range(40,45)] # 

        

 
def saving_time_experiment(message):
    with open(file1,"a") as f:
        elapsed = time.time()
        f.write(message+'='+str(elapsed)+'\n')
    return 0       

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
    
    # severs
    # add original server
    s1 = net.get('s1')
    h250 = net.addDocker('h250', ports=[80], port_bindings={80: 8080}, dimage="my-ubuntu:latest")
    net.addLink(h250, s1, params1={"ip": "10.0.0.250/24"},addr1="00:00:00:00:00:FA")
    h250.popen('systemctl restart apache2')
    h250.popen('iperf -s')

    # add shadow server 1
    s2 = net.get('s2')
    h251 = net.addDocker('h251', ports=[80], port_bindings={80: 8081}, dimage="my-ubuntu:latest")
    net.addLink(h251, s2, params1={"ip": "10.0.0.251/24"},addr1="00:00:00:00:00:FB")
    h251.popen('systemctl restart apache2')
    h251.popen('iperf -s')

    # add shadow server 2
    s3 = net.get('s3')
    h252 = net.addDocker('h252', ports=[80], port_bindings={80: 8082}, dimage="my-ubuntu:latest")
    net.addLink(h252, s3, params1={"ip": "10.0.0.252/24"},addr1="00:00:00:00:00:FC")
    h252.popen('systemctl restart apache2')
    h252.popen('iperf -s')

    # add shadow server 3
    s7 = net.get('s7')
    h253 = net.addDocker('h253', ports=[80], port_bindings={80: 8083}, dimage="my-ubuntu:latest")
    net.addLink(h253, s7, params1={"ip": "10.0.0.253/24"},addr1="00:00:00:00:00:FD")
    h253.popen('systemctl restart apache2')
    h253.popen('iperf -s')

    CLI(net) 

    # Simulation parameters
    sim_time = 500   # simulation time in seconds
    att_time = 100    # time when the attack starts 
    att_duration=300 # duration of the attack

    # Traffic simulation
    print ('Topology ready')
    # legitimate
    print ('Starting legitimate traffic')
    hnr = [net.get('h%d' % i) for i in range(1,46)]
    pnr = [hnr[i].popen('iperf -c 10.0.0.250 -t %s -b 1M' %str(sim_time)) for i in range(len(hnr))]
    saving_time_experiment('Time_Start_Legitimate_Traffic')
    print ('Ready legitimate traffic')
    # attackers
    time.sleep(att_time)     # delay until the attacks start 
    

    print ('Starting attack traffic')
    ha = [net.get('h%d' % i) for i in range(31,33)] 
    pa =[ha[i].popen('slowhttptest -c 10000 -X -r 30 -w 1 -y 1 -n 1 -z 5 -u http://10.0.0.250/ -p 5 -l %s' %str(att_duration)) for i in range(len(ha))]
    
    ha = [net.get('h%d' % i) for i in range(36,38)] 
    pa =[ha[i].popen('slowhttptest -c 10000 -X -r 30 -w 1 -y 1 -n 1 -z 5 -u http://10.0.0.250/ -p 5 -l %s' %str(att_duration)) for i in range(len(ha))]

    ha = [net.get('h%d' % i) for i in range(41,43)] 
    pa =[ha[i].popen('slowhttptest -c 10000 -X -r 30 -w 1 -y 1 -n 1 -z 5 -u http://10.0.0.250/ -p 5 -l %s' %str(att_duration)) for i in range(len(ha))]
    
    print ('Ready attack traffic')
    saving_time_experiment('Time_Start_Attack_Traffic')

    time.sleep(att_duration) 
    saving_time_experiment('Time_End_Attack_Traffic')
    print ('End attack traffic')

    time.sleep(sim_time-att_time-att_duration)
    saving_time_experiment('Time_End_Legitimate_Traffic')
    print('End simulation')

    # Enabe CLI 
    CLI(net)    
    net.stop()