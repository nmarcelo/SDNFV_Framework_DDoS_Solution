# SDNFV_Framework_DDoS_Solution


## Setup tools:
1. Install a linux OS, e.g. Ubuntu, or Virtualize
2. Install Mininet
3. Install ONOS (version  2.6.0) and setup the basic applications, as done in our tutorials in http://sdn.wikidot.com/tutorials
4. Make sure that the native app of ONOS ReactiveFowarding is deactivated/uninstalled
5. Install the [fwd_](/fwd_/) application which replaces the ReactiveForwarding and adds other functionalities
6. Install the [traffic_engineering](/traffic_engineering/) application

## Setup Network
1. Create docker images using  [DockerFile](sdn_nfv_tests/ubuntu/) 
2. Start network configured in script [exampleTopology_traffic.py](/sdn_nfv_tests/)

	2.1. >> sudo python3 exampleTopology_traffic.py
	
3. Run >> pingall  command in the mininet(contairned) terminal to check connectivity of all hosts


## Deploy IDS/IPS
1. Run the FlowCollectorModule. 

	1.1. Open a terminal at the [flowCollector](/flowCollector/) directoty
	
	1.2. >> sudo bash
	
	1.3. >> gradle execute
	
2. Run the IDS and IPS

	1.1. Open a terminal at the [ips](/ips/) directory
	
	1.2. >> sudo python3 qLearning.py

## Run tests
1. Open terminals in mininet

	1.1. >> xterm h1 h2 h3 h4
	
2. Initiate legitimate traffic from h1 and h3

	2.1. >>  iperf -c 10.0.0.%s -t 800 -b 10k
	
3. Initiate attack traffic from h2 and h4

	2.2 >> slowhttptest -c 10000 -X -r 300  -w 1 -y 1 -n 1 -z 5 -u http://localhost:8080/ -p 5 -l 350

## Notes:
1. For steps 2 and 3 of Setup Tools use the tutorials hosted at http://sdn.wikidot.com/tutorials
2. Host 101 captures the traffic of the network.
3. Some variables should be changed, such as:

	3.1. The paths where the results of the experiments are being saved, in [script lstm_server_for_ips_improved.py](/ids/slow_rate/lstm_testbed_based) 
	
	3.2. The paths where the LSTM model is allocated must be changed [script lstm_server_for_ips_improved.py](/ids/slow_rate/lstm_testbed_based) 
	
	3.3. Any other that causes conflict while running the app in your system.
	
4. The author will try to create a tutorial video that explains the deployment of the system and upload it to youtube. Thereafter, the link will be shared in this instruction file.

## How to cite this work
Yungaicela-Naula, N. M., Vargas-Rosales, C., & Perez-Diaz, J. A. (2023).
# SDNFV_Framework_DDoS_Solution
