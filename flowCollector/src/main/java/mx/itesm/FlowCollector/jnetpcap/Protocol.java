package mx.itesm.FlowCollector.jnetpcap;

import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;
import org.jnetpcap.protocol.vpn.L2TP;
import org.jnetpcap.protocol.lan.Ethernet;

public class Protocol {

	private Tcp  tcp;
	private Udp  udp;
	private Ip4  ipv4;
	private Ip6  ipv6;
	private L2TP l2tp;
	private Ethernet eth;
	public Protocol() {
		super();
		eth = new Ethernet();
		tcp = new Tcp();
		udp = new Udp();
		ipv4 = new Ip4();
		ipv6 = new Ip6();
		l2tp = new L2TP();
	}

	public Ethernet getEthernet() {
		return eth;
	}

	public Tcp getTcp() {
		return tcp;
	}

	public Udp getUdp() {
		return udp;
	}

	public Ip4 getIpv4() {
		return ipv4;
	}

	public Ip6 getIpv6() {
		return ipv6;
	}

	public L2TP getL2tp() {
		return l2tp;
	}
	
}
