package model;

import java.util.Arrays;

public class ARP {
	//declaration ARP packet component
	private byte[] ethernetType={0x08, 0x06}; //ARP type
	private byte[] hardwareType={0x00, 0x01};
	private byte[] protocolType={0x08, 0x00};
	private byte hardwareSize=0x06; 
	private byte protocolSize=0x04;
	private byte[] opcode = new byte[2]; //operation code
	private byte[] sourceMAC=new byte[6];
	private byte[] destinationMAC=new byte[6];
	
	private byte[] senderMAC=new byte[6];
	private byte[] senderIP=new byte[4];
	private byte[] targetMAC=new byte[6];
	private byte[] targetIP=new byte[4];
	
	//to know destination's MAC address
	public void makeAPRRequest(byte[] sourceMAC, byte[] senderIP, byte[] targetIP) {	
		//for broadcast
		Arrays.fill(destinationMAC, (byte)0xff);
		opcode[0]=0x00; opcode[1]=0x01;
		System.arraycopy(sourceMAC, 0, this.sourceMAC, 0, 6);
		
		System.arraycopy(sourceMAC, 0, this.senderMAC, 0, 6);
		System.arraycopy(senderIP, 0, this.senderIP, 0, 4);
		
		//fill all 0 to target's MAC address field
		Arrays.fill(targetMAC, (byte)0x00);
		System.arraycopy(targetIP, 0, this.targetIP, 0, 4);
	}
	
	public void makeAPRReply(byte[] destinationMAC, byte[] sourceMAC, byte[] senderMAC, byte[] senderIP, byte[] targetMAC, byte[] targetIP) {
		System.arraycopy(destinationMAC, 0, this.destinationMAC, 0, 6);
		System.arraycopy(sourceMAC, 0, this.sourceMAC, 0, 6); //trick field
		opcode[0]=0x00; opcode[1]=0x02; //reply code
		System.arraycopy(senderMAC, 0, this.senderMAC, 0, 6);
		System.arraycopy(senderIP, 0, this.senderIP, 0, 4);
		System.arraycopy(targetMAC, 0, this.targetMAC, 0, 6);
		System.arraycopy(targetIP, 0, this.targetIP, 0, 4);
	}
	
	//make ARP packet
	public byte[] getPacket() {
		byte[] bytes=new byte[42];
		System.arraycopy(destinationMAC, 0, bytes, 0, destinationMAC.length);
		System.arraycopy(sourceMAC, 0, bytes, 6, sourceMAC.length);
		System.arraycopy(ethernetType, 0, bytes, 12, ethernetType.length);
		System.arraycopy(hardwareType, 0, bytes, 14, hardwareType.length);
		System.arraycopy(protocolType, 0, bytes, 16, protocolType.length);
		bytes[18]=hardwareSize;
		bytes[19]=protocolSize;
		System.arraycopy(opcode, 0, bytes, 20, opcode.length);
		System.arraycopy(senderMAC, 0, bytes, 22, senderMAC.length);
		System.arraycopy(senderIP, 0, bytes, 28, senderIP.length);
		System.arraycopy(targetMAC, 0, bytes, 32, targetMAC.length);
		System.arraycopy(targetIP, 0, bytes, 38, targetIP.length);
		return bytes;
	}
}
