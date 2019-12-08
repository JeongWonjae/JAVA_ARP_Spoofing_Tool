package model;

import java.util.Arrays;

public class ARP {
	//arp packet
	private byte[] destinationMAC=new byte[6];
	private byte[] sourceMAC=new byte[6];
	private byte[] ethernetType={0x08, 0x06}; //arp packet
	private byte[] hardwareType={0x00, 0x01}; //ehternet packet
	private byte[] protocolType={0x08, 0x00}; //ipv4
	private byte hardwareSize=0x06; //mac addr size (6bytes)
	private byte protocolSize=0x04; //ip addr size (4bytes)
	private byte[] opcode = new byte[2]; //operation code
	private byte[] senderMAC=new byte[6];
	private byte[] senderIP=new byte[4];
	private byte[] targetMAC=new byte[6];
	private byte[] targetIP=new byte[4];
	
	public void makeAPRRequest(byte[] sourceMAC, byte[] senderIP, byte[] targetIP) { //know target mac addr		
		Arrays.fill(destinationMAC, (byte)0xff); //fill broadcast bytes all 0s for packet
		System.arraycopy(sourceMAC, 0, this.sourceMAC, 0, 6);
		opcode[0]=0x00; opcode[1]=0x01; //operation code
		System.arraycopy(sourceMAC, 0, this.senderMAC, 0, 6);
		System.arraycopy(senderIP, 0, this.senderIP, 0, 4);
		Arrays.fill(targetMAC, (byte)0x00); //fill all 0s to target's mac addr field, because we don't know target's mac addr
		System.arraycopy(targetIP, 0, this.targetIP, 0, 4);
	}
	
	public void makeAPRReply(byte[] destinationMAC, byte[] sourceMAC, byte[] senderMAC, byte[] senderIP, byte[] targetMAC,
			byte[] targetIP) { //reply target mac addr about request packet
		System.arraycopy(destinationMAC, 0, this.destinationMAC, 0, 6);
		System.arraycopy(sourceMAC, 0, this.sourceMAC, 0, 6);
		opcode[0]=0x00; opcode[1]=0x02; //operation reply code
		System.arraycopy(senderMAC, 0, this.senderMAC, 0, 6);
		System.arraycopy(senderIP, 0, this.senderIP, 0, 4);
		System.arraycopy(targetMAC, 0, this.targetMAC, 0, 6);
		System.arraycopy(targetIP, 0, this.targetIP, 0, 4);
	}
	
	public byte[] getPacket() { //make packet
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
