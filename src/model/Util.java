package model;

public class Util {
	
	//스트링을 주소형식으로 바꿔줌
	public static String bytesToString(byte[] bytes) {
		StringBuilder sb=new StringBuilder();
		int i=0;
		for (byte b : bytes) {
			sb.append(String.format("%02x ", b & 0xff));
			if(++i%16==0) sb.append("\n");
		}
		return sb.toString();
	}

}
