package controller;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.scene.layout.AnchorPane;
import javafx.stage.Stage;

public class Main extends Application {
	
	//피캡변수를 선언
	public static Pcap pcap = null;
	//각 장치들을 담아줄 수 있는 변수 생성
	public static PcapIf device=null;
	
	public static byte[] myIP=null;
	public static byte[] senderIP=null;
	public static byte[] targetIP=null;
	
	public static byte[] myMAC=null;
	public static byte[] senderMAC=null;
	public static byte[] targetMAC=null;
	
	//실질적으로 프로그램 화면, 무대라는 의미를 가짐
	private Stage primaryStage;
	private AnchorPane layout;
	
	@Override
	//FX에서는 start라는 함수로 시작을 할 수 있음
	public void start(Stage primaryStage) {
	//primaryStage를 초기화시켜줌, 제목을 지정
		this.primaryStage=primaryStage;
		this.primaryStage.setTitle("JavaFX ARP Spoofing");
		this.primaryStage.setOnCloseRequest(e->System.exit(0)); //닫기버튼을 눌렀을 때 전체 종료
		setLayout();
	}
	
	public void setLayout() {
		try {
	//view.fxml을 가져옴
			FXMLLoader loader = new FXMLLoader();
	//view.fxml파일 위치를 지정
			loader.setLocation(Main.class.getResource("../view/View.fxml"));
	//앵커펜을 가져와서 매칭시켜줌		
			layout = (AnchorPane) loader.load();
	//씬은 레이아웃을 담는 공간		
			Scene scene = new Scene(layout);
	//씬을 띄워줌
			primaryStage.setScene(scene);
	//씬을 보여줌
			primaryStage.show();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	//현재 stage를 반환
	public Stage getPrimaryStage() {
		return primaryStage;
	}
	
	//런치는 fx에서 제공하는 기본적인 함수로서 항상 이 명령어로 실행할 수 있음
	public static void main(String[] args) {
		launch(args);
	}
}
