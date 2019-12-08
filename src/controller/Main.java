package controller;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.scene.layout.AnchorPane;
import javafx.stage.Stage;

public class Main extends Application {
	
	//��ĸ������ ����
	public static Pcap pcap = null;
	//�� ��ġ���� ����� �� �ִ� ���� ����
	public static PcapIf device=null;
	
	public static byte[] myIP=null;
	public static byte[] senderIP=null;
	public static byte[] targetIP=null;
	
	public static byte[] myMAC=null;
	public static byte[] senderMAC=null;
	public static byte[] targetMAC=null;
	
	//���������� ���α׷� ȭ��, ������ �ǹ̸� ����
	private Stage primaryStage;
	private AnchorPane layout;
	
	@Override
	//FX������ start��� �Լ��� ������ �� �� ����
	public void start(Stage primaryStage) {
	//primaryStage�� �ʱ�ȭ������, ������ ����
		this.primaryStage=primaryStage;
		this.primaryStage.setTitle("JavaFX ARP Spoofing");
		this.primaryStage.setOnCloseRequest(e->System.exit(0)); //�ݱ��ư�� ������ �� ��ü ����
		setLayout();
	}
	
	public void setLayout() {
		try {
	//view.fxml�� ������
			FXMLLoader loader = new FXMLLoader();
	//view.fxml���� ��ġ�� ����
			loader.setLocation(Main.class.getResource("../view/View.fxml"));
	//��Ŀ���� �����ͼ� ��Ī������		
			layout = (AnchorPane) loader.load();
	//���� ���̾ƿ��� ��� ����		
			Scene scene = new Scene(layout);
	//���� �����
			primaryStage.setScene(scene);
	//���� ������
			primaryStage.show();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	//���� stage�� ��ȯ
	public Stage getPrimaryStage() {
		return primaryStage;
	}
	
	//��ġ�� fx���� �����ϴ� �⺻���� �Լ��μ� �׻� �� ��ɾ�� ������ �� ����
	public static void main(String[] args) {
		launch(args);
	}
}
