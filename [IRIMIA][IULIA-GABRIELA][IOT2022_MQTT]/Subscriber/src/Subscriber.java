import org.eclipse.paho.client.mqttv3.MqttClient;
import org.eclipse.paho.client.mqttv3.MqttException;
import org.eclipse.paho.client.mqttv3.persist.MemoryPersistence;

import java.util.concurrent.TimeUnit;

public class Subscriber {

    //static int flag=0;
    public static void main(String[] args) throws MqttException, InterruptedException {

        System.out.println("== START SUBSCRIBER ==");
        MemoryPersistence persistence = new MemoryPersistence();
        MqttClient client = new MqttClient("tcp://test.mosquitto.org:1883", MqttClient.generateClientId(),persistence);
        client.setCallback( new SimpleMqttCallBack() );
        client.connect();

        client.subscribe("validate_sender");
        client.subscribe("enc_key");
        //TimeUnit.SECONDS.sleep(5);
        client.subscribe("enc_payload");
    }

}