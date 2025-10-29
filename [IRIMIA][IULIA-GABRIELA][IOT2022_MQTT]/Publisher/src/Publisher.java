import org.eclipse.paho.client.mqttv3.MqttClient;
import org.eclipse.paho.client.mqttv3.MqttException;
import org.eclipse.paho.client.mqttv3.MqttMessage;
import org.eclipse.paho.client.mqttv3.persist.MemoryPersistence;
import org.json.JSONObject;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class Publisher {

    static byte[] encrypted_session_Key = null;
    static byte[] session_key = null;
    static PublicKey pubKeySubscriber = null;
    static byte[] payloadEncBytes = null;
    static String encryptedPayload;
    static byte[] publisher_signature = null;
    public static void main(String[] args) throws MqttException, NoSuchAlgorithmException, IOException, CertificateException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException, InvalidAlgorithmParameterException {

       // String messageString = "Hello World from Java!";

        //1) preparing the payload
        String jsonPayload ;
        DateTimeFormatter dtf = DateTimeFormatter.ofPattern("uuuu/MM/dd HH:mm:ss");
        LocalDateTime now = LocalDateTime.now();
        String strDate = dtf.format(now);
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("temp", "20°C");
        jsonObject.put("noise", "30dB");
        jsonObject.put("humidity", "40%");
        jsonObject.put("my_time", strDate);

        jsonPayload = jsonObject.toString();

        //2) generate the session key
        SecureRandom secureRandom = null;
        secureRandom = SecureRandom.getInstance("SHA1PRNG");
        session_key = new byte[16]; //16B for the key
        secureRandom.nextBytes(session_key);

        //3) extract the subscriber's public key from his certificate
        pubKeySubscriber = getCertificateKey("SubscriberX509.cer");

        //4) encrypt the session key

        encrypted_session_Key = encryptRSA(pubKeySubscriber,session_key);

        ////////////////////////////////////////////////////////////////////////////

        //5) encrypt the payload using the session key

        byte[] iv = new byte[]{0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF};
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        SecretKeySpec key = new SecretKeySpec(session_key, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);

        payloadEncBytes = cipher.doFinal(jsonPayload.getBytes());

       // encryptedPayload = new String(payloadEncBytes, StandardCharsets.UTF_8);

        ///////////////////////////////////////////////////////////////////////////

        MemoryPersistence persistence = new MemoryPersistence();
        System.out.println("== START PUBLISHER ==");
        MqttClient client = new MqttClient("tcp://test.mosquitto.org:1883", MqttClient.generateClientId(),persistence);
        System.out.println("★★ My session key is : " + getHex(session_key));
        client.connect();

        //send the digital signature to validate the sender(the publisher) on the subscriber side
        //we need the publisher's private key from his keystore
        KeyStore ks = null;
        PrivateKey publisher_priv_key = null;
        try {
            ks = KeyStore.getInstance(KeyStore.getDefaultType());
            char[] password = "passks".toCharArray();
            java.io.FileInputStream fis = new java.io.FileInputStream("publisher.ks");
            ks.load(fis, password);
            fis.close();
            publisher_priv_key = (PrivateKey) ks.getKey("ismkey1", password);


            publisher_signature = getDigitalSignature(encrypted_session_Key, publisher_priv_key);
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        }
        MqttMessage m0 = new MqttMessage();
        m0.setPayload(publisher_signature);

        client.publish("validate_sender", m0);
        System.out.println("★★ Validate_sender_message published !");


        //send enc_session key to the subscriber
        MqttMessage m1 = new MqttMessage();
        m1.setPayload(encrypted_session_Key);

        client.publish("enc_key", m1);

       // System.out.println("My enc key is: "+getHex(encrypted_session_Key));
        System.out.println("★★ Enc_session_key_message published !");

        //send encrypted payload to the subscriber
        MqttMessage m2 = new MqttMessage();
        m2.setPayload(payloadEncBytes);

        client.publish("enc_payload", m2);
        System.out.println("★★ Enc_payload_message published !");
       // System.out.println("Encrypted payload published: " + getHex(payloadEncBytes));


        client.disconnect();
        System.out.println("== END PUBLISHER ==");

    }
////////////////////////////////////////////////////////////////////////////////
public static PublicKey getCertificateKey (String certificateFile) throws IOException, CertificateException {
    File file = new File(certificateFile);
    if(!file.exists())
    {
        System.out.println("No certificate file available");
        throw new FileNotFoundException();
    }
    FileInputStream fis = new FileInputStream(file);
    //to open the certificate
    CertificateFactory certFactory = CertificateFactory.getInstance("X.509");//we can open 509 certificates
    X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(fis);//we have the certificate object

    fis.close();
    return certificate.getPublicKey(); //returns the public key
}

    public static byte[] encryptRSA(Key key, byte[] input) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA");//RSA works as a stream cipher (take 1B at a time)
        cipher.init(Cipher.ENCRYPT_MODE,key);
        return cipher.doFinal(input); //process the entire buffer
    }

    public static String getHex(byte[] array) //as byte array
    {
        String output= "";
        for(byte value :array) //for each byte value in the array
        {
            output += String.format("%02x",value);
        }
        return output;
    }

    //to generate a digital signature (computing a hash and encrypting it with a private key)
    public static byte[] getDigitalSignature(byte[] mybyte, PrivateKey key) throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {

        //to generate the signature
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(key);

        //let's sign the document
        signature.update(mybyte);
        return signature.sign(); //we get the signature of our byte[]
    }

}