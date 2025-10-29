import org.eclipse.paho.client.mqttv3.IMqttDeliveryToken;
import org.eclipse.paho.client.mqttv3.MqttCallback;
import org.eclipse.paho.client.mqttv3.MqttMessage;

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
import java.util.concurrent.TimeUnit;

public class SimpleMqttCallBack implements MqttCallback {

    static int ok=0;
    static int flag=0;
    static byte[] encrypted_session_Key = null;
    static byte[] dig_signature = null;
    static byte[] decrypted_session_Key = null;
    static byte[] encrypted_payload = null;
    static SecretKeySpec skeySpec = null;
    public void connectionLost(Throwable throwable) {
        System.out.println("Connection to MQTT broker lost!");
    }

    public void messageArrived(String s, MqttMessage mqttMessage) throws Exception {
        flag++;
        if(flag==1) dig_signature = mqttMessage.getPayload();
        if(flag==2 ) {
            //System.out.println("Message received:\t"+ new String(mqttMessage.getPayload()) );
            //System.out.println("Encrypted session key received: "+getHex(mqttMessage.getPayload()));

            encrypted_session_Key = mqttMessage.getPayload();

            //check the signature first
            if(hasValidSignature(encrypted_session_Key,getCertificateKey("PublisherX509.cer"),dig_signature))
            {
                ok = 1;
                System.out.println("★★ The publisher is validated!");
                //get subscriber's private key from his keystore
                KeyStore ks = null;
                PrivateKey privKeySubscriber = null;
                try {
                    ks = KeyStore.getInstance(KeyStore.getDefaultType());
                    char[] password = "passks".toCharArray();
                    java.io.FileInputStream fis = new java.io.FileInputStream("subscriber.ks");
                    ks.load(fis, password);
                    fis.close();
                    privKeySubscriber = (PrivateKey) ks.getKey("ismkey1", password);

                    // decrypt the session key
                    decrypted_session_Key = decryptRSA(privKeySubscriber, encrypted_session_Key);
                    //System.out.println("★★ I've decrypted the session key !!");
                    System.out.println("★★ My decrypted session key is: " + getHex(decrypted_session_Key));

                } catch (KeyStoreException | FileNotFoundException e) {
                    e.printStackTrace();
                } catch (CertificateException e) {
                    e.printStackTrace();
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                } catch (IOException e) {
                    e.printStackTrace();
                } catch (UnrecoverableKeyException e) {
                    e.printStackTrace();
                } catch (NoSuchPaddingException e) {
                    e.printStackTrace();
                } catch (InvalidKeyException e) {
                    e.printStackTrace();
                } catch (IllegalBlockSizeException e) {
                    e.printStackTrace();
                } catch (BadPaddingException e) {
                    e.printStackTrace();
                }
            }


            else{
                System.out.println("The publisher is not validated!");
            }

        }

        //get encrypted payload
        if(flag==3 && ok==1) {
            encrypted_payload = mqttMessage.getPayload();
            //System.out.println("The received encrypted payload is : " + getHex(encrypted_payload));

            // decrypt the payload
            byte[] iv = new byte[]{0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF};
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            Cipher cipher;
            skeySpec = new SecretKeySpec(decrypted_session_Key, "AES");
            try {
                cipher = Cipher.getInstance("AES/CBC/NoPadding");
                cipher.init(Cipher.DECRYPT_MODE, skeySpec, ivSpec);
                byte[] payloadDecBytes = cipher.doFinal(encrypted_payload);
                String decryptedPayload = new String(payloadDecBytes, StandardCharsets.UTF_8);
                System.out.println("★★ My decrypted payload is: " + decryptedPayload);
                flag=0;
                ok=0;

            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (NoSuchPaddingException e) {
                e.printStackTrace();
            } catch (BadPaddingException e) {
                e.printStackTrace();
            } catch (IllegalBlockSizeException e) {
                e.printStackTrace();
            } catch (InvalidKeyException e) {
                e.printStackTrace();
            } catch (InvalidAlgorithmParameterException e) {
                e.printStackTrace();
            }
        }
    }

    public void deliveryComplete(IMqttDeliveryToken iMqttDeliveryToken) {

    }
    ///////////////////////////////////////////////////////////////////////////////////
    public static String getHex(byte[] array) //as byte array
    {
        String output= "";
        for(byte value :array) //for each byte value in the array
        {
            output += String.format("%02x",value);
        }
        return output;
    }
    public static byte[] decryptRSA(Key key, byte[] input) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE,key);
        return cipher.doFinal(input);
    }

    public static boolean hasValidSignature(byte[] enc_key , PublicKey key, byte[] digitalSignature) throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(key); //initialize for verifying
        //need to recompute the digital signature
        signature.update(enc_key);
        return signature.verify(digitalSignature); //will check the recomputed digital signature with the one given as argument//returns true or false

    }
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
}