

import java.io.*;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Calendar;
import java.util.Date;
import java.util.Scanner;
import java.util.concurrent.TimeUnit;

import org.json.JSONObject;
import org.w3c.dom.ls.LSOutput;
import org.ws4d.coap.Constants;
import org.ws4d.coap.connection.BasicCoapChannelManager;
import org.ws4d.coap.interfaces.CoapChannelManager;
import org.ws4d.coap.interfaces.CoapClient;
import org.ws4d.coap.interfaces.CoapClientChannel;
import org.ws4d.coap.interfaces.CoapRequest;
import org.ws4d.coap.interfaces.CoapResponse;
import org.ws4d.coap.messages.CoapEmptyMessage;
import org.ws4d.coap.messages.CoapMediaType;
import org.ws4d.coap.messages.CoapRequestCode;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * @author Christian Lerche <christian.lerche@uni-rostock.de>
 */

public class Client implements CoapClient {
    private static String SERVER_ADDRESS ; //local IP address

    private static int PORT = Constants.COAP_DEFAULT_PORT;
    static int counter = 0;
    CoapChannelManager channelManager = null;
    CoapClientChannel clientChannel = null;

    byte[] encrypted_session_Key = null;
    byte[] dig_sig = null;
    byte[] decrypted_session_Key = null;
    static int flag=0;
    static int ok=0;
    static String payload;
    static String encryptedPayload;
    byte[] payloadEncBytes = null;
    static PublicKey pub_key_Server = null;
    public static void main(String[] args) throws InterruptedException, IOException, CertificateException {
	/*if (args != null && args.length >= 1) {
		SERVER_ADDRESS = args[0];
		if (args.length >= 2)
			PORT = Integer.parseInt(args[1]);
	}*/
        //Date date = Calendar.getInstance().getTime();
        //DateFormat dateFormat = new SimpleDateFormat("yyyy-mm-dd hh:mm:ss");
        //String strDate = dateFormat.format(date);
        DateTimeFormatter dtf = DateTimeFormatter.ofPattern("uuuu/MM/dd HH:mm:ss");
        LocalDateTime now = LocalDateTime.now();
        String strDate = dtf.format(now);
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("temp", "20°C");
        jsonObject.put("noise", "30dB");
        jsonObject.put("humidity", "40%");
        jsonObject.put("my_time", strDate);

        payload = jsonObject.toString();

        //System.out.println("Print JSON string :"+payload);
        //System.out.println("My payload in bytes is "+ getHex(payload.getBytes()));

        pub_key_Server = getCertificateKey ("ServerX509.cer");


        System.out.println("★★ Please write the IP of the server (local IP address): ");
        Scanner scan= new Scanner(System.in);
        SERVER_ADDRESS=scan.nextLine();
        System.out.println("Start CoAP Client: " + SERVER_ADDRESS);
        System.out.println("★★ My payload as JSON :"+payload);
        Client client = new Client();
        client.channelManager = BasicCoapChannelManager.getInstance();
        client.runTestClient0();
        TimeUnit.SECONDS.sleep(2);
        flag=1;
        client.runTestClient();
        TimeUnit.SECONDS.sleep(2);
        if(ok==1) client.runTestClient2();
    }

    public void runTestClient0(){
        try {
            clientChannel = channelManager.connect(this, InetAddress.getByName(SERVER_ADDRESS), PORT);
            CoapRequest coapRequestKey0 = clientChannel.createRequest(true, CoapRequestCode.GET);
            clientChannel.sendMessage(coapRequestKey0);
            System.out.println("Sent Request : GET the signature in order to validate the Server");


        } catch (UnknownHostException e) {
            e.printStackTrace();
        }
    }


    public void runTestClient(){
        try {
            clientChannel = channelManager.connect(this, InetAddress.getByName(SERVER_ADDRESS), PORT);
            CoapRequest coapRequestKey = clientChannel.createRequest(true, CoapRequestCode.GET);
            clientChannel.sendMessage(coapRequestKey);
            System.out.println("Sent Request : GET the encrypted session key");


        } catch (UnknownHostException e) {
            e.printStackTrace();
        }
    }

    public void runTestClient2(){
        try {
            clientChannel = channelManager.connect(this, InetAddress.getByName(SERVER_ADDRESS), PORT);

                    // SENT THE ENCRYPTED JSON PAYLOAD TO THE SERVER
                    CoapRequest coapRequestEncPayload = clientChannel.createRequest(true, CoapRequestCode.POST);
                    //coapRequestEncPayload.setUriPath(encryptedPayload);
                    coapRequestEncPayload.setPayload(payloadEncBytes);
                    clientChannel.sendMessage(coapRequestEncPayload);
                    System.out.println("Sent Request : POST the encrypted payload");

        } catch (UnknownHostException e) {
            e.printStackTrace();
        }
    }

    @Override
    public void onConnectionFailed(CoapClientChannel channel, boolean notReachable, boolean resetByServer) {
        System.out.println("Connection Failed");
    }

    @Override
    public void onResponse(CoapClientChannel channel, CoapResponse response)  {
        //verify the signature
        if (flag==0) {

            dig_sig = response.getPayload();
            //System.out.println("Dig_sign is "+getHex(dig_sig));
            System.out.println("★★ I've received the digital signature from the server !");
        }

        if(flag==1) {
            System.out.println("★★ I've received the encrypted session key from the server !!");
            encrypted_session_Key = response.getPayload();

            //System.out.println("Enc_session_key is "+getHex(encrypted_session_Key));

            try {
                if (hasValidSignature( encrypted_session_Key, pub_key_Server,dig_sig))
                {
                    ok = 1;
                    System.out.println("★★ The server is validated!");
                }
                else System.out.println("The server is not validated!");
            } catch (IOException e) {
                e.printStackTrace();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (InvalidKeyException e) {
                e.printStackTrace();
            } catch (SignatureException e) {
                e.printStackTrace();
            }

        }

        if(flag==1 && ok==1) {

            //1)get client's private key from his keystore
            KeyStore ks = null;
            PrivateKey privKeyClient = null;
            
            try {
                ks = KeyStore.getInstance(KeyStore.getDefaultType());
                char[] password = "passks".toCharArray();
                java.io.FileInputStream fis = new java.io.FileInputStream("myclient.ks");
                ks.load(fis, password);
                fis.close();
                privKeyClient = (PrivateKey) ks.getKey("ismkey1", password);

                //2) decrypt the session key
                decrypted_session_Key = decryptRSA(privKeyClient, encrypted_session_Key);
                System.out.println("★★ I've decrypted the session key !!");
                //System.out.println("Decrypted session key: "+getHex(decrypted_session_Key));
                //flag=1;
///////////////////////////////////////////////////////////////////////////////////////////////////////

                byte[] iv = new byte[]{0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF};
                IvParameterSpec ivSpec = new IvParameterSpec(iv);
                Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
                SecretKeySpec key = new SecretKeySpec(decrypted_session_Key, "AES");
                //System.out.println("Session key: "+getHex(key.getEncoded()));

                cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
                //System.out.println("number of input bytes is "+payload.getBytes().length);
                payloadEncBytes = cipher.doFinal(payload.getBytes());
                System.out.println("★★ I've encrypted the payload !! Now I'll send it to the server !!");

                //encryptedPayload = new String(payloadEncBytes, StandardCharsets.UTF_8);
                //System.out.println("Encrypted payload: " + getHex(payloadEncBytes));

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
            } catch (InvalidAlgorithmParameterException e) {
                e.printStackTrace();
            }

        }
    }

    //////////////////////////////////////////////////////////////
    public static byte[] decryptRSA(Key key, byte[] input) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE,key);
        return cipher.doFinal(input);
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
