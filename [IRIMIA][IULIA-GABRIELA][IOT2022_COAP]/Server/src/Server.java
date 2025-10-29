/* Copyright [2011] [University of Rostock]
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *****************************************************************************/



import org.ws4d.coap.connection.BasicCoapChannelManager;
import org.ws4d.coap.interfaces.CoapChannelManager;
import org.ws4d.coap.interfaces.CoapMessage;
import org.ws4d.coap.interfaces.CoapRequest;
import org.ws4d.coap.interfaces.CoapServer;
import org.ws4d.coap.interfaces.CoapServerChannel;
import org.ws4d.coap.messages.CoapMediaType;
import org.ws4d.coap.messages.CoapResponseCode;

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
import java.util.Arrays;
import java.util.Base64;
import java.util.concurrent.TimeUnit;

/**
 * @author Christian Lerche <christian.lerche@uni-rostock.de>
 */

public class Server implements CoapServer {
    private static final int PORT = 5683;
    static int counter = 0;
    static byte[] encrypted_session_Key = null;
   static byte[] session_key = null;
   static PrivateKey server_priv_key = null;
    byte[] session_key2 = null;
    byte[] encrypted_payload = null;
    byte[] encrypted_payload2 = null;
    static PublicKey pubKeyClient= null;;
    static PublicKey pubKeyClient2= null;;
    static int flag=0;
    static byte[] server_signature = null;
    static SecretKeySpec skeySpec = null;
    public static void main(String[] args) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        System.out.println("Start CoAP Server on port " + PORT);
        Server server = new Server();

        CoapChannelManager channelManager = BasicCoapChannelManager.getInstance();
        channelManager.createServerListener(server, PORT);

        //////////////////////////////////////////////////////////////
        //preparing the symmetric key (session key)
        //I assumed I have on the server side the certificate of the client
        //i want to encrypt the generated symmetric key using the public key of the client extracted from the certificate
        //1) extract the client's public key from his certificate

        pubKeyClient2 = getCertificateKey("ClientCertificateX509.cer");

        //2) generate the session key
        SecureRandom secureRandom = null;
        secureRandom = SecureRandom.getInstance("SHA1PRNG");
        session_key = new byte[16]; //16B for the key
        secureRandom.nextBytes(session_key);
        ///////////////////////////////////////////////////////
    }

    @Override
    public CoapServer onAccept(CoapRequest request) {
        System.out.println("Accept connection...");
        flag++;
        return this;
    }

    @Override
    public void onRequest(CoapServerChannel channel, CoapRequest request) {
        //System.out.println("Received message: " + request.toString()+ " URI: " + request.getUriPath());

        CoapMessage response1 = channel.createResponse(request, CoapResponseCode.Content_205);
        response1.setContentType(CoapMediaType.text_plain);

        //send the signature to the client
        if(flag==1)
        {
            KeyStore ks = null;
            try {
                ks = KeyStore.getInstance(KeyStore.getDefaultType());
                char[] password = "passks".toCharArray();
                java.io.FileInputStream fis = new java.io.FileInputStream("myserver.ks");
                ks.load(fis, password);
                fis.close();
                server_priv_key = (PrivateKey) ks.getKey("ismkey1", password);
                //3)encrypt the session key with the pubKeyClient & prepare signature
                encrypted_session_Key = encryptRSA(pubKeyClient2, session_key);
                server_signature = getDigitalSignature(encrypted_session_Key, server_priv_key);

                response1.setPayload(server_signature);
                channel.sendMessage(response1);
                System.out.println("★★ Sending the digital signature to the client !!");
            } catch (KeyStoreException | FileNotFoundException e) {
                e.printStackTrace();
            } catch (SignatureException e) {
                e.printStackTrace();
            } catch (NoSuchPaddingException e) {
                e.printStackTrace();
            } catch (BadPaddingException e) {
                e.printStackTrace();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (CertificateException e) {
                e.printStackTrace();
            } catch (InvalidKeyException e) {
                e.printStackTrace();
            } catch (UnrecoverableKeyException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            } catch (IllegalBlockSizeException e) {
                e.printStackTrace();
            }

        }

        if(flag==2) {

            //4)send the encrypted session key to the client
            //response.setPayload("payload...".getBytes());
            response1.setPayload(encrypted_session_Key);
            if (request.getObserveOption() != null) {
                System.out.println("Client wants to observe this resource.");
            }
            response1.setObserveOption(1);
            channel.sendMessage(response1);
            System.out.println("★★ Sending the encrypted session key to the client !!");


        }
/////////////////////////////////////////////////////////////
        //System.out.println("Received message: " + request.toString()+ " URI: " + request.getUriPath());
        //CoapMessage response2 = channel.createResponse(request, CoapResponseCode.Content_205);
        //response2.setContentType(CoapMediaType.text_plain);

        if(flag==3) {
            encrypted_payload = request.getPayload();//OK
            encrypted_payload2 = Arrays.copyOf(encrypted_payload, encrypted_payload.length);
            //flag=1;
            //System.out.println("The received encrypted payload is : " + getHex(encrypted_payload2));
            System.out.println("★★ I've received the encrypted payload from the client !!");

            byte[] iv = new byte[]{0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF};
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            Cipher cipher2;
            skeySpec = new SecretKeySpec(session_key, "AES"); //OK
            // System.out.println("Session key: " + getHex(skeySpec.getEncoded()));
            try {
                cipher2 = Cipher.getInstance("AES/CBC/NoPadding");
                //cipher.init(Cipher.DECRYPT_MODE, skeySpec, ivSpec);
                cipher2.init(Cipher.DECRYPT_MODE, skeySpec, ivSpec);

                byte[] payloadDecBytes = cipher2.doFinal(encrypted_payload2);

                String decryptedPayload = new String(payloadDecBytes, StandardCharsets.UTF_8);

                System.out.println("★★ My decrypted payload is: " + decryptedPayload);
                //System.out.println("My decrypted payload in bytes is:" + getHex(payloadDecBytes));
                flag=4;

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

    @Override
    public void onSeparateResponseFailed(CoapServerChannel channel) {
        System.out.println("Separate response transmission failed.");

    }

/////////////////////////////////////////////////////////
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
