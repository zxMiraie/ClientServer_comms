package Client;

import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class Client {

   public static void main(String[] args) throws Exception {
       if (args.length != 3) {
               System.out.println("java Client host port user");
               System.exit(1);
       }
       String host = args[0];
       int port = Integer.parseInt(args[1]);
       String user = args[2];


       PublicKey serverPublicKey = loadPublicKey("server.pub");
       PrivateKey clientPrivateKey = loadPrivateKey(user + ".prv");

       Socket s = new Socket(host,port);

       DataInputStream dis = new DataInputStream(s.getInputStream());
       DataOutputStream dos= new DataOutputStream(s.getOutputStream());
       BufferedReader consoleIn = new BufferedReader(new InputStreamReader(System.in));

       byte[] clientRandom = new byte[16];
       SecureRandom secureRandom = new SecureRandom();
       secureRandom.nextBytes(clientRandom);
       byte[] userIDBytes = user.getBytes("UTF-8");

       //construct a payload to send
       //random 16 bytes + userid -> server will read those
       byte[] payloadOut = new byte[16 + userIDBytes.length];
       System.arraycopy(clientRandom, 0, payloadOut, 0, 16);
       System.arraycopy(userIDBytes, 0, payloadOut, 16, userIDBytes.length);

       byte[] encClientToServer = rsaEncrypt(payloadOut, serverPublicKey);
       byte[] sigClientToServer = signData(encClientToServer, clientPrivateKey);

       dos.writeInt(encClientToServer.length);
       dos.write(encClientToServer);
       dos.flush();

       dos.writeInt(sigClientToServer.length);
       dos.write(sigClientToServer);
       dos.flush();

       System.out.println("Client to Server sent");

       byte[] encServerToClient = receiveBytes(dis);
       byte[] sigServerToClient = receiveBytes(dis);

       boolean sigOk = verifySignature(encServerToClient, sigServerToClient, serverPublicKey);
       if (!sigOk) {
           System.err.println("Server signature verification FAILED. ABORT!");
           return;
       }
       System.out.println("Server signature verified successfully.");

       byte[] combinedRandom = rsaDecrypt(encServerToClient, clientPrivateKey);
       if (combinedRandom.length != 32) {
           System.err.println("Server payload is wrong.");
           return;
       }

       for (int i = 0; i < 16; i++) {
           if (combinedRandom[i] != clientRandom[i]) {
               System.err.println("Mismatch.");
               return;
           }
       }
       System.out.println("ClientRandom checked");
       //byte[] serverRandom = Arrays.copyOfRange(serverPayload, 16, 32);
       System.out.println("Received combinedRandom = " + Arrays.toString(combinedRandom));


       SecretKeySpec aesKey = new SecretKeySpec(combinedRandom, "AES");

       byte[] currentIV = md5(combinedRandom);

       //command
       while (true) {
           System.out.print("Enter command (ls, get <file>, bye): ");
           String cmd = consoleIn.readLine();
           if (cmd == null) break;
           cmd = cmd.trim();
           if (cmd.isEmpty()) continue;

           byte[] encCmd = aesEncrypt(cmd.getBytes("UTF-8"), aesKey, currentIV);
           currentIV = md5(currentIV);

           dos.writeInt(encCmd.length);
           dos.write(encCmd);
           dos.flush();


           if (cmd.equalsIgnoreCase("bye")) {
               System.out.println("Client exiting...");
               break;
           }


           byte[] encResp = receiveBytes(dis);
           byte[] plainResp = aesDecrypt(encResp, aesKey, currentIV);
           currentIV = md5(currentIV);

           if (cmd.startsWith("ls")) {
               String list = new String(plainResp, "UTF-8");
               System.out.println("Server listsl:\n" + list);

           } else if (cmd.startsWith("get ")) {
               String maybeError = new String(plainResp, "UTF-8");
               if (maybeError.startsWith("ERROR:")) {
                   System.err.println(maybeError);
               } else {
                   String filename = cmd.substring(4).trim();
                   Files.write(Paths.get(filename), plainResp);
                   System.out.println("File [" + filename + "] saved.");
               }

           } else {
               String respStr = new String(plainResp, "UTF-8");
               System.out.println("Server: " + respStr);
           }
       }

    }

    private static byte[] aesEncrypt(byte[] plain, SecretKeySpec aesKey, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(iv));
        byte[] cipherText = cipher.doFinal(plain);
        return cipherText;
    }

    private static byte[] aesDecrypt(byte[] cipherData, SecretKeySpec aesKey, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));
        return cipher.doFinal(cipherData);
    }

    private static byte[] md5(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(data);
    }

    private static byte[] receiveBytes(DataInputStream dis) throws IOException {
        int length = dis.readInt();
        if (length < 0 || length > 10_000_000) {
            throw new IOException("Invalid length: " + length);
        }
        byte[] data = new byte[length];
        dis.readFully(data);
        return data;
    }

    private static byte[] rsaEncrypt(byte[] data, PublicKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    private static byte[] rsaDecrypt(byte[] data, PrivateKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    private static byte[] signData(byte[] data, PrivateKey key) throws Exception {
        Signature signer = Signature.getInstance("SHA1withRSA");
        signer.initSign(key);
        signer.update(data);
        return signer.sign();
    }

    private static boolean verifySignature(byte[] data, byte[] signature, PublicKey key) throws Exception {
        Signature verifier = Signature.getInstance("SHA1withRSA");
        verifier.initVerify(key);
        verifier.update(data);
        return verifier.verify(signature);
    }

    private static PrivateKey loadPrivateKey(String filename) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(filename));
        PKCS8EncodedKeySpec prvkeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(prvkeySpec);
    }

    private static PublicKey loadPublicKey(String filename) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(filename));
        X509EncodedKeySpec pubkeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(pubkeySpec);
    }

}
