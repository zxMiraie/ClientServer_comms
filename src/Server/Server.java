package Server;

import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Server {

    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            System.err.println("java Server port");
            System.exit(1);
        }

        int port = Integer.parseInt(args[0]);
        PrivateKey serverPrivateKey = loadPrivateKey("server.prv");

        ServerSocket ss = new ServerSocket(port);
        System.out.println("Server listening on port " + port);
        while (true) {
            Socket s = ss.accept();
            System.out.println("Client connected");
            handleClient(s, serverPrivateKey);
        }
    }

    private static void handleClient(Socket s, PrivateKey serverPrivateKey) {
        try(DataInputStream dis = new DataInputStream(s.getInputStream());
            DataOutputStream dos = new DataOutputStream(s.getOutputStream())) {

            //client to server
            int len1 = dis.readInt();
            byte[] encClientToServer = new byte[len1];
            dis.readFully(encClientToServer);

            int len2 = dis.readInt();
            byte[] sigClientToServer = new byte[len2];
            dis.readFully(sigClientToServer);

            //as mentioned in the client first 16 are client random bytes
            //rest is userid
            byte[] decrypted = rsaDecrypt(encClientToServer, serverPrivateKey);
            byte[] clientRandom = Arrays.copyOfRange(decrypted, 0, 16);
            byte[] userIdBytes = Arrays.copyOfRange(decrypted, 16, decrypted.length);
            String userId = new String(userIdBytes, "UTF-8");

            System.out.println("UserID: " + userId);
            System.out.println("Client random: " + Arrays.toString(clientRandom));

            PublicKey clientPublicKey;
            clientPublicKey = loadPublicKey(userId + ".pub");

            boolean sigOk = verifySignature(encClientToServer, sigClientToServer, clientPublicKey);
            if (!sigOk) {
                System.err.println("Signature verification FAILED. Closing.");
                s.close();
                return;
            }
            System.out.println("Signature verified for user: " + userId);

            //server to client payload
            byte[] serverRandom = new byte[16];
            SecureRandom secureRandom = new SecureRandom();
            secureRandom.nextBytes(serverRandom);

            byte[] combinedRandom = new byte[32];
            System.arraycopy(clientRandom, 0, combinedRandom, 0, 16);
            System.arraycopy(serverRandom, 0, combinedRandom, 16, 16);

            byte[] encServerToClient = rsaEncrypt(combinedRandom, clientPublicKey);
            byte[] sigServerToClient = signData(encServerToClient, serverPrivateKey);

            dos.writeInt(encServerToClient.length);
            dos.write(encServerToClient);

            dos.writeInt(sigServerToClient.length);
            dos.write(sigServerToClient);
            dos.flush();

            System.out.println("Sent combinedRandom to client.");
            System.out.println("combinedRandom = " + Arrays.toString(combinedRandom));

            SecretKey aesKey = new SecretKeySpec(combinedRandom, "AES");

            byte[] currentIV = md5(combinedRandom);

            while (true) {
                int clen = dis.readInt();
                if (clen < 0 || clen > 10_000_000) {
                    System.err.println("Invalid command length: " + clen);
                    break;
                }
                byte[] encCmd = new byte[clen];
                dis.readFully(encCmd);

                byte[] cmdBytes = aesDecrypt(encCmd, aesKey, currentIV);
                currentIV = md5(currentIV);

                String cmd = new String(cmdBytes, "UTF-8").trim();
                System.out.println("Client cmd: " + cmd);

                if (cmd.equalsIgnoreCase("bye")) {
                    System.out.println("Bye bye client.");
                    break;
                } else if (cmd.equals("ls")) {
                    File dir = new File(".");
                    File[] files = dir.listFiles();
                    StringBuilder sb = new StringBuilder();
                    if (files != null) {
                        for (File f : files) {
                            if (!f.isDirectory() && !f.getName().endsWith(".prv")) {
                                sb.append(f.getName()).append("\n");
                            }
                        }
                    }
                    byte[] resp = sb.toString().getBytes("UTF-8");

                    byte[] encResp = aesEncrypt(resp, aesKey, currentIV);

                    currentIV = md5(currentIV);

                    dos.writeInt(encResp.length);
                    dos.write(encResp);
                    dos.flush();

                } else if (cmd.startsWith("get ")) {
                    String filename = cmd.substring(4).trim();
                    File f = new File(filename);
                    if (!f.exists() || f.isDirectory() || f.getName().endsWith(".prv")) {
                        String err = "File not found or invalid.";
                        byte[] encErr = aesEncrypt(err.getBytes("UTF-8"), aesKey, currentIV);
                        currentIV = md5(currentIV);

                        dos.writeInt(encErr.length);
                        dos.write(encErr);
                        dos.flush();
                    } else {
                        // read file
                        byte[] fileBytes = Files.readAllBytes(f.toPath());
                        byte[] encFile = aesEncrypt(fileBytes, aesKey, currentIV);
                        currentIV = md5(currentIV);

                        dos.writeInt(encFile.length);
                        dos.write(encFile);
                        dos.flush();
                    }
                } else {
                    String unknown = "Unknown command " + cmd;
                    byte[] encUnknown = aesEncrypt(unknown.getBytes("UTF-8"), aesKey, currentIV);
                    currentIV = md5(currentIV);

                    dos.writeInt(encUnknown.length);
                    dos.write(encUnknown);
                    dos.flush();
                }
            }

            s.close();



        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }


    }

    private static byte[] aesEncrypt(byte[] plain, SecretKey aesKey, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(iv));
        return cipher.doFinal(plain);
    }

    private static byte[] aesDecrypt(byte[] cipherData, SecretKey aesKey, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));
        return cipher.doFinal(cipherData);
    }

    private static byte[] rsaDecrypt(byte[] data, PrivateKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    private static byte[] rsaEncrypt(byte[] data, PublicKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    private static PrivateKey loadPrivateKey(String filename) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(filename));
        PKCS8EncodedKeySpec keyspec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(keyspec);
    }

    private static PublicKey loadPublicKey(String filename) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(filename));
        X509EncodedKeySpec keyspec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(keyspec);
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

    private static byte[] md5(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(data);
    }

}

