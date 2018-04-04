package com.mbr.zuul.util.security.rsa;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

public class DCPRSAKeyPair {

    private static final String ALGORITHM = "RSA";
    private static final int KEY_SIZE = 2048;


    private String publicKey = "";
    private String privateKey = "";

    public DCPRSAKeyPair(String publicKey, String privateKey) {
        super();
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public String getPrivateKey() {
        return privateKey;
    }


    /**
     * 随机生成密钥对
     *
     * @return
     * @throws NoSuchAlgorithmException
     */
    public static DCPRSAKeyPair randomKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keygen = KeyPairGenerator.getInstance(ALGORITHM);
        SecureRandom random = new SecureRandom();
        // 512位已被破解，用1024位,最好用2048位
        keygen.initialize(KEY_SIZE, random);
        // 生成密钥对
        KeyPair keyPair = keygen.generateKeyPair();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        String privateKeyStr = Base64.getEncoder().encodeToString(privateKey.getEncoded());
        String publicKeyStr = Base64.getEncoder().encodeToString(publicKey.getEncoded());
        return new DCPRSAKeyPair(publicKeyStr, privateKeyStr);
    }

    /**
     * 保存密钥对到文件，PEM格式
     *
     * @param publicFile
     * @param privateFile
     */
    public void savePEMToFile(File publicFile, File privateFile) {
        String publicPem = addPublicPemHeaderAndFooter(publicKey);
        String privatePem = addPrivatePk8pemHeaderAndFooter(privateKey);
        DCPFileWriter.write(publicFile, publicPem);
        DCPFileWriter.write(privateFile, privatePem);
    }

    private String addPrivatePk8pemHeaderAndFooter(String body) {
        String header = "-----BEGIN PRIVATE KEY-----";
        String footer = "-----END PRIVATE KEY-----";

        return header + "\n" + body + "\n" + footer;
    }

    private String addPublicPemHeaderAndFooter(String body) {
        String header = "-----BEGIN PUBLIC KEY-----";
        String footer = "-----END PUBLIC KEY-----";
        return header + "\n" + body + "\n" + footer;
    }

    public static class DCPFileWriter {

        public static void write(File file, String content) {
            FileOutputStream os = null;
            try {
                os = new FileOutputStream(file, true);
                byte[] data = content.getBytes();
                os.write(data, 0, data.length);
                os.flush();
            } catch (Exception e) {
                e.printStackTrace();
            } finally {
                if (os != null) {
                    try {
                        os.close();
                    } catch (IOException e) {
                        e.printStackTrace();

                    }
                }
            }
        }

    }

}
