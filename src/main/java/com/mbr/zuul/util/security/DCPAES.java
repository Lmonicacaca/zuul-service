package com.mbr.zuul.util.security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Random;

public class DCPAES {

    private static final String ALGORITHM = "AES";
    private static final String CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final String DEFAULT_CHARSET = "UTF-8";

    public enum DCPAESSize {
        DCPAES128(16),
        DCPAES192(24),
        DCPAES256(32);

        private int keySize;

        DCPAESSize(int size) {
            this.keySize = size;
        }

        public int getKeySize() {
            return keySize;
        }
    }

    /**
     * 通过指定size随机密钥
     *
     * @return
     * @throws NoSuchAlgorithmException
     */
    public static byte[] randomKey(DCPAESSize dcpSize) throws NoSuchAlgorithmException {
        KeyGenerator keygen = KeyGenerator.getInstance(ALGORITHM);
        // 16 字节 == 128 bit
        keygen.init(dcpSize.getKeySize() * 8, new SecureRandom());
        SecretKey secretKey = keygen.generateKey();
        return secretKey.getEncoded();
    }

    /**
     * 随机iv
     *
     * @return
     */
    public static byte[] randomIV() {
        StringBuffer stringBuffer = new StringBuffer();

        for (int i = 0; i < 16; i++) {
            stringBuffer.append(Integer.toHexString(new Random().nextInt(16)));
        }

        String s = stringBuffer.toString();

        return stringBuffer.toString().getBytes();
    }


    /**
     * 通过base64String 构造SecretKeySpec
     *
     * @param base64String
     * @return
     */
    public static SecretKeySpec keySpecForBase64String(String base64String) {
        byte[] secretKey = Base64.getDecoder().decode(base64String);
        return new SecretKeySpec(secretKey, ALGORITHM);
    }


    /**
     * 通过byte构造SecretKeySpec
     *
     * @param bytes
     * @return
     */
    public static SecretKeySpec keySpecForByte(byte[] bytes) {

        return new SecretKeySpec(bytes, ALGORITHM);
    }

    /**
     * encrypt
     *
     * @param key
     * @param plain
     * @return
     */
    public static byte[] encrypt(SecretKeySpec key, byte[] plain, byte[] iv) throws Exception {

        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key,ivSpec);// 初始化
        byte[] result = cipher.doFinal(plain);
        return result;
    }



    /**
     * encrypt
     *
     * @param base64KeyString
     * @param plain
     * @return
     */
    public static byte[] encrypt(String base64KeyString, byte[] plain, byte[] iv) throws Exception {
        return encrypt(keySpecForBase64String(base64KeyString), plain, iv);
    }

    /**
     * encrypt
     *
     * @param keyBytes
     * @param plain
     * @return
     */
    public static byte[] encrypt(byte[] keyBytes, byte[] plain, byte[] iv) throws Exception {
        return encrypt(keySpecForByte(keyBytes), plain, iv);
    }


    /**
     * encrypt
     *
     * @param key
     * @param cipherBytes
     * @return
     * @throws Exception
     */
    public static byte[] decrypt(SecretKeySpec key, byte[] cipherBytes, byte[] iv) throws Exception {
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        byte[] result = cipher.doFinal(cipherBytes);
        return result;
    }

    /**
     * decrypt
     *
     * @param base64KeyString
     * @param cipherBytes
     * @return
     */
    public static byte[] decrypt(String base64KeyString, byte[] cipherBytes, byte[] iv) throws Exception {
        return decrypt(keySpecForBase64String(base64KeyString), cipherBytes, iv);
    }

    /**
     * decrypt
     *
     * @param keyBytes
     * @param cipherBytes
     * @return
     */
    public static byte[] decrypt(byte[] keyBytes, byte[] cipherBytes, byte[] iv) throws Exception {
        return decrypt(keySpecForByte(keyBytes), cipherBytes, iv);
    }

    public  static void main(String[] args){
        try {
            byte[] aesKey = DCPAES.randomKey(DCPAESSize.DCPAES256);
            byte[] iv = DCPAES.randomIV();
            String keyString = Base64.getEncoder().encodeToString(aesKey);
            String ivString =  Base64.getEncoder().encodeToString(iv);
            String content = "ooxx";
            byte[] bb = DCPAES.encrypt(keyString,content.getBytes(),iv);
            String bbString =  Base64.getEncoder().encodeToString(bb);
            System.out.println("aes key :"+keyString);
            System.out.println("iv :"+ivString);
            System.out.println("内容："+bbString);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
