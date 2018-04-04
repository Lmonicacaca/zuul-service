package com.mbr.zuul.util;


import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.Base64;
import java.util.Random;

/**
 * 对称加密算法
 * @author
 *
 */
public class AesUtil {

    public static final String KEY_ALGORITHM = "AES";
    public static final String ECB_CIPHER_ALGORITHM = "AES/ECB/PKCS5Padding";
    public static final String CBC_CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";
    public static final int KEY_SIZE = 256;

    /**
     * 使用ECB模式进行加密。 加密过程三步走： 1. 传入算法，实例化一个加解密器 2. 传入加密模式和密钥，初始化一个加密器 3.
     * 调用doFinal方法加密
     *
     * @param plainText
     * @return
     */
    public static byte[] AesEcbEncode(byte[] plainText, SecretKey key) {

        try {

            Cipher cipher = Cipher.getInstance(ECB_CIPHER_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(plainText);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException
                | InvalidKeyException | IllegalBlockSizeException
                | BadPaddingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 使用ECB解密，三步走，不说了
     *
     * @param decodedText
     * @param key
     * @return
     */
    public static String AesEcbDecode(byte[] decodedText, SecretKey key) {
        try {
            Cipher cipher = Cipher.getInstance(ECB_CIPHER_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, key);
            return new String(cipher.doFinal(decodedText));
        } catch (NoSuchAlgorithmException | NoSuchPaddingException
                | InvalidKeyException | IllegalBlockSizeException
                | BadPaddingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return null;

    }

    /**
     * CBC加密，三步走，只是在初始化时加了一个初始变量
     *
     * @param plainText
     * @param key
     * @param IVParameter
     * @return
     */
    public static byte[] AesCbcEncode(byte[] plainText, SecretKey key,
                                      byte[] IVParameter) {
        try {
            IvParameterSpec ivParameterSpec = new IvParameterSpec(IVParameter);

            Cipher cipher = Cipher.getInstance(CBC_CIPHER_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);
            return cipher.doFinal(plainText);

        } catch (NoSuchAlgorithmException | NoSuchPaddingException
                | InvalidKeyException | InvalidAlgorithmParameterException
                | IllegalBlockSizeException | BadPaddingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return null;
    }

    /**
     * CBC 解密
     *
     * @param decodedText
     * @param key
     * @param IVParameter
     * @return
     */
    public static String AesCbcDecode(byte[] decodedText, SecretKey key,
                                      byte[] IVParameter) {
        IvParameterSpec ivParameterSpec = new IvParameterSpec(IVParameter);

        try {
            Cipher cipher = Cipher.getInstance(CBC_CIPHER_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);
            return new String(cipher.doFinal(decodedText));
        } catch (NoSuchAlgorithmException | NoSuchPaddingException
                | InvalidKeyException | InvalidAlgorithmParameterException
                | IllegalBlockSizeException | BadPaddingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        return null;

    }

    /**
     * 1.创建一个KeyGenerator 2.调用KeyGenerator.generateKey方法
     *
     *
     * @return
     */
    public static byte[] generateAESSecretKey() {
        KeyGenerator keyGenerator;
        try {
            keyGenerator = KeyGenerator.getInstance(KEY_ALGORITHM);
            keyGenerator.init(KEY_SIZE,new SecureRandom());
            SecretKey secretKey = keyGenerator.generateKey();
            return secretKey.getEncoded();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 还原密钥
     *
     * @param secretBytes
     * @return
     */
    public static SecretKey restoreSecretKey(byte[] secretBytes) {
        SecretKey secretKey = new SecretKeySpec(secretBytes, KEY_ALGORITHM);
        return secretKey;
    }

    public static byte[] generateAESSecretIv(){
        StringBuffer stringBuffer = new StringBuffer();

        for (int i = 0;i<16;i++){
            stringBuffer.append(Integer.toHexString(new Random().nextInt(16)));
        }

        String  s = stringBuffer.toString();

        return stringBuffer.toString().getBytes();
    }


    public static void main(String[] arg) {
        System.out.println(generateAESSecretIv().length);

        /*String key = "vh/EgfXObODkPrnw9H7rm6kW963nopihCZQPtFi2Xo0=";
        String iv = "AQIDBAUGBwgJCgsMDQ4PEA==";
        byte[] secretBytes = org.apache.commons.codec.binary.Base64.decodeBase64(key);
        byte[] ivByte = org.apache.commons.codec.binary.Base64.decodeBase64(iv);
        byte[] IVPARAMETERS = generateAESSecretIv();
        ///System.out.println("iv: "+org.apache.commons.codec.binary.Base64.encodeBase64String(IVPARAMETERS));

        //System.out.println("key : "+org.apache.commons.codec.binary.Base64.encodeBase64String(secretBytes));
        SecretKey secretKey = restoreSecretKey(secretBytes);
        //byte[]  encodedText = AesCbcEncode("如果安装了JRE，将两个jar文件放到%JRE_HOME%\\lib\\security下覆盖原来文件，记得先备份。".getBytes(), secretKey, IVPARAMETERS);


       // System.out.println("密文 " + org.apache.commons.codec.binary.Base64.encodeBase64String(encodedText));
        String text = "02LODy+O3FSXEBN84DqudDCgvrySTArP4NaDZs2WWqleK+z+d3dNqOQrKijALeDj";
        byte[] t = org.apache.commons.codec.binary.Base64.decodeBase64(text);

        String decode =  AesCbcDecode(t,secretKey,ivByte);


        System.out.println("解密 " + decode);*/
    }
}
