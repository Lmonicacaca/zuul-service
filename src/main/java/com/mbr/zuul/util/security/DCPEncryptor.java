package com.mbr.zuul.util.security;


import com.mbr.zuul.util.security.rsa.DCPRSA;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class DCPEncryptor {


    public static boolean verifySignature(String signature, String signType, String key, String iv, String cipher,String partnerPublicKey) {

        String signToken = cipher + key + iv;

        DCPRSA.DCPRSASignAlgorithm signAlgorithm = DCPRSA.DCPRSASignAlgorithm.RSA2;
        if (signType.equals("RSA")) {
            signAlgorithm = DCPRSA.DCPRSASignAlgorithm.RSA1;
        }

        byte[] tokenBytes = signToken.getBytes();
        byte[] signatureBytes = Base64.getDecoder().decode(signature);

        try {
            return DCPRSA.verify(tokenBytes, signatureBytes, partnerPublicKey, signAlgorithm);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    public static byte[] decrypt(String key, String iv, String cipher,String selfPrivateKey) {
        try {

            //1. RSA解开AESKEY
            byte[] keyBytes = Base64.getDecoder().decode(key);
            byte[] aesKeyPlain = DCPRSA.decrypt(keyBytes, selfPrivateKey);

            String aesKeyPlainBase64 = Base64.getEncoder().encodeToString(aesKeyPlain);
//            System.out.println("aesKeyPlainBase64:"+aesKeyPlain.length);
//            System.out.println(aesKeyPlainBase64);

            //2. AES解开cipher
            byte[] ivBytes = Base64.getDecoder().decode(iv);
            byte[] cipherBytes = Base64.getDecoder().decode(cipher);

            return DCPAES.decrypt(aesKeyPlain, cipherBytes, ivBytes);

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }

    }

    /**
     * 加密返回数据
     * @param resBody  数据内容
     * @param partnerPublicKey 商户公钥
     * @param selfPrivateKey 平台私钥
     * @return
     */
    public static Map<String,String> encrypt(String resBody,String partnerPublicKey,String selfPrivateKey) {
        try {
            Map<String,String> map = new HashMap<>();

            byte[] aesKey = DCPAES.randomKey(DCPAES.DCPAESSize.DCPAES256);
//            System.out.println("aes key："+Base64.getEncoder().encodeToString(aesKey));
            // 商户公钥 加密key
            byte[] keyEncrypted = DCPRSA.encrypt(aesKey,partnerPublicKey);
            String keyString = Base64.getEncoder().encodeToString(keyEncrypted);


            //随机iv
            byte[] iv = DCPAES.randomIV();
            String ivString = Base64.getEncoder().encodeToString(iv);

            //加密数据
            byte[] content = DCPAES.encrypt(aesKey,resBody.getBytes(),iv);
            String cipherString = Base64.getEncoder().encodeToString(content);

            //平台私钥签名
            String signString = cipherString+keyString+ivString;
//            System.out.println("签名数据:"+signString);
            byte[] signByte = DCPRSA.sign(signString.getBytes("UTF-8"),selfPrivateKey, DCPRSA.DCPRSASignAlgorithm.RSA2);
            String signature =  Base64.getEncoder().encodeToString(signByte);

            //
            map.put("cipher",cipherString);
            map.put("iv",ivString);
            map.put("signature",signature);
            map.put("key",keyString);
            return map;
        }catch (Exception e){
            e.printStackTrace();
            return null;
        }


    }

}
