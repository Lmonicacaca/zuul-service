package com.mbr.zuul.util;


import com.alibaba.fastjson.JSONObject;

import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class SecurityUtil {

    public static void main(String args[]){
       // Long time = new Date().getTime();

        /*try {
            RsaUtil.RsaKeyPair ra = RsaUtil.generaterKeyPair();
            System.out.println(ra.getPrivateKey());
            System.out.println(ra.publicKey);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }*/


        String partner_no = "10000000000000";

        String signType = "RSA2";
        String charset= "UTF-8";
        String timestamp = "1522547768902";
        System.out.println(timestamp);
        String aesKey = "iLrc3ty7xhPgztlOVy+CuRhyz5ajg8EVATD36vUVmIQ=";
       // String pubKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAgUtjUwQCpo5c49BHhU+k+DU5XYA5Ww9+Jeql9J4IzvHoW1ChX2tDiBPwB+pJbrUE9EEw+jEuj9QQIKyQwBbYpyoNh0uJMsGJJRcuIJYEsznw4wzvU/" +
        //        "q9U0OcYJfQ9Qu5xQ3dH2yk1CS4v2Ai1v+wngZ1t4hcvKW2Ccbyh4SGxVQHhOCC4JchFHgmsRsytjIzZHxOGMvzhRy2fjHcYMyGNpgqHBMHx4sTtIdrKZ52MQ+A/Vjj3iznXbLNRxz5PtFO/" +
         //       "c2iX8l6FbYj6iMXmcUZlUv08g7H1+hLObVHbDBLML/" +
          //      "DkwQwpxz26f9S6jgR7XBBD31+tc5Vlede7cYWDLmx9QIDAQAB";
        String priKey = "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCBS2NTBAKmjlzj0EeFT6T4NTldgDlbD34l6qX0ngjO8ehbUKFfa0OIE/AH6klutQT0QTD6MS6P1BAgrJDAFtinKg2HS4kywYklFy4glgSzOfDjDO9T+r1TQ5xgl9D1C7nFDd0fbKTUJLi/YCLW/7CeBnW3iFy8pbYJxvKHhIbFVAeE4ILglyEUeCaxGzK2MjNkfE4Yy/OFHLZ+MdxgzIY2mCocEwfHixO0h2spnnYxD4D9WOPeLOddss1HHPk+0U79zaJfyXoVtiPqIxeZxRmVS/TyDsfX6Es5tUdsMEswv8OTBDCnHPbp/1LqOBHtcEEPfX61zlWV517txhYMubH1AgMBAAECggEAJp7WNF3mTMoJhSMZugBoTpvXXs6GU2T1UW4d1EvAZdBsj5ouGcp4iZUrBbI97Qu1RyCR+KnoNp4pkxj4w+gPHx+4msk9WiPlS2b5KFKnZMHR6oBanMMw+kYf19qBWDEAdJQHkPNq6NNvO/sDbSVDJHDZiND6on79OT5sA37aouZgYC4yfpkKWM7MhREgmEzpk5xbRgIR48/Rp/Dv67N92VLwy/Zim38ED/Hic9xCSdnQSwDKyZ36uUumKCC2bEQlQA5f0koIpPc1TO6+U+278GCT839GQ0Ni2ZxfB1u33eHH8aX2NUiM0U9rlXlviB/o/RpcVhf4D/zlXif8lS/aAQKBgQDYl7JjBHvPGJn70SG3Rg1PvS3XRpzC9hnynAdn1w1Z803HwBfQ54SuQu/FaaGpHMqwEaVBtiAvU77+MqiIs48rsrTPN209M6F397Rf3zm9Nnt7YkwRllPbGJgYleUPbzAYnD5gH0Cf5mgP8kfxCeSujhyCAq8g00Mdlm4y8k4YMQKBgQCY0ZRn4Po/psxq2bptnB3ALmUuSjc/INNoCDZ885NRVtgCVZw9cQERB9m8ECREKLhkDhtWsgfZhq2eEb/jWW04edBTg+BvvZIu+qT4xB25FiaEzpgBO+iuGjgqf70sJaizLxWj0QE+FzQf24VaTb1bGNJfxFPaXvsEn3Wq2xGJBQKBgFsrL1lij8LSdi57DxgYEo5X8S3GeUHPWYi3iJ569RHByiGkh+HVMhIv9sE//14x0ldedhM82DtTovdY13wDKOaZ6GW4zPCQBQ18ZJ5eVe2BO2TqMV7NyipVJeBjZ/GhObuCOPc48HjeATuFHiclpO6cvv8ypgjJJF0V7vje6WRhAoGAUrTSuenD5mESrx2JTTs5ysIRVp0qC0trvxj6zGNTLqlunMzSk1oudpYmHCcsSYs0SEpuN1yA7RR7sFnw3U2P1AnxWtG7zR3vGOfkExKo93vqeuQI1lojEt7z2ORrcJItHFT2REOghYcvWbKIGJiMS9pCOTxbGYtgFV9r4n1PnzUCgYBgnO51b7UkJasj7SaRRskCY+QWqB8kiPiJTsipS9sGCPBojtJmXzMC/+n4cvmXmymRm+G9hcFYEZbI1hm6v1SQkA2A4VMQ3oTEgNwPydgBe/MguBjtlMaytKE8jrG30FjtD+bJo5DrHhs6qG6xkc81dQuVzVtWURVDUrDErW8N9g==";
        Map<String,Object> mapContent = new HashMap<>();
        mapContent.put("aa","bb");
        try {
            String body = JSONObject.toJSONString(mapContent);
            String mwAes = AesUtil.encrypt(body,aesKey);
            String key = RsaUtil.encrypt(aesKey,RsaUtil.getPrivateKey(priKey),charset);

            Map<String,String> mapSign = new HashMap<>();
            mapSign.put("partner_no",partner_no);
            mapSign.put("sign_type",signType);
            mapSign.put("charset",charset);
            mapSign.put("timestamp",timestamp);
            mapSign.put("body",mwAes);


            String signString = CommonsUtil.putPairsSequenceAndTogether(mapSign);
            //String signBase64 = org.apache.commons.codec.binary.Base64.encodeBase64String(signString.getBytes());

            String sign = RsaUtil.sign(signString,priKey,true,charset);

            Map<String,Object> mapC = new HashMap<>();
            mapC.put("data",mwAes);
            mapC.put("key",key);

            Map headerMap = new HashMap();
            headerMap.put("partner_no",partner_no);
            headerMap.put("sign",sign);
            headerMap.put("sign_type",signType);
            headerMap.put("charset",charset);
            headerMap.put("timestamp",timestamp);

            String headerBase64 = org.apache.commons.codec.binary.Base64.encodeBase64String(JSONObject.toJSONBytes(headerMap));

            System.out.println("header:"+headerBase64);
            System.out.println("body:"+JSONObject.toJSONString(mapC));


        } catch (Exception e) {
            e.printStackTrace();
        }


    }


    /**
     * 消息摘要
     * @author
     *
     */
    public static class MessageDigestUtil {

        public static byte[] digest(String content, boolean isMd5) throws Exception {
            MessageDigest messageDigest = null;
            String algorithm = isMd5 ? "MD5" : "SHA";
            messageDigest = MessageDigest.getInstance(algorithm);
            return messageDigest.digest(content.getBytes());
        }

        public static byte[] digest1(String content, boolean isMd5) throws Exception {
            MessageDigest messageDigest = null;
            String algorithm = isMd5 ? "MD5" : "SHA";
            messageDigest = MessageDigest.getInstance(algorithm);
            messageDigest.update(content.getBytes());
            return messageDigest.digest();
        }
    }

    /**
     * 对称加密算法
     * @author
     *
     */
    public static class AesUtil {
        private static final String ALGORITHM = "AES";
        private static final String DEFAULT_CHARSET = "UTF-8";
        private static final int KEY_SIZE = 256;

        /**
         * 生成秘钥
         * @return
         * @throws NoSuchAlgorithmException
         */
        public static byte[] generaterKey() throws NoSuchAlgorithmException {
            KeyGenerator keygen = KeyGenerator.getInstance(ALGORITHM);
            keygen.init(KEY_SIZE, new SecureRandom()); // 16 字节 == 128 bit
            //            keygen.init(128, new SecureRandom(seedStr.getBytes())); // 随机因子一样，生成出来的秘钥会一样
            SecretKey secretKey = keygen.generateKey();
            return secretKey.getEncoded();
        }

        /**
         */
        public static SecretKeySpec getSecretKeySpec(String secretKeyStr){
            byte[] secretKey = Base64.getDecoder().decode(secretKeyStr);
            System.out.println(secretKey.length);
            return new SecretKeySpec(secretKey, ALGORITHM);
        }
        /**
         */
        public static SecretKeySpec getSecretKeySpec(byte[] secretKeyStr){
            //byte[] secretKey = Base64.getDecoder().decode(secretKeyStr);
            //System.out.println(secretKey.length);
            return new SecretKeySpec(secretKeyStr, ALGORITHM);
        }

        /**
         * 加密
         */
        public static String encrypt(String content,byte[] secretKey) throws Exception{
            Key key = getSecretKeySpec(secretKey);
            Cipher cipher = Cipher.getInstance(ALGORITHM);// 创建密码器
            cipher.init(Cipher.ENCRYPT_MODE, key);// 初始化
            byte[] result = cipher.doFinal(content.getBytes(DEFAULT_CHARSET));
            return Base64.getEncoder().encodeToString(result);
        }

        /**
         * 加密
         */
        public static String encrypt(String content,String secretKey) throws Exception{
            Key key = getSecretKeySpec(secretKey);
            Cipher cipher = Cipher.getInstance(ALGORITHM);// 创建密码器
            cipher.init(Cipher.ENCRYPT_MODE, key);// 初始化
            byte[] result = cipher.doFinal(content.getBytes(DEFAULT_CHARSET));
            return Base64.getEncoder().encodeToString(result);
        }


        /**
         * 解密
         */
        public static String decrypt(String content, String secretKey) throws Exception{
            Key key = getSecretKeySpec(secretKey);
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] result = cipher.doFinal(Base64.getDecoder().decode(content));
            return new String(result);
        }

        /**
         * 解密
         */
        public static String decrypt(String content, byte[] secretKey) throws Exception{
            Key key = getSecretKeySpec(secretKey);
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] result = cipher.doFinal(Base64.getDecoder().decode(content));
            return new String(result);
        }
    }

    /**
     * 非对称加密算法
     * @author
     *
     */
    public static class RsaUtil {

        public static class RsaKeyPair {
            private String publicKey ="";
            private String privateKey ="";

            public RsaKeyPair(String publicKey, String privateKey) {
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
        }

        private static final String ALGORITHM = "RSA";
        private static final String ALGORITHMS_SHA1WithRSA = "SHA1WithRSA";
        private static final String ALGORITHMS_SHA256WithRSA = "SHA256WithRSA";
       // private static final String DEFAULT_CHARSET = "UTF-8";
        private static final int KEY_SIZE=2048;
        private static String getAlgorithms(boolean isRsa2) {
            return isRsa2 ? ALGORITHMS_SHA256WithRSA : ALGORITHMS_SHA1WithRSA;
        }

        /**
         * 生成秘钥对
         * @return
         * @throws NoSuchAlgorithmException
         */
        public static RsaKeyPair generaterKeyPair() throws NoSuchAlgorithmException{
            KeyPairGenerator keygen = KeyPairGenerator.getInstance(ALGORITHM);
            SecureRandom random = new SecureRandom();
            //            SecureRandom random = new SecureRandom(seedStr.getBytes()); // 随机因子一样，生成出来的秘钥会一样
            // 512位已被破解，用1024位,最好用2048位
            keygen.initialize(KEY_SIZE, random);
            // 生成密钥对
            KeyPair keyPair = keygen.generateKeyPair();
            RSAPrivateKey privateKey = (RSAPrivateKey)keyPair.getPrivate();
            RSAPublicKey publicKey = (RSAPublicKey)keyPair.getPublic();
            String privateKeyStr = Base64.getEncoder().encodeToString(privateKey.getEncoded());
            String publicKeyStr = Base64.getEncoder().encodeToString(publicKey.getEncoded());
            return new RsaKeyPair(publicKeyStr,privateKeyStr);
        }

        /**
         * 获取公钥
         * @param publicKey
         * @return
         * @throws Exception
         */
        public static PublicKey getPublicKey(String publicKey) throws Exception{
            byte[] keyBytes = Base64.getDecoder().decode(publicKey);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
            return keyFactory.generatePublic(spec);
        }

        /**
         * 获取私钥
         * @param privateKey
         * @return
         * @throws NoSuchAlgorithmException
         * @throws InvalidKeySpecException
         * @throws Exception
         */
        public static PrivateKey getPrivateKey(String privateKey) throws Exception{
            byte[] keyBytes = Base64.getDecoder().decode(privateKey);
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
            PrivateKey pk = keyFactory.generatePrivate(spec);
            return pk;
        }

        /**
         * 要私钥签名
         * @throws InvalidKeySpecException
         * @throws Exception
         */
        public static String sign(String content, String privateKey, boolean isRsa2,String charset) throws Exception {
            PrivateKey priKey = getPrivateKey(privateKey);
            java.security.Signature signature = java.security.Signature.getInstance(getAlgorithms(isRsa2));
            signature.initSign(priKey);
            signature.update(content.getBytes(charset));
            byte[] signed = signature.sign();
            return Base64.getEncoder().encodeToString(signed);
        }

        /**
         * 要公钥签名
         */
        public static boolean verify(String content,String sign,String publicKey,boolean isRsa2,String charset) throws Exception {
            PublicKey pubKey = getPublicKey(publicKey);
            java.security.Signature signature = java.security.Signature.getInstance(getAlgorithms(isRsa2));
            signature.initVerify(pubKey);
            signature.update(content.getBytes(charset));
            return signature.verify(Base64.getDecoder().decode(sign));
        }

        /**
         * 加密
         * @param content
         * @param pubOrPrikey
         * @return
         */
        public static String encrypt(String content, Key pubOrPrikey,String charset) throws Exception{
            Cipher cipher = null;
            cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, pubOrPrikey);
            byte[] result = cipher.doFinal(content.getBytes(charset));
            return Base64.getEncoder().encodeToString(result);
        }

        /**
         * 解密
         * @param content
         * @param pubOrPrikey
         * @return
         */
        public static String decrypt(String content, Key pubOrPrikey) throws Exception {
            Cipher cipher = null;
            cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, pubOrPrikey);
            byte[] result = cipher.doFinal(Base64.getDecoder().decode(content));
            return new String(result);
        }
    }

}
