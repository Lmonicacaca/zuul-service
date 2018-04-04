package com.mbr.zuul.util.security.rsa;

import javax.crypto.Cipher;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class DCPRSA {

    public enum DCPRSASignAlgorithm {

        RSA1("SHA1WithRSA"),
        RSA2("SHA256WithRSA");

        private String name;

        public String getName() {
            return name;
        }

        DCPRSASignAlgorithm(String name) {
            this.name = name;
        }
    }

    private static final String ALGORITHM = "RSA";

    /**
     * 获取公钥
     *
     * @param publicKeyBytes
     * @return
     * @throws Exception
     */
    public static PublicKey publicKeyForBytes(byte[] publicKeyBytes) throws Exception {
        X509EncodedKeySpec spec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        return keyFactory.generatePublic(spec);
    }

    /**
     * 获取公钥
     *
     * @param publicKeyBase64String
     * @return
     * @throws Exception
     */
    public static PublicKey publicKeyForBase64String(String publicKeyBase64String) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(publicKeyBase64String);
        return publicKeyForBytes(keyBytes);
    }


    /**
     * 通过Bytes获取私钥
     *
     * @param privateKeyBytes
     * @return
     * @throws Exception
     */
    public static PrivateKey privateKeyForBytes(byte[] privateKeyBytes) throws Exception {
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        return keyFactory.generatePrivate(spec);
    }

    /**
     * 通过Base64获取私钥
     *
     * @param privateKeyBase64String
     * @return
     * @throws Exception
     */
    public static PrivateKey privateKeyForBase64String(String privateKeyBase64String) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(privateKeyBase64String);
        return privateKeyForBytes(keyBytes);
    }


    /**
     * 私钥签名,key为Base64
     *
     * @throws Exception
     * @throws Exception
     */
    public static byte[] sign(byte[] content, String privateKeyBaseString, DCPRSASignAlgorithm algorithm) throws Exception {
        PrivateKey priKey = privateKeyForBase64String(privateKeyBaseString);
        return sign(content, priKey, algorithm);
    }

    /**
     * 私钥签名,key为bytes
     *
     * @throws Exception
     * @throws Exception
     */
    public static byte[] sign(byte[] content, byte[] privateKeyBytes, DCPRSASignAlgorithm algorithm) throws Exception {
        PrivateKey priKey = privateKeyForBytes(privateKeyBytes);
        return sign(content, priKey, algorithm);
    }

    /**
     * 私钥签名,key为bytes
     *
     * @throws Exception
     * @throws Exception
     */
    public static byte[] sign(byte[] content, PrivateKey privateKey, DCPRSASignAlgorithm algorithm) throws Exception {
        Signature signature = Signature.getInstance(algorithm.getName());
        signature.initSign(privateKey);
        signature.update(content);
        return signature.sign();
    }


    /**
     * 验证签名
     *
     * @param srcBytes
     * @param signedBytes
     * @param publicKeyBase64String
     * @param algorithm
     * @return
     * @throws Exception
     */
    public static boolean verify(byte[] srcBytes, byte[] signedBytes, String publicKeyBase64String, DCPRSASignAlgorithm algorithm) throws Exception {
        PublicKey pubKey = publicKeyForBase64String(publicKeyBase64String);
        return verify(srcBytes, signedBytes, pubKey, algorithm);
    }


    /**
     * 验证签名
     *
     * @param srcBytes
     * @param signedBytes
     * @param publicKeyBytes
     * @param algorithm
     * @return
     * @throws Exception
     */
    public static boolean verify(byte[] srcBytes, byte[] signedBytes, byte[] publicKeyBytes, DCPRSASignAlgorithm algorithm) throws Exception {
        PublicKey pubKey = publicKeyForBytes(publicKeyBytes);
        return verify(srcBytes, signedBytes, pubKey, algorithm);
    }

    /**
     * 验证签名
     *
     * @param srcBytes
     * @param signedBytes
     * @param publicKey
     * @param algorithm
     * @return
     * @throws Exception
     */
    public static boolean verify(byte[] srcBytes, byte[] signedBytes, PublicKey publicKey, DCPRSASignAlgorithm algorithm) throws Exception {
        Signature signature = Signature.getInstance(algorithm.getName());
        signature.initVerify(publicKey);
        signature.update(srcBytes);
        return signature.verify(signedBytes);
    }

    /**
     * 公钥加密
     *
     * @param content
     * @param base64PublicKeyString
     * @return
     */
    public static byte[] encrypt(byte[] content, String base64PublicKeyString) throws Exception {

        PublicKey pubKey = publicKeyForBase64String(base64PublicKeyString);

        return encrypt(content, pubKey);
    }


    /**
     * 公钥加密
     *
     * @param content
     * @param publicKeyBytes
     * @return
     * @throws Exception
     */
    public static byte[] encrypt(byte[] content, byte[] publicKeyBytes) throws Exception {

        PublicKey pubKey = publicKeyForBytes(publicKeyBytes);

        return encrypt(content, pubKey);
    }

    /**
     * 公钥加密
     *
     * @param content
     * @param publicKey
     * @return
     * @throws Exception
     */
    public static byte[] encrypt(byte[] content, PublicKey publicKey) throws Exception {

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(content);
    }


    /**
     * 私钥解密
     *
     * @param content
     * @param base64PrivateKeyString
     * @return
     */
    public static byte[] decrypt(byte[] content, String base64PrivateKeyString) throws Exception {

        PrivateKey privateKey = privateKeyForBase64String(base64PrivateKeyString);

        return decrypt(content, privateKey);
    }


    /**
     * 私钥解密
     *
     * @param content
     * @param privateKeyBytes
     * @return
     * @throws Exception
     */
    public static byte[] decrypt(byte[] content, byte[] privateKeyBytes) throws Exception {

        PrivateKey privateKey = privateKeyForBytes(privateKeyBytes);

        return decrypt(content, privateKey);
    }


    /**
     * 私钥解密
     *
     * @param content
     * @param privateKey
     * @return
     * @throws Exception
     */
    public static byte[] decrypt(byte[] content, PrivateKey privateKey) throws Exception {

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(content);
    }
}
