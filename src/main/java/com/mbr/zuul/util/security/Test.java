package com.mbr.zuul.util.security;

import com.mbr.zuul.util.security.rsa.DCPRSA;
import com.mbr.zuul.util.security.rsa.DCPRSAKeyPair;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Test {



    public static void main(String[] args){
        String content = "hello world   sdsd";
        String publicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAgUtjUwQCpo5c49BHhU+k+DU5XYA5Ww9+Jeql9J4IzvHoW1ChX2tDiBPwB+pJbrUE9EEw+jEuj9QQIKyQwBbYpyoNh0uJMsGJJRcuIJYEsznw4wzvU/q9U0OcYJfQ9Qu5xQ3dH2yk1CS4v2Ai1v+wngZ1t4hcvKW2Ccbyh4SGxVQHhOCC4JchFHgmsRsytjIzZHxOGMvzhRy2fjHcYMyGNpgqHBMHx4sTtIdrKZ52MQ+A/Vjj3iznXbLNRxz5PtFO/c2iX8l6FbYj6iMXmcUZlUv08g7H1+hLObVHbDBLML/DkwQwpxz26f9S6jgR7XBBD31+tc5Vlede7cYWDLmx9QIDAQAB";
        String privateKey = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQD0IyX1YRQHkDkatQQYxeSKcoOPrMVBPptj7G/3MgIJXphecBY1m9KSHNNuPAsQLG33W/uGyysgBf8TTAfYnhGrhHF8uD5ESTdzbnMaGI00YrGxnVFg7zuY9Qi7elij+dHz0ABLsEqLJi8dPrSGgwDVCFVD6MKm6Q4ZyCQLDKc9cLYdJgz/vBLIkEicpaE/2ep1EKGRkpjRap6YlBUI4Xdfs5JT+cb6Tf0WlGiPYmYIu4e5bqdpiHnT+YidWrX/0If9OSEa9PE30aS8rkuluwozzarS8h8Av297BDaWPtzcMan3VJNn0gz7D1W++6FU+Z9//bJY0LSuAaJhGno+hLwlAgMBAAECggEAAy118ASscxDAfYV/oSbqO5cT+UnBY4ECGsHYDzqaZi7SAuComVgG3Jn9coDbkAFUCRUsZ+u7CvapBEJIE9yy1C2sIHhxbwgY7aqxWtSY+eaS84HdrkpO10XRMEd+Ydv9jJPXfSS1Q6xijpnjVaDc4Ojz2ydraSq9YT6GoZIvlxAa/LJLwS2puxkl/33xBjHKwgsiMmRVohE/EkVG+gZxKVibx7KebvQ0BoiyIUHoC+ndkXLYZcjieZmxecq+5BcIpsKKo8iiexZDEBxSAMkr1ViS1OqzazCcN7tIab+nshKsYvNMElEK5ItLDkwYuIwmA+W0rxDsPTpUeTDdegktgQKBgQD6d3qMK26qguMCjsi8XH6Svsfzds3q1RAnkjFTgP6MSjEqnW/TkCzbxeG7P2o/wRGp63NKw75AGNLj2xuPRq6nN/gcm0lU0vfjPjVdsaHsqEeVX06rw+rTElfd7n4YTmlVlyncYKdf+0pepsbyZP68jFkMxMWjAA+oxggddLDgxQKBgQD5h9+WmHQmUWrrOf+Ng1/b0CBkawpMoI2+TDVdM22ENRc5tASo0EdATmFyNAwqiR2RLjIHhn43yOflcD+L6XlKLG+3RV2ARDcMHITmazE9M8R0cRPktvgz3ZGXq6JSl0aKgnmjouSvhiqGX5aEIKNiMAzpxfsSPAesUb3UQ8dj4QKBgDPvFDz+QHsgmpuMKblM4H3jCyjDaJ0ZwrjBynKLG7zRIXK5pFdU3MhRNqYR1yETEmuOQ6CsB8XYn9nZM9S4jjxkEZE07bal6/p1irE7xNyCZB1n3rMk84sCka+V5RV7JMI3jtmAPRRc0aXgpP3bzSohW9GW93f96kFPlp0s9gQVAoGAajWqNphnf9PR1ZOXMa3EhHRfBT8GYD1Kd8BKSoRUThym6Rm1jgExAq8aDRkYQJaiLiRiiQ9289mg0ujnM29KAAdP+csdlDX01EPjUYw4phs9uG5VEFnM5Y6epNcaPVtEXDpS+hKgkhFiUlWnZE/cGzPmmy54wncosPEOAqZi3SECgYEAx9tmARU4mxmBF9W6DHGaOFcLovOkOkhdoX+NmOh/1ckCW9GbjbG2D0VXgojAF/Ps74sfXR5Prg5JGy/MGcRW1zMWxc88Uc7w6iS+CQJADw45VPsHsQqoGjfzjlE19A+SomlyCoFtXkfDzx63J4h6XZm0+xKEvdvJ0VwdwwgRDig=";//商户私钥

//        try {
//            //DCPRSAKeyPair.savePrivatePemToFile(DCPRSA.privateKeyForBase64String(privateKey),"/Users/luoqb/private.pem");
//
//            PEMParser pr = new PEMParser(new FileReader("/Users/luoqb/rsa_private_key.pem"));
//            PEMKeyPair prKey = (PEMKeyPair) pr.readObject();
//            PrivateKey p = new JcaPEMKeyConverter().getKeyPair(prKey).getPrivate();
//        } catch (Exception e) {
//            e.printStackTrace();
//        }

        try {

            DCPRSAKeyPair.savePublicPemToFile(DCPRSA.publicKeyForBase64String(publicKey),"/Users/luoqb/public.pem");
            DCPRSAKeyPair.savePrivatePemToFile(DCPRSA.privateKeyForBase64String(privateKey),"/Users/luoqb/private.pem");
//            DCPRSAKeyPair.savePublicPemToFile(DCPRSA.publicKeyForBase64String(publicKey),"/Users/luoqb/public.pem");
//            DCPRSAKeyPair.savePrivatePemToFile(DCPRSA.privateKeyForBase64String(privateKey),"/Users/luoqb/private.pem");
//
//
//
//            byte[] c = DCPRSA.encrypt(content.getBytes(), publicKey);
//            String ppstr = Base64.getEncoder().encodeToString(c);
//            System.out.println("加密数据:"+ppstr);
////
////            PEMParser pr = new PEMParser(new FileReader("/Users/luoqb/rsa_private_key.pem"));
////            PEMKeyPair prKey = (PEMKeyPair) pr.readObject();
////            PrivateKey p = new JcaPEMKeyConverter().getKeyPair(prKey).getPrivate();
//            byte[] b = DCPRSA.sign(content.getBytes(),privateKey, DCPRSA.DCPRSASignAlgorithm.RSA2);
//            String sign = Base64.getEncoder().encodeToString(b);
//            System.out.println("签名数据:"+sign);
//            boolean bl = DCPRSA.verify(content.getBytes(),b,publicKey, DCPRSA.DCPRSASignAlgorithm.RSA2);
//            System.out.println("验证签名:"+bl);
//////            byte[] keyBytes = Base64.getDecoder().decode(ppstr);
//////            byte[] d = DCPRSA.decrypt(keyBytes,p);
////            content = "a0WD8hKz461FutRPy5n1whqZM5wmcMEr8WhpK8aqwTbnJGOXrDq6ODh3SC1w0xY5V9YeCqSsvFSj2Oi3PGFzLvQ65fX0s1AF8fb821MD4grHJBhBJHGPjWsE5BN20HNdPI9hwY851+poRSEnOg1Z3g54KrZUi+3/ifuJmSOpzlqb4koBiLk7ocUyjqB5B3N5zL15TM0fzJY2rQeOx1mgmmoD/L8EF85xHZW0CuXBV/BR2b4/+OGDO2uPjdji2HLFpjTI2wsyghnoZ6zI0OA6uUCzyuRTrznT4k4GzNnnSq4N+zM8wiQSig5M/6agdVwZagDHFCXLrLBPkJtoXtN7fg==";
////            byte[] v = Base64.getDecoder().decode(content);
////            byte[] cc = DCPRSA.decrypt(v,DCPRSAKeyPair.readPrivatePkcs8ByPem("/Users/luoqb/rsa_private_key_pkcs8.pem"))   ;
////            System.out.println("解密:"+new String(cc));

        } catch (IOException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }




    }



}
