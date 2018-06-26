package com.mbr.zuul.util.security;


import java.io.UnsupportedEncodingException;

public class Test {



    public static void main(String[] args){
        String key = "SB5o9jMbsEKHCeD8sw1HelXMIPaYUVxQMvXm6a/rIPgRsEqfGBCxBiWDHhWFh1KdaaOG+li1aiaTM3/yEOAJwPUPSixFuBzsP1xJsWt6AI8Yu5T/AtO3MBJI/ff9wgeDhQGbo58hslPJYDu8JEC6WbF+CybqgaJC7rrFTEAinns8ZXT7RDE5sx//nQ5Z/Iz2TD5hVMjRb3dOiqAhcRnkCw03w3/6VyichKZbR1F1EJjMFAPHk8kmyAWpkMNCceaqfmGQW2vNeVR99YyO3jNORDTjM4ehVhq70rjGLduCkAhxfh6VziUAySWYQjoV+mukR1egUo8jogPe2VmQKy/JEg==";

        String iv = "NmEwYjYzOWFjOTQ4ZmMxOQ==";
        String cipher = "kqe2PoGVmr11IzZcBCOeCrwSU8lizXzwLIWI6UfQrxmx+VxvLpvO0z2qXQ6Ltt7IjeqawHQIAmTu6FpDaZLy1RIXPOvU2pbWRIm9MYUdIpmG/HHGuk1bJqUqPUKgOZIO0IJKz10PtmOpm7os0GZnJOVnHHo2ojxvtL0ze6GDrDw=";
        String selfPrivateKey = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCJH8neIGffAfrdlmrKYUK8BjkIZ7fh6194HIc6yWV5a6MMsA0gN6jabB1JQCxkJN3UdzUZUJGCxZflC+PE0HP6UmUHmOtwsxKPwl4cHVQ4vtJmp3xpmGPC0R79FJ2kuqEc1RQbWFI42T7EQI2eg4Rz+dktsp1lJvRpjHRw9+2nk2L38Cg7xPZsRrbnWEGl1g1ydDdXIAgPs5gNAM2oqgcMkViPiltnU6WtKQs5Z+9xGbt6ef38lM1s9mi44bQNRwV9ySv9G92/jrD9Ve7yQrpiVyS+mUwk5uGvC2PSzM8pfhhvSD5Y546pzfrQPnsizZoo4uh/rx/wiCpRW3RsZ6MzAgMBAAECggEBAIETvlds07oVyArsO6wz77jEds1VrL9qa9zJpfYNfIrWao5X7pMkMbshyFOap+7A0VvdtssUj1S1IW2HSqmKu5GoG9gR95aHynIuuZ3ncc9UuQPOpwtTWp0Zcv0yec6Fq4FThnDTK9q9jRr51RWgoX72cpxUpVqBV9M/VqC8kSaK7rviMT/9n+woRLmprefuayqGifvZfK85ZX0u6gZhIK4CjbpLnT96HR8hzMH9fQxYr7NfNHxmLNqhXrdgJL5vH8vOcgb5YRhl6XV8/zArqyBTGmyz3PS2XE65PXi4bJ+uH8SX2iH5vPiOyxHo0sOXfqqa6uPFUnUGEC3OYA0tCtkCgYEA2uew3Tht+RNoxBGeSLQ7vodX0uZC1RcYZb8INC+87HGOKx1FjuqygG7SuBPf4HhW50B/gjnKnJ1DVIAttNOeRZ0TtbH72hEwzrHPugNu2yUmmDiSzWd2e9mWUNDE6xMJ9kCzJjI/v0l+xdNy+V77FIGF8mK4Sw4MncLta3ki9d0CgYEAoFxdoYrIZ+RWjEzEgqZEe8XcMsRmZh0HJwozUBzNSa72mMATD+xnmEKWOxiCNyzCELVUPxoeJ6l5v88fXb2pgPoIle/7sy+Wu0LahaG33le8Ame/dBGV7G7/pRP5gKKenL60GzXGAOwtLk2zzhnxxtMZQ9ncyGrivTh5eN/ClE8CgYBhqdLfr8howr8QEugyea7Z/1owbqjMl0Q8SLFpTw8T0knidGnPLGi9IjSDCeLtK+NhwwXgXNZHb2ZVseYyceOAHWdoveKmVNsYrH4H+HYh8X45lavxVkKnWNlWbv4b/t+H7S/AT9TfC/QyYHdASJ7udCcFkAO3AKqiTBBOzbnKRQKBgQCH0tQHYHov7OoVeWw0UMnOoB7K7SjiMpH9Uhl2MH78evIpHP7ITO7NuxBty2t3ejSBXGSX8fI6m8QgXzls95jbQmwFOzfQZG1h/NUDvJ709xCqZN93WvHGSZnEY2+/sX1wu+Hm7hvgaio2ft/doIH1apWKr7veERItPOk+JSA05wKBgB1mqNht9AHZdOXaGksnEisHu7HYIx/ILkNtOnELV2iEXPyqQd0tip+CF8abAnvK5ohriYRQtVFpf+96MJY2NTqJVGNLnyZFoGe7HhuaHEBaV15uxoR9OgoiZV9mbfig/9y5EAh/y/zhCuKWO++aCutT317vbokLmGpbfE77nAzi";
        byte[] b = DCPEncryptor.decrypt(key,iv,cipher,selfPrivateKey);
        String bodyString = null;
        try {
            bodyString = new String(b,"UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        System.out.println(bodyString);
    }



}
