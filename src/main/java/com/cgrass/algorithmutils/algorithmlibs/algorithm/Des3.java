package com.cgrass.algorithmutils.algorithmlibs.algorithm;

import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;

/**
 * Copyright (c) 2017. cq Inc. All rights reserved.
 * Down, kageyuki anchor. Though not to, the heart yearning.
 *
 * @Describe 3des
 * @Notice
 * @Author chen.
 * @Date 2017/6/17.
 */

public class Des3 {
    static String DES = "DES/ECB/NoPadding";
    private static String TriDes = "DESede/ECB/NoPadding";
    public static final String CHECK_KEY = "0000000000000000";
    //检验pinKey 和 macKey 的CheckValue 的 Key


    public static byte[] str2Bcd(String asc) {
        int len = asc.length();
        int mod = len % 2;

        if (mod != 0) {
            asc = "0" + asc;
            len = asc.length();
        }

        byte abt[] = new byte[len];
        if (len >= 2) {
            len = len / 2;
        }

        byte bbt[] = new byte[len];
        abt = asc.getBytes();
        int j, k;

        for (int p = 0; p < asc.length() / 2; p++) {
            if ((abt[2 * p] >= '0') && (abt[2 * p] <= '9')) {
                j = abt[2 * p] - '0';
            } else if ((abt[2 * p] >= 'a') && (abt[2 * p] <= 'z')) {
                j = abt[2 * p] - 'a' + 0x0a;
            } else {
                j = abt[2 * p] - 'A' + 0x0a;
            }

            if ((abt[2 * p + 1] >= '0') && (abt[2 * p + 1] <= '9')) {
                k = abt[2 * p + 1] - '0';
            } else if ((abt[2 * p + 1] >= 'a') && (abt[2 * p + 1] <= 'z')) {
                k = abt[2 * p + 1] - 'a' + 0x0a;
            } else {
                k = abt[2 * p + 1] - 'A' + 0x0a;
            }

            int a = (j << 4) + k;
            byte b = (byte) a;
            bbt[p] = b;
        }
        return bbt;
    }



    /**
     * 把字节数组转化成16进制的字符串
     *
     * @param src
     * @return
     */
    public static String bytesToHexString(byte[] src) {
        StringBuilder stringBuilder = new StringBuilder();
        if (src == null || src.length <= 0) {
            return null;
        }
        for (int i = 0; i < src.length; i++) {
            int v = src[i] & 0xFF;
            String hv = Integer.toHexString(v);
            if (hv.length() < 2) {
                stringBuilder.append(0);
            }
            stringBuilder.append(hv);
        }
        return stringBuilder.toString();
    }


    /**
     * 3des加密
     *
     * @param key  密钥
     * @param data 明文数据 16进制且长度为16的整数倍
     * @return 密文数据
     */
    public static byte[] Union3DesEncrypt(byte key[], byte data[]) {
        try {
            byte[] k = new byte[24];

            int len = data.length;
            if (data.length % 8 != 0) {
                len = data.length - data.length % 8 + 8;
            }
            byte[] needData = null;
            if (len != 0)
                needData = new byte[len];

            for (int i = 0; i < len; i++) {
                needData[i] = 0x00;
            }
            System.arraycopy(data, 0, needData, 0, data.length);
            if (key.length == 16) {
                System.arraycopy(key, 0, k, 0, key.length);
                System.arraycopy(key, 0, k, 16, 8);
            } else {
                System.arraycopy(key, 0, k, 0, 24);
            }
            KeySpec ks = new DESedeKeySpec(k);
            SecretKeyFactory kf = SecretKeyFactory.getInstance("DESede");
            SecretKey ky = kf.generateSecret(ks);
            Cipher c = Cipher.getInstance(TriDes);
            c.init(Cipher.ENCRYPT_MODE, ky);
            return c.doFinal(needData);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }

    }

    /**
     * 3des解密
     *
     * @param key  密钥
     * @param data 密文数据 16进制且长度为16的整数倍
     * @return 明文数据
     */
    public static byte[] Union3DesDecrypt(byte key[], byte data[]) {
        try {
            byte[] k = new byte[24];

            int len = data.length;
            if (data.length % 8 != 0) {
                len = data.length - data.length % 8 + 8;
            }
            byte[] needData = null;
            if (len != 0)
                needData = new byte[len];

            for (int i = 0; i < len; i++) {
                needData[i] = 0x00;
            }

            System.arraycopy(data, 0, needData, 0, data.length);

            if (key.length == 16) {
                System.arraycopy(key, 0, k, 0, key.length);
                System.arraycopy(key, 0, k, 16, 8);
            } else {
                System.arraycopy(key, 0, k, 0, 24);
            }
            KeySpec ks = new DESedeKeySpec(k);
            SecretKeyFactory kf = SecretKeyFactory.getInstance("DESede");
            SecretKey ky = kf.generateSecret(ks);

            Cipher c = Cipher.getInstance(TriDes);
            c.init(Cipher.DECRYPT_MODE, ky);
            return c.doFinal(needData);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * des解密
     *
     * @param key  密钥
     * @param data 密文数据 16进制且长度为16的整数倍
     * @return 明文数据
     */
    public static byte[] UnionDesDecrypt(byte key[], byte data[]) {

        try {
            KeySpec ks = new DESKeySpec(key);
            SecretKeyFactory kf = SecretKeyFactory.getInstance("DES");
            SecretKey ky = kf.generateSecret(ks);

            Cipher c = Cipher.getInstance(DES);
            c.init(Cipher.DECRYPT_MODE, ky);
            return c.doFinal(data);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * des加密
     *
     * @param key  密钥
     * @param data 明文数据 16进制且长度为16的整数倍
     * @return 密文数据
     */
    public static byte[] UnionDesEncrypt(byte key[], byte data[]) {

        try {
            KeySpec ks = new DESKeySpec(key);
            SecretKeyFactory kf = SecretKeyFactory.getInstance("DES");
            SecretKey ky = kf.generateSecret(ks);

            Cipher c = Cipher.getInstance(DES);
            c.init(Cipher.ENCRYPT_MODE, ky);
            return c.doFinal(data);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * 双倍长密钥的加密
     *
     * @param key  密钥 16字节
     * @param data 数据 8字节
     * @return 加密的数据
     * 双倍长的DES加密过程是先用前半部分进行DES加密，后半部分进行DES解密
     * 再用前半部分进行DES加密
     */
    public static byte[] DoubleDesEncrypt(byte key[], byte data[]) {

        byte[] key1 = new byte[8]; // 前半部分
        byte[] key2 = new byte[8]; // 后半部分

        //对密钥进行截断，分为前半部分和后半部分
        for (int i = 0; i < key.length; i++) {
            if (i < 8) {
                key1[i] = key[i];
            } else {
                key2[i - 8] = key[i];
            }
        }

        byte[] result = new byte[data.length]; // 中间进行转换使用数据

        //1. 前半部分对数据进行加密
        result = UnionDesEncrypt(key1, data);

        //2. 后半部分对数据进行解密
        result = UnionDesDecrypt(key2, result);

        //3. 前半部分对数据进行加密
        result = UnionDesEncrypt(key1, result);

        return result;
    }


    /**
     * 双倍长密钥的解密
     *
     * @param key  密钥 16字节
     * @param data 数据 8字节
     * @return 加密的数据
     * 双倍长的DES加密过程是先用前半部分进行DES加密，后半部分进行DES解密
     * 再用前半部分进行DES加密
     */
    public static byte[] doubleDesDecrypt(byte[] key, byte[] data) {
        byte[] key1 = new byte[8];
        byte[] key2 = new byte[8];


        for (int i = 0; i < key.length; i++) {
            if (i < 8) {
                key1[i] = key[i];
            } else {
                key2[(i - 8)] = key[i];
            }
        }
        byte[] result = new byte[data.length];
        result = UnionDesDecrypt(key1, data);
        result = UnionDesEncrypt(key2, result);
        result = UnionDesDecrypt(key1, result);
        return result;
    }

    /**
     * 对byte数组进行取反
     *
     * @param args
     * @return
     */
    public static byte[] getByteNot(byte[] args) {
        byte[] result = new byte[args.length];

        for (int i = 0; i < args.length; i++) {
            result[i] = (byte) ~args[i];
        }
        return result;
    }

    /**
     * 3DES的分散密钥，双倍长密钥
     *
     * @param key    双倍长密钥16字节，32字符
     * @param factor 分散因子，8字节，16字符
     * @return 返回的是密钥 16字节，32字符
     * 过程： 1. 用双倍长密钥对传入的分散因子进行加密
     * 2. 对分散因子进行取反
     * 3. 用双倍长密钥对取反后的分散因子进行加密
     * 4. 将2次加密的数据进行拼接返回
     */
    public static String GenRandomKey(String key, String factor) {
        byte[] keyByte = str2Bcd(key);
        byte[] factorByte = str2Bcd(factor);

        //1 . 使用双倍长密钥对传入的分散因子进行加密
        byte[] temp1 = DoubleDesEncrypt(keyByte, factorByte);
        //2 . 对分散因子进行取反操作
        byte[] factorByteTemp = getByteNot(factorByte);
        //3 . 使用双倍长密钥对取反后的分散因子进行加密
        byte[] temp2 = DoubleDesEncrypt(keyByte, factorByteTemp);

        String result = "";
        //4 . 将2次加密的数据进行拼接返回
        result = bytesToHexString(temp1) + bytesToHexString(temp2);
        return result;
    }

    /**
     * 数据解密
     *
     * @param key  密钥 支持单倍和多倍密钥
     * @param data 密文数据 16进制且长度为16的整数倍
     * @return 明文数据
     */
    public static String UnionDecryptData(String key, String data) {
        if ((key.length() != 16) && (key.length() != 32) && (key.length() != 48)) {
            return (null);
        }
        if (data.length() % 16 != 0) {
            return "";
        }
        int lenOfKey = 0;
        lenOfKey = key.length();
        String strEncrypt = "";
        byte sourData[] = str2Bcd(data);
        switch (lenOfKey) {
            case 16:
                byte deskey8[] = str2Bcd(key);
                byte encrypt[] = UnionDesDecrypt(deskey8, sourData);
                strEncrypt = bytesToHexString(encrypt);
                break;
            case 32:
            case 48:
                String newkey1 = "";
                if (lenOfKey == 32) {
                    String newkey = key.substring(0, 16);
                    newkey1 = key + newkey;
                } else {
                    newkey1 = key;
                }
                byte deskey24[] = str2Bcd(newkey1);
                byte desEncrypt[] = Union3DesDecrypt(deskey24, sourData);
                strEncrypt = bytesToHexString(desEncrypt);
        }
        return strEncrypt;
    }

    /**
     * 数据加密
     *
     * @param key  密钥 支持单倍和多倍密钥
     * @param data 密文数据 16进制且长度为16的整数倍
     * @return 明文数据
     */
    public static String UnionEncryptData(String key, String data) {
        if ((key.length() != 16) && (key.length() != 32) && (key.length() != 48)) {
            return (null);
        }
        if (data.length() % 16 != 0) {
            return "";
        }
        int lenOfKey = 0;
        lenOfKey = key.length();
        String strEncrypt = "";
        byte sourData[] = str2Bcd(data);
        switch (lenOfKey) {
            case 16:
                byte deskey8[] = str2Bcd(key);
                byte encrypt[] = UnionDesEncrypt(deskey8, sourData);
                strEncrypt = bytesToHexString(encrypt).toUpperCase();
                break;
            case 32:
            case 48:
                String newkey1 = "";
                if (lenOfKey == 32) {
                    String newkey = key.substring(0, 16);
                    newkey1 = key + newkey;
                } else {
                    newkey1 = key;
                }
                byte deskey24[] = str2Bcd(newkey1);
                byte desEncrypt[] = Union3DesEncrypt(deskey24, sourData);
                strEncrypt = bytesToHexString(desEncrypt).toUpperCase();
        }
        return strEncrypt;
    }

    /**
     * 解密pinkey
     *
     * @param zmk
     * @param pinKey 密文
     * @return
     */
    public static String pinKeyDecrypt(String zmk, String pinKey) {

        byte[] tmkByte = str2Bcd(zmk);
        byte[] pinkByte = str2Bcd(pinKey);


        byte[] MwPinkByte = Union3DesDecrypt(tmkByte, pinkByte);

        String pinKeyResult = bytesToHexString(MwPinkByte).toUpperCase();
        return pinKeyResult;
    }

    public static String UnionDecrypt(String T2Len) {
        int t2len = Integer.parseInt(T2Len);
        while (t2len % 16 != 0) {
            t2len++;
        }
        String resultHex = String.valueOf(t2len);
        return resultHex;
    }

    public static String trackInf(String trackInf, String TLen) {
        int TLen1 = Integer.parseInt(TLen);
        return trackInf.substring(0, TLen1);
    }

    /**
     * 获取明文 pinKey
     *
     * @param s
     * @return pinKey
     */
    public static String getPinKey(String s, String zmk) {
        String pinKey = s.substring(0, 32);
        String pinKey_1 = UnionDecryptData(zmk, pinKey);
        String checkValue = s.substring(32, 40);
        String checkValue2 = UnionEncryptData(pinKey_1, CHECK_KEY).substring(0, 8);
        if (checkValue.equals(checkValue2)) {
            return pinKey_1;
        }
        return "";
    }

    /**
     * @param s
     * @return
     */
    public static String getMacKey(String s, String zmk) {
        String macKey = s.substring(40, 56);
        String macKey_1 = UnionDecryptData(zmk, macKey);
        String checkValue = s.substring(72, 80);
        String checkValue2 = UnionEncryptData(macKey_1, CHECK_KEY).substring(0, 8);
        if (checkValue.equals(checkValue2)) {
            return macKey_1;
        }
        return "";
    }
}
