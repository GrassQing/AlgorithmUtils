package com.cgrass.algorithmutils.algorithmlibs.algorithm;

import java.security.MessageDigest;

public class Md5 {
    public static byte[] encryptMD5(byte[] data) throws Exception {
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        md5.update(data);
        return md5.digest();

    }
}
