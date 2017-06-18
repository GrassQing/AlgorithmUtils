package com.cgrass.algorithmutils.algorithmlibs.tools;

public class Convert {
	
	public static String bcd2Str(byte[] b) {
		char[] HEX_DIGITS = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
		StringBuilder sb = new StringBuilder(b.length * 2);
		for (int i = 0; i < b.length; ++i) {
			sb.append(HEX_DIGITS[((b[i] & 0xF0) >>> 4)]);
			sb.append(HEX_DIGITS[(b[i] & 0xF)]);
		}
		return sb.toString();
	}

	public static byte[] str2Bcd(String asc) {
		int len = asc.length();
		int mod = len % 2;
		if (mod != 0) {
			asc = "0" + asc;
			len = asc.length();
		}
		byte[] abt = new byte[len];
		if (len >= 2)
			len /= 2;
		byte[] bbt = new byte[len];
		abt = asc.getBytes();
		for (int p = 0; p < asc.length() / 2; ++p) {
			int j;
			int k;
			if ((abt[(2 * p)] >= 97) && (abt[(2 * p)] <= 122))
				j = abt[(2 * p)] - 97 + 10;
			else if ((abt[(2 * p)] >= 65) && (abt[(2 * p)] <= 90))
				j = abt[(2 * p)] - 65 + 10;
			else {
				j = abt[(2 * p)] - 48;
			}
			if ((abt[(2 * p + 1)] >= 97) && (abt[(2 * p + 1)] <= 122))
				k = abt[(2 * p + 1)] - 97 + 10;
			else if ((abt[(2 * p + 1)] >= 65) && (abt[(2 * p + 1)] <= 90))
				k = abt[(2 * p + 1)] - 65 + 10;
			else {
				k = abt[(2 * p + 1)] - 48;
			}
			int a = (j << 4) + k;
			byte b = (byte) a;
			bbt[p] = b;
		}
		return bbt;
	}

	public static void int2ByteArray(int i, byte[] to, int offset) {
		to[offset] = (byte) (i >>> 24 & 0xFF);
		to[(offset + 1)] = (byte) (i >>> 16 & 0xFF);
		to[(offset + 2)] = (byte) (i >>> 8 & 0xFF);
		to[(offset + 3)] = (byte) (i & 0xFF);
	}

	public static void int2ByteArrayLittleEndian(int i, byte[] to, int offset) {
		to[offset] = (byte) (i & 0xFF);
		to[(offset + 1)] = (byte) (i >>> 8 & 0xFF);
		to[(offset + 2)] = (byte) (i >>> 16 & 0xFF);
		to[(offset + 3)] = (byte) (i >>> 24 & 0xFF);
	}

	public static void short2ByteArray(short s, byte[] to, int offset) {
		to[offset] = (byte) (s >>> 8 & 0xFF);
		to[(offset + 1)] = (byte) (s & 0xFF);
	}

	public static void short2ByteArrayLittleEndian(short s, byte[] to, int offset) {
		to[offset] = (byte) (s & 0xFF);
		to[(offset + 1)] = (byte) (s >>> 8 & 0xFF);
	}

	public static int byteArray2Int(byte[] from, int offset) {
		return (from[offset] << 24 & 0xFF000000 | from[(offset + 1)] << 16 & 0xFF0000 | from[(offset + 2)] << 8 & 0xFF00 | from[(offset + 3)] & 0xFF);
	}

	public static int byteArray2IntLittleEndian(byte[] from, int offset) {
		return (from[(offset + 3)] << 24 & 0xFF000000 | from[(offset + 2)] << 16 & 0xFF0000 | from[(offset + 1)] << 8 & 0xFF00 | from[offset] & 0xFF);
	}

	public static short byteArray2Short(byte[] from, int offset) {
		return (short) (from[offset] << 8 & 0xFF00 | from[(offset + 1)] & 0xFF);
	}

	public static short byteArray2ShortLittleEndian(byte[] from, int offset) {
		return (short) (from[(offset + 1)] << 8 & 0xFF00 | from[offset] & 0xFF);
	}

    public static String AsciiStringToString(String var0) {
        String var1 = "";
        int var2 = var0.length() / 2;

        for(int var3 = 0; var3 < var2; ++var3) {
            String var4 = var0.substring(var3 * 2, var3 * 2 + 2);
            int var5 = hexStringToAlgorism(var4);
            char var6 = (char)var5;
            String var7 = String.valueOf(var6);
            var1 = var1 + var7;
        }

        return var1;
    }

    public static int hexStringToAlgorism(String var0) {
        var0 = var0.toUpperCase();
        int var1 = var0.length();
        int var2 = 0;

        for(int var3 = var1; var3 > 0; --var3) {
            char var4 = var0.charAt(var3 - 1);
            boolean var5 = false;
            int var6;
            if(var4 >= 48 && var4 <= 57) {
                var6 = var4 - 48;
            } else {
                var6 = var4 - 55;
            }

            var2 = (int)((double)var2 + Math.pow(16.0D, (double)(var1 - var3)) * (double)var6);
        }

        return var2;
    }

	/**
	 * 把字节数组转换成16进制字符串.
	 *
	 * @param bArray
	 *            the b array
	 * @return the string
	 */
	public static final String bytesToHexStringNoSpace(byte[] bArray) {
		if (bArray == null || bArray.length == 0) {
			return "";
		}

		StringBuffer sb = new StringBuffer(bArray.length);
		String sTemp;
		for (int i = 0; i < bArray.length; i++) {
			sTemp = Integer.toHexString(0xFF & bArray[i]);
			if (sTemp.length() < 2)
				sb.append(0);
			sb.append(sTemp.toUpperCase());
			sb.append("");
		}
		return sb.toString();
	}

	private static byte toByte(char c) {
		byte b = (byte) "0123456789ABCDEF".indexOf(c);
		return b;
	}

	/**
	 * 把16进制字符串转换成字节数组
	 *
	 * @param hex
	 * @return
	 */
	public static byte[] hexStringToByte(String hex) {
		hex = hex.toUpperCase();
		int len = (hex.length() / 2);
		byte[] result = new byte[len];
		char[] achar = hex.toCharArray();
		for (int i = 0; i < len; i++) {
			int pos = i * 2;
			result[i] = (byte) (toByte(achar[pos]) << 4 | toByte(achar[pos + 1]));
		}
		return result;
	}

	/**
	 * 把字节数组转换成16进制字符串.
	 *
	 * @param bArray
	 *            the b array
	 * @return the string
	 */
	public static final String bytesToHexString(byte[] bArray) {
		if (bArray == null || bArray.length == 0) {
			return "";
		}

		StringBuffer sb = new StringBuffer(bArray.length);
		String sTemp;
		for (int i = 0; i < bArray.length; i++) {
			sTemp = Integer.toHexString(0xFF & bArray[i]);
			if (sTemp.length() < 2)
				sb.append(0);
			sb.append(sTemp.toUpperCase());
			sb.append(" ");
		}
		return sb.toString();
	}
}