package cn.xsshome.algorithmNation.util;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.Calendar;
import java.util.Date;

import com.xiaoleilu.hutool.lang.Base64;

public class Util4Hex {
	/**
	 * 根据路径获取公钥对象
	 * @param path
	 * @return
	 * @throws Exception
	 */
	public static PublicKey getpubKey(String path) throws Exception{
		StringBuffer str = new StringBuffer("");
		File file = new File(path);
		X509EncodedKeySpec keySpec = null;
		KeyFactory keyFactory = null;
		try {
			FileReader fileReader = new FileReader(file);
			int ch = 0;
			while ((ch=fileReader.read())!=-1) {
				str.append((char)ch);
			}
			fileReader.close();
			byte[] buffer = Base64.decode(str.toString());
			keyFactory = KeyFactory.getInstance("RSA");
			keySpec = new X509EncodedKeySpec(buffer);
			return keyFactory.generatePublic(keySpec);
		} catch (Exception e) {
			throw new Exception("公钥数据为空");
		}
	}
	public static String bytesToHexString(byte[] src){   
	    StringBuilder stringBuilder = new StringBuilder("");   
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
	 * Convert hex string to byte[]  
	 * @param hexString the hex string  
	 * @return byte[]  
	 */  
	public static byte[] hexStringToBytes(String hexString) {   
	    if (hexString == null || hexString.equals("")) {   
	        return null;   
	    }   
	    hexString = hexString.toUpperCase();   
	    int length = hexString.length() / 2;   
	    char[] hexChars = hexString.toCharArray();   
	    byte[] d = new byte[length];   
	    for (int i = 0; i < length; i++) {   
	        int pos = i * 2;   
	        d[i] = (byte) (charToByte(hexChars[pos]) << 4 | charToByte(hexChars[pos + 1]));   
	    }   
	    return d;   
	}  
	 /**
     * 十六进制串转化为byte数组
     * 
     * @return the array of byte
     */
    public static byte[] hexToByte(String hex)
            throws IllegalArgumentException {
        if (hex.length() % 2 != 0) {
            throw new IllegalArgumentException();
        }
        char[] arr = hex.toCharArray();
        byte[] b = new byte[hex.length() / 2];
        for (int i = 0, j = 0, l = hex.length(); i < l; i++, j++) {
            String swap = "" + arr[i++] + arr[i];
            int byteint = Integer.parseInt(swap, 16) & 0xFF;
            b[j] = new Integer(byteint).byteValue();
        }
        return b;
    }
	public static X509Certificate rootCA(String rootPath) throws Exception{
		X509Certificate cert = null;
		FileInputStream fis = new FileInputStream(rootPath);
		BufferedInputStream bis = new BufferedInputStream(fis);
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		while (bis.available() > 0) {
			cert = (X509Certificate) cf.generateCertificate(fis);
		}
		return cert;
	}
	/**  
	 * Convert char to byte  
	 * @param c char  
	 * @return byte  
	 */  
	 private static byte charToByte(char c) {   
	    return (byte) "0123456789ABCDEF".indexOf(c);   
	}  
		/**
		 * 计算当前时间的N年后
		 * @param later 正整数
		 * @return
		 */
		public static Date getYearLater(int later) {
			Date date = new Date();
			try {
				Calendar calendar = Calendar.getInstance();
				calendar.add(Calendar.YEAR,later);
				date = calendar.getTime();
			} catch (Exception e) {
				System.out.println(e.getMessage());
			}
			return date;
		}
}
