package cn.xsshome.algorithmNation.util;

import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.math.ec.ECPoint;

/**
 * SM2加解密
 * @author 小帅丶
 * @类名称  SM2EnDecryption
 * @remark 
 * @date  2018-01-30
 */
public class SM2EnDecryption {
	/**
	 * 
	 * @param hexStrPub
	 * @param data
	 * @return
	 */
	public static String encrypt(String hexStrPub,byte[] data){
		byte sm2PublicKey[] = Util.hexToByte(hexStrPub);
		byte[] formatedPubKey = new byte[65];
		if(sm2PublicKey.length==64){
			formatedPubKey = new byte[65];
			formatedPubKey[0] = 0x04;
			System.arraycopy(sm2PublicKey, 0, formatedPubKey, 1, sm2PublicKey.length);
		}else{
			formatedPubKey = sm2PublicKey;
		}
		byte[] source = new byte[data.length];
		System.arraycopy(data, 0, source, 0, data.length);
		Cipher2SM2 cipher2sm2 = new Cipher2SM2();
		SM2Factory sm2Factory = SM2Factory.getInstance();
		ECPoint ecPoint = sm2Factory.ecc_curve.decodePoint(sm2PublicKey);
		ECPoint c1 = cipher2sm2.Init_enc(sm2Factory, ecPoint);
		cipher2sm2.Encrypt(source);
		byte [] c3 = new byte[32];
		cipher2sm2.Dofinal(c3);
		return Util.byteToHex(c1.getEncoded(false)) + Util.byteToHex(source) +Util.byteToHex(c3);
	}
	/**
	 * SM2加密 
	 * @param hexStrPub 公钥信息
	 * @param data 加密数据信息
	 * @return
	 */
	public static String encrypt(byte[]hexStrPub,byte[] data){
		byte[] source = new byte[data.length];
		byte[] formatedPubKey;
		System.arraycopy(data, 0, source, 0, data.length);
		Cipher2SM2 cipher2sm2 = new Cipher2SM2();
		SM2Factory sm2Factory = SM2Factory.getInstance();
		if(hexStrPub.length==64){
			formatedPubKey = new byte[65];
			formatedPubKey[0] = 0x04;
			System.arraycopy(hexStrPub, 0, formatedPubKey, 1, hexStrPub.length);
		}else{
			formatedPubKey = hexStrPub;
		}
		ECPoint ecPoint = sm2Factory.ecc_curve.decodePoint(formatedPubKey);
		ECPoint c1 = cipher2sm2.Init_enc(sm2Factory, ecPoint);
		cipher2sm2.Encrypt(source);
		byte [] c3 = new byte[32];
		cipher2sm2.Dofinal(c3);
		return Util.byteToHex(c1.getEncoded(false)) + Util.byteToHex(source) +Util.byteToHex(c3);
	}
	/**
	 * SM2解密
	 * @param privateKey 私钥信息
	 * @param encryptedData 加密后的数据信息
	 * @return
	 * @throws IOException
	 */
	public static byte[] decrypt(byte[] privateKey, byte[] encryptedData) throws IOException {
		if (privateKey == null || privateKey.length == 0) {
			return null;
		}
		if (encryptedData == null || encryptedData.length == 0) {
			return null;
		}
		// 加密字节数组转换为十六进制的字符串 长度变为encryptedData.length * 2
		String data = Util.byteToHex(encryptedData);
		/***
		 * 分解加密字串 （C1 = C1标志位2位 + C1实体部分128位 = 130） （C3 = C3实体部分64位 = 64） （C2 =
		 * encryptedData.length * 2 - C1长度 - C2长度）
		 */
		byte[] c1Bytes = Util.hexToByte(data.substring(0, 130));
		int c2Len = encryptedData.length - 97;
		byte[] c2 = Util.hexToByte(data.substring(130, 130 + 2 * c2Len));
		byte[] c3 = Util.hexToByte(data.substring(130 + 2 * c2Len,194 + 2 * c2Len));

		SM2Factory sm2 = SM2Factory.getInstance();
		BigInteger userD = new BigInteger(1, privateKey);
		// 通过C1实体字节来生成ECPoint
		ECPoint c1 = sm2.ecc_curve.decodePoint(c1Bytes);
		Cipher2SM2 cipher = new Cipher2SM2();
		cipher.Init_dec(userD, c1);
		cipher.Decrypt(c2);
		cipher.Dofinal(c3);
		// 返回解密结果
		return c2;
	}
}
