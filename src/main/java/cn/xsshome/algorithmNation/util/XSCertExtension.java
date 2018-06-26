package cn.xsshome.algorithmNation.util;


import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyUsage;
/**
 * 拓展信息方法封装
 * @author 小帅丶
 *
 */
public class XSCertExtension {
	/**
	 * 证书CRL分布点
	 * @return
	 */
	public static CRLDistPoint getCRLDIstPoint() {
		return null;
	}
	/**
	 * 证书策略
	 * @return
	 */
	public static ASN1EncodableVector getPolicyInfo() {
		return null;
	}
	/**
	 * 增强密钥用法
	 * 如果需要更多请自行查看 @see KeyPurposeId
	 * @return ExtendedKeyUsage
	 */
	public static ExtendedKeyUsage getExtendKeyUsage() {
		return null;
	}
	/**
	 * 密钥用法
	 * @return
	 */
	public static KeyUsage getKeyUsage() {
		int usage = KeyUsage.digitalSignature;  
        usage += KeyUsage.nonRepudiation;  
        usage += KeyUsage.keyEncipherment;  
        usage += KeyUsage.dataEncipherment;  
        usage += KeyUsage.keyAgreement;  
        usage += KeyUsage.keyCertSign;  
        usage += KeyUsage.cRLSign;  
        usage += KeyUsage.encipherOnly;  
        usage += KeyUsage.decipherOnly;  
        KeyUsage keyUsage = new KeyUsage(usage);  
		return keyUsage;
	}
}
