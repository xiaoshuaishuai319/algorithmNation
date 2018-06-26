package cn.xsshome.algorithmNation.util;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECField;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEREncodableVector;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.gnu.GNUObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ECPoint;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.bc.BcX509v3CertificateBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECNamedDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.crypto.tls.SignatureAlgorithm;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.SignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.bc.BcECContentSignerBuilder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;

import sun.net.www.content.audio.aiff;
import sun.security.ec.CurveDB;
import sun.security.util.DerEncoder;
import sun.security.x509.AlgorithmId;
import sun.security.x509.SubjectKeyIdentifierExtension;

import com.xiaoleilu.hutool.lang.Base64;

/**
 * 国密证书相关工具类
 * @author 小帅丶
 *
 */
public class SMCertUtil {
	/**
	 * 国密证书签名算法名称
	 */
	private static String  SignAlgorName = "SM3WITHSM2";
	/**
	 * 生成国密ROOT证书方法 X509v3CertificateBuilder
	 * @param cn
	 * @param o
	 * @throws Exception
	 */
	public static void genSM2CertByX509v3CertificateBuilder(String cn,String o) throws Exception {
		org.bouncycastle.jce.provider.BouncyCastleProvider bouncyCastleProvider = new org.bouncycastle.jce.provider.BouncyCastleProvider();
		Security.addProvider(bouncyCastleProvider);
		String fileName = "root"+new Date().getTime()/1000;
		String path  = "F:/root/";
		String rootCertPath = path+fileName+".cer";
		try {
			//公私钥对 生成公私钥对非免费开源
			KeyPair kp = null;
			//转换成ECPublicKeyParameters  ECPrivateKeyParameters
			ECPublicKeyParameters bcecPublicKey =(ECPublicKeyParameters) ECUtil.generatePublicKeyParameter(kp.getPublic());
			ECPrivateKeyParameters bcecPrivateKey = (ECPrivateKeyParameters) ECUtil.generatePrivateKeyParameter(kp.getPrivate());
			//申请服务器证书信息
		    String  issuerString = "CN="+cn+",O="+o;
			X500Name issueDn = new X500Name(issuerString);  
	        X500Name subjectDn = new X500Name(issuerString);  
	        //代码非免费开源此方法createSubjectECPublicKeyInfo
	        SubjectPublicKeyInfo info =createSubjectECPublicKeyInfo(bcecPublicKey);
	        SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(ASN1Sequence.getInstance(kp.getPublic().getEncoded()));
			X509v3CertificateBuilder builder = new X509v3CertificateBuilder(issueDn, BigInteger.valueOf(System.currentTimeMillis()), new Date(), Util4Hex.getYearLater(5), Locale.CHINA, subjectDn, info);
			//基本约束
			BasicConstraints basicConstraints = new BasicConstraints(0);
			builder.addExtension(Extension.basicConstraints, true, basicConstraints);
			//添加CRL分布点 代码非免费开源此方法getCRLDIstPoint
			builder.addExtension(Extension.cRLDistributionPoints, true, XSCertExtension.getCRLDIstPoint());
			//添加证书策略 代码非免费开源此方法getPolicyInfo
			builder.addExtension(Extension.certificatePolicies, true, new DERSequence(XSCertExtension.getPolicyInfo()));
			//颁发者密钥标识 
			DigestCalculator calculator = new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1));
			X509ExtensionUtils extensionUtils = new X509ExtensionUtils(calculator);
			builder.addExtension(Extension.authorityKeyIdentifier, false, extensionUtils.createAuthorityKeyIdentifier(publicKeyInfo));
			//使用者密钥标识 
			builder.addExtension(Extension.subjectKeyIdentifier, false,extensionUtils.createSubjectKeyIdentifier(publicKeyInfo));
			//密钥用法
			builder.addExtension(Extension.keyUsage,true,XSCertExtension.getKeyUsage());
			//增强密钥用法 代码非免费开源此方法getExtendKeyUsage
			builder.addExtension(Extension.extendedKeyUsage,true,XSCertExtension.getExtendKeyUsage());
			AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(SignAlgorName);  
			AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find("SHA1");
			ContentSigner contentSigner = new BcECContentSignerBuilder(sigAlgId,digAlgId).build(bcecPrivateKey);
			X509CertificateHolder certificateHolder = builder.build(contentSigner);
			FileOutputStream outputStream = new FileOutputStream(rootCertPath);
			outputStream.write(certificateHolder.getEncoded());
			outputStream.close();
		} catch (Exception e) {
			e.printStackTrace();
			System.out.println("======根证书申请失败"+e.getMessage());
		}
	}
	private static SubjectPublicKeyInfo createSubjectECPublicKeyInfo(
			ECPublicKeyParameters bcecPublicKey) {
		//代码非免费开源此部分
		return null;
	}
}

