package cn.xsshome.algorithmNation.sample;

import cn.xsshome.algorithmNation.util.SM2VerifySign;
import cn.xsshome.algorithmNation.util.Util;
import cn.xsshome.algorithmNation.util.Util4Hex;
import cn.xsshome.algorithmNation.vo.SM2SignVO;

/**
 * SM2签名验签
 * @author 小帅丶
 */
public class TestSign {
	public static void main(String[] args) throws Exception {
		String text = "这是一段明文";
		byte [] sourceData = text.getBytes();
		String publicKey ="FA05C51AD1162133DFDF862ECA5E4A481B52FB37FF83E53D45FD18BBD6F32668A92C4692EEB305684E3B9D4ACE767F91D5D108234A9F07936020A92210BA9447";
		String privatekey = "5EB4DF17021CC719B678D970C620690A11B29C8357D71FA4FF9BF7FB6D89767A";
		SM2SignVO sign = SM2VerifySign.Sign2SM2(Util.hexStringToBytes(privatekey), sourceData);
		SM2SignVO verify = SM2VerifySign.VerifySignSM2(Util.hexStringToBytes(publicKey), sourceData, Util4Hex.hexStringToBytes(sign.getSm2_sign()));
		System.out.println("签名得到的r值:"+sign.getSign_r()+"\n签名值 "+sign.getSm2_sign());
		System.out.println("验签得到的R值:"+verify.getVerify_r());
		System.err.println("\n验签结果" +verify.isVerify());
	}
}
