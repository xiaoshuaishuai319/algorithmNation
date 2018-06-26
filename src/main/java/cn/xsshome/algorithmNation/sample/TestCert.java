package cn.xsshome.algorithmNation.sample;

import cn.xsshome.algorithmNation.util.SMCertUtil;
/**
 * 生成证书
 * @author 小帅丶
 *
 */
public class TestCert {
	public static void main(String[] args) throws Exception {
		SMCertUtil.genSM2CertByX509v3CertificateBuilder("测试", "测试");
	}
}
