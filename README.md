[![Version](https://img.shields.io/badge/version-0.0.1-brightgreen.svg)](https://www.xsshome.cn/)
[![License](http://img.shields.io/:license-apache-blue.svg)](http://www.apache.org/licenses/LICENSE-2.0.html)
[![JDK 1.8](https://img.shields.io/badge/JDK-1.8-green.svg "JDK 1.8")]()
[![作者](https://img.shields.io/badge/%E4%BD%9C%E8%80%85-%E5%B0%8F%E5%B8%85%E4%B8%B6-7AD6FD.svg)](https://www.xsshome.cn/)

SM2生成证书请移步:[https://blog.csdn.net/u010651369/article/details/76907312](https://blog.csdn.net/u010651369/article/details/76907312)

sm2root.cer是一个国密证书测试文件。可以自行下载查看相关证书内容哦

QQ:783021975

SM2证书生成相关文档&博文地址(有完全免费开源的代码)：[http://gm4j.mydoc.io/](http://gm4j.mydoc.io/)

新加1.SMCertUtil 生成国密证书工具类 2. XSCertExtension 拓展信息工具类

目录结构
```
cn.xsshome.algorithmNation
       ├── sample                                  //测试代码
                └── Test                          //SM2加解密示例代码
                └── TestSign                     //SM2签名验签示例代码
                └── TestCert                     //SM2证书生成调用示例代码          
                └── TestSM4                     //SM4加解密示例代码   
       ├── vo                                   //相关Java对象
       └── util                                //工具类包含了SM2 SM3等一系列工具类
```
       
所需依赖包
```
<!-- BC依赖包 -->
<dependency>
    <groupId>org.bouncycastle</groupId>
    <artifactId>bcpkix-jdk15on</artifactId>
    <version>1.57</version>
</dependency>
<!-- BC依赖包 -->
<dependency>
    <groupId>org.bouncycastle</groupId>
    <artifactId>bcmail-jdk15on</artifactId>
    <version>1.56</version>
</dependency>
<!-- hutool工具类 -->
<dependency>
    <groupId>com.xiaoleilu</groupId>
    <artifactId>hutool-all</artifactId>
    <version>3.0.9</version>
</dependency>
```

