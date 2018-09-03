package cn.xsshome.algorithmNation.util;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
/**
 * 国密SM4加解密 
 * 非小帅丶编写。
 * 代码参考来源于 https://github.com/ZZMarquis/gmhelper 
 * @author https://github.com/ZZMarquis/gmhelper  
 */
public class SM4EnDecryption {
	static{
		Security.addProvider(new BouncyCastleProvider());
	}
	//算法名称
	public static final String ALGORITHM_NAME = "SM4";
	//ECB P5填充
    public static final String ALGORITHM_NAME_ECB_PADDING = "SM4/ECB/PKCS5Padding";
    //CBC P5填充
    public static final String ALGORITHM_NAME_CBC_PADDING = "SM4/CBC/PKCS5Padding";
    //密钥长度
    public static final int DEFAULT_KEY_SIZE = 128;
    /**
     * 获取密钥
     * @return byte
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    public static byte[] generateKey() throws NoSuchAlgorithmException, NoSuchProviderException {
        return generateKey(DEFAULT_KEY_SIZE);
    }
    /**
     * 获取指定长度密钥
     * @param keySize 密钥的长度
     * @return byte
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    public static byte[] generateKey(int keySize) throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyGenerator kg = KeyGenerator.getInstance(ALGORITHM_NAME, BouncyCastleProvider.PROVIDER_NAME);
        kg.init(keySize, new SecureRandom());
        return kg.generateKey().getEncoded();
    }
    /**
     * ECB P5填充加密
     * @param key 密钥
     * @param data 明文数据
     * @return byte
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public static byte[] encrypt_Ecb_Padding(byte[] key, byte[] data)
        throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException,
        NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = generateEcbCipher(ALGORITHM_NAME_ECB_PADDING, Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }
    /**
     * ECB P5填充解密
     * @param key 密钥
     * @param cipherText 加密后的数据
     * @return byte
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws NoSuchPaddingException
     */
    public static byte[] decrypt_Ecb_Padding(byte[] key, byte[] cipherText)
        throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException,
        NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException {
        Cipher cipher = generateEcbCipher(ALGORITHM_NAME_ECB_PADDING, Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(cipherText);
    }
    /**
     * CBC P5填充加密
     * @param key 密钥
     * @param iv 偏移量
     * @param data 明文数据
     * @return byte
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws InvalidAlgorithmParameterException
     */
    public static byte[] encrypt_Cbc_Padding(byte[] key, byte[] iv, byte[] data)
        throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException,
        NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException,
        InvalidAlgorithmParameterException {
        Cipher cipher = generateCbcCipher(ALGORITHM_NAME_CBC_PADDING, Cipher.ENCRYPT_MODE, key, iv);
        return cipher.doFinal(data);
    }
    /**
     * CBC P5填充解密
     * @param key 密钥
     * @param iv 偏移量
     * @param cipherText 加密数据
     * @return byte
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws NoSuchPaddingException
     * @throws InvalidAlgorithmParameterException
     */
    public static byte[] decrypt_Cbc_Padding(byte[] key, byte[] iv, byte[] cipherText)
        throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException,
        NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException,
        InvalidAlgorithmParameterException {
        Cipher cipher = generateCbcCipher(ALGORITHM_NAME_CBC_PADDING, Cipher.DECRYPT_MODE, key, iv);
        return cipher.doFinal(cipherText);
    }
    /**
     * ECB P5填充加解密Cipher初始化
     * @param algorithmName 算法名称
     * @param mode 1 加密  2解密
     * @param key 密钥
     * @return Cipher
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     */
    private static Cipher generateEcbCipher(String algorithmName, int mode, byte[] key)
        throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException,
        InvalidKeyException {
        Cipher cipher = Cipher.getInstance(algorithmName, BouncyCastleProvider.PROVIDER_NAME);
        Key sm4Key = new SecretKeySpec(key, ALGORITHM_NAME);
        cipher.init(mode, sm4Key);
        return cipher;
    }
    /**
     * CBC P5填充加解密Cipher初始化
     * @param algorithmName 算法名称
     * @param mode 1 加密  2解密
     * @param key 密钥
     * @param iv 偏移量
     * @return Cipher
     * @throws InvalidKeyException
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws NoSuchPaddingException
     */
    private static Cipher generateCbcCipher(String algorithmName, int mode, byte[] key, byte[] iv)
        throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
        NoSuchProviderException, NoSuchPaddingException {
        Cipher cipher = Cipher.getInstance(algorithmName, BouncyCastleProvider.PROVIDER_NAME);
        Key sm4Key = new SecretKeySpec(key, ALGORITHM_NAME);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(mode, sm4Key, ivParameterSpec);
        return cipher;
    }
}
