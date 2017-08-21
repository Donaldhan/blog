package webservice;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;
/**
 * 目前主流的加密方式有：（对称加密）AES、DES        
 * （非对称加密）RSA、DSA。
 * SecretKeyFactory表示秘密密钥的工厂，
 * 密钥工厂用来将密钥（类型 Key 的不透明加密密钥）转换为密钥规范（底层密钥材料的透明表示形式），
 * 反之亦然。秘密密钥工厂只对秘密（对称）密钥进行操作。
 * 密钥工厂为双工模式，即其允许根据给定密钥规范（密钥材料）构建不透明密钥对象，或以适当格式获取密钥对象的底层密钥材料。 
 * 调用AES/DES加密算法包最精要的就是下面两句话：
 * Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
 * cipher.init(Cipher.ENCRYPT_MODE, key, zeroIv);
 * CBC是工作模式，DES一共有电子密码本模式（ECB）、加密分组链接模式（CBC）、加密反馈模式（CFB）和输出反馈模式（OFB）四种模式
 * PKCS5Padding是填充模式，还有其它的填充模式：
 * 然后，cipher.init（)一共有三个参数：Cipher.ENCRYPT_MODE, key, zeroIv，zeroIv就是初始化向量。
 * 工作模式、填充模式、初始化向量这三种因素一个都不能少。否则，如果你不指定的话，那么就要程序就要调用默认实现。
 * @author donald
 * @date 2017-8-21
 * @time 下午3:05:25
 */
public class DesHelper {
	/**初始化向量参数*/
	private static final String IV = "1234567-";
	private static final String encodeCharSet = "UTF-8";
	/**DESCBC加密算法*/
	private static final String DESECB_FACTORY_INSTANCE = "DES";
	/**3DESCBC加密算法*/
	private static final String DESECB3_FACTORY_INSTANCE = "DESede";
	/**DESCBC填充模式*/
	private static final String Cipher_FACTORY_INSTANCE = "DES/CBC/PKCS5Padding";
	/**3DESCBC填充模式*/
	private static final String Cipher3_FACTORY_INSTANCE = "DESede/ECB/PKCS5Padding";
	private static volatile DesHelper instance = null;
	/**
	 * 
	 * @return
	 */
	public static synchronized DesHelper getInstance(){
		if(null == instance){
			instance = new DesHelper();
		}
		return instance;
	}	 
	/**
	  * DESCBC加密
	  * @param src 数据源
	  * @param key 密钥，长度必须是8的倍数
	  * @return 返回加密后的数据
	  * @throws Exception
	  */
    public String encryptDESCBC(final String src, final String key) throws Exception {
        // --生成key,同时制定是des还是DESede,两者的key长度要求不同
        final DESKeySpec desKeySpec = new DESKeySpec(key.getBytes(encodeCharSet));
        final SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(DESECB_FACTORY_INSTANCE);
        final SecretKey secretKey = keyFactory.generateSecret(desKeySpec);
        // --加密向量
        final IvParameterSpec iv = new IvParameterSpec(IV.getBytes(encodeCharSet));
        // --通过Chipher执行加密得到的是一个byte的数组,Cipher.getInstance("DES")就是采用ECB模式,
        //cipher.init(Cipher.ENCRYPT_MODE,secretKey)就可以了.
        final Cipher cipher = Cipher.getInstance(Cipher_FACTORY_INSTANCE);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
        final byte[] b = cipher.doFinal(src.getBytes(encodeCharSet));
        // --通过base64,将加密数组转换成字符串
        final BASE64Encoder encoder = new BASE64Encoder();
        return encoder.encode(b);
    }

    /**
     * DESCBC解密
     * @param src 数据源
     * @param key 密钥，长度必须是8的倍数
     * @return 返回解密后的原始数据
     * @throws Exception
     */
    public String decryptDESCBC(final String src, final String key) throws Exception {
        // --通过base64,将字符串转成byte数组
        final BASE64Decoder decoder = new BASE64Decoder();
        final byte[] bytesrc = decoder.decodeBuffer(src);
        // --解密的key
        final DESKeySpec desKeySpec = new DESKeySpec(key.getBytes(encodeCharSet));
        final SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(DESECB_FACTORY_INSTANCE);
        final SecretKey secretKey = keyFactory.generateSecret(desKeySpec);
        // --向量
        final IvParameterSpec iv = new IvParameterSpec(IV.getBytes(encodeCharSet));
        // --Chipher对象解密Cipher.getInstance("DES")就是采用ECB模式,
        //cipher.init(Cipher.DECRYPT_MODE,secretKey)就可以了.
        final Cipher cipher = Cipher.getInstance(Cipher_FACTORY_INSTANCE);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
        final byte[] retByte = cipher.doFinal(bytesrc);

        return new String(retByte);

    }

    /**
     * 3DESECB加密,key必须是长度大于等于 3*8 = 24 位
     * @param src
     * @param key
     * @return
     * @throws Exception
     */
    public String encrypt3DESECB(final String src, final String key) throws Exception {
        final DESedeKeySpec dks = new DESedeKeySpec(key.getBytes(encodeCharSet));
        final SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(DESECB3_FACTORY_INSTANCE);
        final SecretKey securekey = keyFactory.generateSecret(dks);
        final Cipher cipher = Cipher.getInstance(Cipher3_FACTORY_INSTANCE);
        cipher.init(Cipher.ENCRYPT_MODE, securekey);
        final byte[] b = cipher.doFinal(src.getBytes());
        final BASE64Encoder encoder = new BASE64Encoder();
        return encoder.encode(b).replaceAll("\r", "").replaceAll("\n", "");

    }

    /**
     * 3DESECB解密,key必须是长度大于等于 3*8 = 24 位
     * @param src
     * @param key
     * @return
     * @throws Exception
     */
    public String decrypt3DESECB(final String src, final String key) throws Exception {
        // --通过base64,将字符串转成byte数组
        final BASE64Decoder decoder = new BASE64Decoder();
        final byte[] bytesrc = decoder.decodeBuffer(src);
        // --解密的key
        final DESedeKeySpec dks = new DESedeKeySpec(key.getBytes(encodeCharSet));
        final SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(DESECB3_FACTORY_INSTANCE);
        final SecretKey securekey = keyFactory.generateSecret(dks);
        // --Chipher对象解密
        final Cipher cipher = Cipher.getInstance(Cipher3_FACTORY_INSTANCE);
        cipher.init(Cipher.DECRYPT_MODE, securekey);
        final byte[] retByte = cipher.doFinal(bytesrc);
        return new String(retByte);
    }
    public static void main(String[] args) throws Exception {
    	String timeStamp = "20170824094138";
	String passWord="123456";
	String key = "aassffgdwlfsffgsfdgsdgssfgsg";
	String encodeResult = DesHelper.getInstance().encrypt3DESECB(timeStamp+passWord, key);
	System.out.println("3DES algorithm encode result:"+encodeResult);
	}
}
