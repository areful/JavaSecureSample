package gj.secure;

import gj.secure.rsa.RSAUtil;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

/**
 * created by areful <p>
 * Date: 2019/2/12 <p>
 */
public class RSATest {
    public static void main(String[] args) throws Exception {
        KeyPair keyPair = RSAUtil.genKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        System.err.println("公钥加密——私钥解密");
        String src = "第一次握手：Client将标志位SYN置为1，随机产生一个值seq=J，并将该数据包发送给Server，Client进入SYN_SENT状态，等待Server确认。";
        System.out.println("原文字：\t" + src);
        byte[] encodedData = RSAUtil.encryptByPublicKey(publicKey, src.getBytes());
        System.out.println("加密后：\t" + Arrays.toString(encodedData));
        String plainText = new String(RSAUtil.decryptByPrivateKey(privateKey, encodedData));
        System.out.println("解密后: \t" + plainText);

        System.err.println("私钥加密——公钥解密");
        System.out.println("原文字：\t" + src);
        encodedData = RSAUtil.encryptByPrivateKey(privateKey, src.getBytes());
        System.out.println("加密后：\t" + Arrays.toString(encodedData));
        plainText = new String(RSAUtil.decryptByPublicKey(publicKey, encodedData));
        System.out.println("解密后: \t" + plainText);

        System.err.println("私钥签名——公钥验证签名");
        byte[] sign = RSAUtil.sign(privateKey, encodedData);
        System.err.println("签名：\t\t" + Arrays.toString(sign));
        boolean status = RSAUtil.verify(publicKey, encodedData, sign);
        System.err.println("验证结果：\t" + status);
    }
}