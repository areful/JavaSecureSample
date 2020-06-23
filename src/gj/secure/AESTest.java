package gj.secure;

import gj.secure.aes.AESUtil;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import javax.crypto.spec.IvParameterSpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Base64;

/**
 * created by areful <p>
 * Date: 2019/2/12
 */
public class AESTest {

    public static void main(String[] args) throws Exception {
        testCbc();

        testEcb();
    }

    private static void testCbc() throws Exception {
        Key key = AESUtil.generateKey("0123456789abcdef".getBytes());
        IvParameterSpec iv = new IvParameterSpec("abcdefghijklmnop".getBytes());

        String text = "7nm工艺、Zen 2架构的移动版锐龙4000U、锐龙4000H系列，桌面版锐龙4000G系列，都是非常的香，" +
                "AMD还刚刚发布了鸡血版的锐龙3000XT。但是，很多玩家也在热切期盼Zen 3全新架构的第四代桌面锐龙4000系列，" +
                "虽然仍是7nm工艺，但是架构、频率、缓存、性能等都会有飞跃一般的提升。";
        byte[] cipherText = AESUtil.encrypt(key, iv, text.getBytes(StandardCharsets.UTF_8));
        String base64String = Base64.getEncoder().encodeToString(cipherText);
        System.out.println(base64String);
        byte[] plainText = AESUtil.decrypt(key, iv, Base64.getDecoder().decode(base64String));
        System.out.println(new String(plainText, StandardCharsets.UTF_8));
    }

    private static void testEcb() throws Exception {
        String text = "AMD今晚发布了锐龙3000XT系列新品，这是7nm Zen2的提频版，7月7日正式开卖，" +
                "正好是7nm上市一周年的日子。如果不延期的话，今年还会有7nm+工艺的Zen3处理器，也就是锐龙4000桌面版。";
        Key key = AESUtil.generateKey();
        byte[] bytes = AESUtil.encrypt(key, text.getBytes(StandardCharsets.UTF_8));
        String cipherText = toB64(bytes);
        System.out.println(cipherText);

        byte[] encryptedBytes = fromB64(cipherText);
        byte[] r = AESUtil.decrypt(key, encryptedBytes);
        System.out.println(new String(r, StandardCharsets.UTF_8));
    }

    private static String toB64(byte[] bytes) {
        return new BASE64Encoder().encode(bytes);
    }

    private static byte[] fromB64(String b64String) throws IOException {
        return new BASE64Decoder().decodeBuffer(b64String);
    }
}