package gj.secure.rsa;

import javax.crypto.Cipher;
import java.io.ByteArrayOutputStream;
import java.security.*;

/**
 * created by areful <p>
 * Date: 2019/2/12 <p>
 */
public class RSAUtil {
    public static final String ALGORITHM_RSA = "RSA";
    public static final String ALGORITHM_RSA_PKCS1PADDING = "RSA/ECB/PKCS1PADDING";
    public static final String SIGNATURE_ALGORITHM = "MD5withRSA";
    private static final int MAX_ENCRYPT_BLOCK = 117;
    private static final int MAX_DECRYPT_BLOCK = 128;

    public static KeyPair genKeyPair() throws Exception {
        KeyPairGenerator kg = KeyPairGenerator.getInstance(ALGORITHM_RSA);
        kg.initialize(1024);
        return kg.generateKeyPair();
    }

    public static byte[] encryptByPublicKey(PublicKey pubKey, byte[] data) throws Exception {
        return doFinal(pubKey, Mode.ENCRYPT, data);
    }

    public static byte[] decryptByPrivateKey(PrivateKey priKey, byte[] data) throws Exception {
        return doFinal(priKey, Mode.DECRYPT, data);
    }

    public static byte[] encryptByPrivateKey(PrivateKey priKey, byte[] data) throws Exception {
        return doFinal(priKey, Mode.ENCRYPT, data);
    }

    public static byte[] decryptByPublicKey(PublicKey pubKey, byte[] data) throws Exception {
        return doFinal(pubKey, Mode.DECRYPT, data);
    }

    public static byte[] sign(PrivateKey priKey, byte[] data) throws Exception {
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(priKey);
        signature.update(data);
        return signature.sign();
    }

    public static boolean verify(PublicKey pubKey, byte[] data, byte[] sign) throws Exception {
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initVerify(pubKey);
        signature.update(data);
        return signature.verify(sign);
    }

    private enum Mode {
        ENCRYPT(Cipher.ENCRYPT_MODE),
        DECRYPT(Cipher.DECRYPT_MODE);
        private final int value;

        Mode(int value) {
            this.value = value;
        }
    }

    private static byte[] doFinal(Key key, Mode mode, byte[] data) throws Exception {
        final int MAX = (mode == Mode.ENCRYPT) ? MAX_ENCRYPT_BLOCK : MAX_DECRYPT_BLOCK;
        final int LEN = data.length;
        byte[] cache;
        int i = 0, off = 0;

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Cipher cipher = Cipher.getInstance(ALGORITHM_RSA_PKCS1PADDING);
        cipher.init(mode.value, key);
        while (off < LEN) {
            cache = cipher.doFinal(data, off, Math.min(LEN - off, MAX));
            out.write(cache, 0, cache.length);
            i++;
            off = i * MAX;
        }
        byte[] result = out.toByteArray();
        out.close();
        return result;
    }
}