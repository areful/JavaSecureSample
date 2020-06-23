package gj.secure.aes;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;

/**
 * created by areful <p>
 * Date: 2019/2/12 <p>
 */
public class AESUtil {
    public static final String KEY_ALGORITHM = "AES";
    public static final String CIPHER_ALGORITHM_CBC = "AES/CBC/PKCS5Padding";
    public static final String CIPHER_ALGORITHM_ECB = "AES/ECB/PKCS5Padding";

    public static Key generateKey() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance(KEY_ALGORITHM);
        kg.init(128);
        return kg.generateKey();
    }

    public static Key generateKey(byte[] keyBytes) {
        return new SecretKeySpec(keyBytes, KEY_ALGORITHM);
    }

    public static byte[] encrypt(Key key, byte[] data) throws Exception {
        return EcbCipher.doFinal(Mode.ENCRYPT, key, data);
    }

    public static byte[] decrypt(Key key, byte[] data) throws Exception {
        return EcbCipher.doFinal(Mode.DECRYPT, key, data);
    }

    public static byte[] encrypt(Key key, IvParameterSpec iv, byte[] data) throws Exception {
        return CbcCipher.doFinal(Mode.ENCRYPT, key, iv, data);
    }

    public static byte[] decrypt(Key key, IvParameterSpec iv, byte[] data) throws Exception {
        return CbcCipher.doFinal(Mode.DECRYPT, key, iv, data);
    }

    private enum Mode {
        ENCRYPT(Cipher.ENCRYPT_MODE),
        DECRYPT(Cipher.DECRYPT_MODE);
        public final int type;

        Mode(int type) {
            this.type = type;
        }
    }

    private static class CbcCipher {
        private static byte[] doFinal(Mode mode, Key key, IvParameterSpec iv, byte[] data) throws Exception {
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM_CBC);
            cipher.init(mode.type, key, iv);
            return cipher.doFinal(data);
        }
    }

    private static class EcbCipher {
        private static byte[] doFinal(Mode mode, Key key, byte[] data) throws Exception {
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM_ECB);
            cipher.init(mode.type, key);
            return cipher.doFinal(data);
        }
    }
}