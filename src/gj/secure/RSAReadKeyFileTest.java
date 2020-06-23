package gj.secure;

import gj.secure.rsa.DerUtils;
import gj.secure.rsa.PemUtils;
import gj.secure.util.Base64Util;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;

/**
 * created by areful <p>
 * Date: 2019/2/12 <p>
 * <pre class="prettyprint">
 * # generate .pem of private key
 * openssl genrsa -out private_key.pem 1024
 *
 * # generate .der of private key
 * openssl pkcs8 -topk8 -inform PEM -outform DER -in private_key.pem -out private_key.der -nocrypt
 *
 * # generate .pem of public key
 * openssl rsa -in private_key.pem -pubout -out public_key.pem
 * # generate .der of public key
 * openssl rsa -in private_key.pem -pubout -out public_key.der -outform DER
 * </pre>
 */
public class RSAReadKeyFileTest {
    public static void main(String[] args) throws Exception {
        {
            PublicKey publicKey = DerUtils.getPublicKey("src/gj/secure/public_key.der");
            System.out.println(Base64Util.toB64(publicKey.getEncoded()));

            PrivateKey privateKey = DerUtils.getPrivateKey("src/gj/secure/private_key.der");
            System.out.println(Base64Util.toB64(privateKey.getEncoded()));
        }

        {
            Security.addProvider(new BouncyCastleProvider());

            PublicKey publicKey = PemUtils.readPublicKeyFromFile("src/gj/secure/public_key.pem", "RSA");
            System.out.println(Base64Util.toB64(publicKey.getEncoded()));
            PrivateKey privateKey = PemUtils.readPrivateKeyFromFile("src/gj/secure/private_key.pem", "RSA");
            System.out.println(Base64Util.toB64(privateKey.getEncoded()));
        }
    }
}