package gj.secure.util;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import java.io.IOException;

public class Base64Util {

    public static String toB64(byte[] bytes) {
        return new BASE64Encoder().encode(bytes);
    }

    public static byte[] fromB64(String b64String) throws IOException {
        return new BASE64Decoder().decodeBuffer(b64String);
    }
}
