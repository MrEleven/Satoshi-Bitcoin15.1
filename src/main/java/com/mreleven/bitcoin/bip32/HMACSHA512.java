package com.mreleven.bitcoin.bip32;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * 类概述
 *
 * @author eleven@creditfolder.io
 * @since 2018年04月17日 17:39
 */
public class HMACSHA512 {

    /**
     * Used to generate a maser's key hash (using "Bitcoin seed" string as key)
     *
     * @param value
     * @return
     * @throws Exception
     */
    public static byte[] hash(byte[] keyBytes, byte[] value) throws NoSuchAlgorithmException, InvalidKeyException {
        final SecretKeySpec key = new SecretKeySpec(keyBytes, "HmacSHA512");
        final Mac mac = Mac.getInstance("HmacSHA512");
        mac.init(key);
        return mac.doFinal(value);

    }
}
