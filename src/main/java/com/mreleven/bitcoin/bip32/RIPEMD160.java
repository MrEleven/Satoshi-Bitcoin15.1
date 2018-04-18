package com.mreleven.bitcoin.bip32;

import org.spongycastle.crypto.digests.RIPEMD160Digest;

/**
 * 类概述
 *
 * @author eleven@creditfolder.io
 * @since 2018年04月18日 17:35
 */
public class RIPEMD160 {

    public static byte[] hash(byte[] value) {
        byte[] ph = new byte[20];
        RIPEMD160Digest digest = new RIPEMD160Digest();
        digest.update(value, 0, value.length);
        digest.doFinal(ph, 0);
        return ph;
    }
}
