package com.mreleven.bitcoin.bip32;

import com.sun.tools.javac.util.Assert;
import org.spongycastle.asn1.sec.SECNamedCurves;
import org.spongycastle.asn1.x9.X9ECParameters;
import org.spongycastle.crypto.params.ECDomainParameters;

import java.math.BigInteger;

/**
 * 类概述
 *
 * @author eleven@creditfolder.io
 * @since 2018年04月17日 23:05
 */
public class CKey {
    public static final X9ECParameters curve = SECNamedCurves.getByName("secp256k1");
    public static final ECDomainParameters params = new ECDomainParameters(curve.getCurve(), curve.getG(), curve.getN(), curve.getH());

    private byte[] pri;

    public CKey(byte[] pri) {
        this.pri = pri;
    }

    public CKey() {
    }

    public byte[] getPri() {
        return pri;
    }

    public void setPri(byte[] pri) {
        this.pri = pri;
    }

    public byte[] getPub(boolean compressed) {
        Assert.check(this.pri != null, "CExtKey: prikey is null");
        return curve.getG().multiply(new BigInteger(1, pri)).getEncoded(compressed);
    }

    public static void main(String args[]) {
        int a = 10;
        System.out.println(Integer.MAX_VALUE);
        long x = 2147483648L;
        System.out.println(x > Integer.MAX_VALUE);
    }
}
