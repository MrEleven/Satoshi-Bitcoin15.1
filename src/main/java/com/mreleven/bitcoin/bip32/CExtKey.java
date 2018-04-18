package com.mreleven.bitcoin.bip32;

import com.sun.tools.javac.util.Assert;
import org.spongycastle.util.encoders.Hex;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * 类概述
 *
 * @author eleven@creditfolder.io
 * @since 2018年04月17日 23:06
 */
public class CExtKey {
    private static final byte[] PUBVERSION = Hex.decode("0488B21E");
    private static final byte[] PRIVERSION = Hex.decode("0488ADE4");

    private static final int LEN_DEPTH = 1;
    private static final int LEN_FINGER = 4;
    private static final int LEN_CHILDNUMBER = 4;
    private static final int LEN_CHAINCODE = 32;
    private static final int LEN_KEY = 33;

    // 32bit
    private byte[] chainCode;
    // depth
    private Byte depth;
    // childnumber
    private Long childnumber;
    // 密钥对
    private CKey key;
    // 密钥指纹
    private byte[] fingerprint;

    public CExtKey(byte[] pri, byte[] chainCode) {
        this.key = new CKey(pri);
        this.chainCode = chainCode;
    }

    public byte[] getPri() {
        return this.key.getPri();
    }

    public byte[] getPub(boolean compressed) {
        return this.key.getPub(compressed);
    }

    public byte[] getChainCode() {
        return chainCode;
    }

    public void setChainCode(byte[] chainCode) {
        this.chainCode = chainCode;
    }

    public byte getDepth() {
        return depth;
    }

    public void setDepth(byte depth) {
        this.depth = depth;
    }

    public long getChildnumber() {
        return childnumber;
    }

    public void setChildnumber(long childnumber) {
        this.childnumber = childnumber;
    }

    public byte[] getFingerprint() {
        return fingerprint;
    }

    public void setFingerprint(byte[] fingerprint) {
        this.fingerprint = fingerprint;
    }

    /**
     * 从扩展私钥解析CExtKey
     * @param extPriKey
     * @return
     */
    public static CExtKey parseFromExtPriKey(String extPriKey) {
        // depth(1bytes) + fingerprint(4bytes) + childnumber(4bytes) + chaincode(32bytes) + pub(33bytes)
        byte[] data = Base58.decodeBase58Check(PUBVERSION, extPriKey);
        byte depth = data[0];
        int position = LEN_DEPTH;
        byte[] fingerprint = Arrays.copyOfRange(data, position, position + LEN_FINGER);
        position += LEN_FINGER;
        byte[] childnumber = Arrays.copyOfRange(data, position, position + LEN_CHILDNUMBER);
        position += LEN_CHILDNUMBER;
        byte[] chaincode = Arrays.copyOfRange(data, position, position + LEN_CHAINCODE);
        position += LEN_CHAINCODE;
        byte[] priv = Arrays.copyOfRange(data, position, position + LEN_KEY);

        CExtKey cExtKey = new CExtKey(priv, chaincode);
        cExtKey.setDepth(depth);
        cExtKey.setFingerprint(fingerprint);
        cExtKey.setChildnumber(Utils.readUint32BE(childnumber, 0));
        return cExtKey;
    }

    public String serialExtPriKey() {
        Assert.check(this.childnumber != null, "CExtKey: childnumber is null");
        Assert.check(this.depth != null, "CExtKey: depth is null");
        byte[] dataToSerial = new byte[74];
        // 1byte depth
        dataToSerial[0] = depth.byteValue();
        int position = LEN_DEPTH;
        // 4bytes  the fingerprint of the parent's key (0x00000000 if master key)
        System.arraycopy(fingerprint, 0, dataToSerial, position, LEN_FINGER);
        position += LEN_FINGER;
        // 4 bytes: child number. This is ser32(i) for i in xi = xpar/i, with xi the key being serialized. (0x00000000 if master key)
        Utils.uint32ToByteArrayBE(childnumber, dataToSerial, position);
        position += LEN_CHILDNUMBER;
        // 32 bytes: the chain code
        System.arraycopy(chainCode, 0, dataToSerial, position, LEN_CHAINCODE);
        position += LEN_CHAINCODE;
        // 33 bytes: the public key or private key data (serP(K) for public keys, 0x00 || ser256(k) for private keys)
        dataToSerial[41] = 0;
//        System.out.println("pri:" + Hex.encode(getPri()));
        System.arraycopy(getPri(), 0, dataToSerial, position + 1, LEN_KEY - 1);
        return Base58.base58check(PRIVERSION, dataToSerial);
    }

    public String serialExtPubKey() {
        Assert.check(this.childnumber != null, "CExtKey: childnumber is null");
        Assert.check(this.depth != null, "CExtKey: depth is null");
        byte[] dataToSerial = new byte[74];
        // 1byte depth
        dataToSerial[0] = depth.byteValue();
        int position = LEN_DEPTH;
        // 4bytes  the fingerprint of the parent's key (0x00000000 if master key)
        System.arraycopy(fingerprint, 0, dataToSerial, position, LEN_FINGER);
        position += LEN_FINGER;
        // 4 bytes: child number. This is ser32(i) for i in xi = xpar/i, with xi the key being serialized. (0x00000000 if master key)
        Utils.uint32ToByteArrayBE(childnumber, dataToSerial, position);
        position += LEN_CHILDNUMBER;
        // 32 bytes: the chain code
        System.arraycopy(chainCode, 0, dataToSerial, position, LEN_CHAINCODE);
        position += LEN_CHAINCODE;
        // 33 bytes: the public key or private key data (serP(K) for public keys, 0x00 || ser256(k) for private keys)
//        System.out.println("pub:" + Hex.encode(getPub(true)));
        System.arraycopy(getPub(true), 0, dataToSerial, position, LEN_KEY);
        return Base58.base58check(PUBVERSION, dataToSerial);
    }

    /**
     * 根据父私钥获取子私钥
     * @param index
     * @param index 这里必须用long，java没有无符号整型
     * @return
     */
    public CExtKey derive(long index) throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] indexbytes = new byte[4];
        indexbytes[0] = (byte) ((index >>> 24) & 0xff);
        indexbytes[1] = (byte) ((index >>> 16) & 0xff);
        indexbytes[2] = (byte) ((index >>> 8) & 0xff);
        indexbytes[3] = (byte) (index & 0xff);

        byte[] hmachash = null;
        // 强化子密钥
        if (index > Integer.MAX_VALUE) {
            byte[] byteToHash = new byte[37];
            byteToHash[0] = 0;
            byte[] ppri = getPri();
            System.arraycopy(ppri, 0, byteToHash, 1, ppri.length);
            System.arraycopy(indexbytes, 0, byteToHash, 1 + ppri.length, indexbytes.length);
            hmachash = HMACSHA512.hash(chainCode, byteToHash);
        }
        // 普通子密钥
        else {
            byte[] ppub = this.getPub(true);
            byte[] byteToHash = new byte[37];
            System.arraycopy(ppub, 0, byteToHash, 0, ppub.length);
            System.arraycopy(indexbytes, 0, byteToHash, ppub.length, indexbytes.length);
            hmachash = HMACSHA512.hash(chainCode, byteToHash);
        }
        Assert.check(hmachash.length == 64, "hmacshah.length is not 64");
        byte[] cchiancode = Arrays.copyOfRange(hmachash, 32, 64);
        byte[] lefthandhash = Arrays.copyOfRange(hmachash, 0, 32);
        BigInteger privBigInteger = new BigInteger(1, lefthandhash).add(new BigInteger(1, getPri())).mod(CKey.curve.getN());
        byte[] priv = null;
        byte[] privbytes = privBigInteger.toByteArray();
        if (privbytes.length > 32) {
            priv = Arrays.copyOfRange(privbytes, privbytes.length - 32, privbytes.length);
        }
        else {
            priv = privbytes;
        }
        CExtKey child = new CExtKey(priv, cchiancode);
        child.setChildnumber(index);
        child.setDepth((byte)(this.depth + 1));
        child.setFingerprint(getMyFingerPrint());
        return child;
    }

    public byte[] getMyFingerPrint() {
        // RIPEMD160(SHA256(publickey))
        byte[] keyID = RIPEMD160.hash(Sha256Hash.hash(getPub(true)));
        return Arrays.copyOfRange(keyID, 0, 4);
    }


    public static void main(String args[]) {
        testParse();
    }

    public static void testParse() {
        String extPriKey = "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7";
        CExtKey cExtKey = CExtKey.parseFromExtPriKey(extPriKey);
        cExtKey.show();
        System.out.println(cExtKey.serialExtPubKey());
    }

    public void show() {
        System.out.println("depth       :" + depth);
        System.out.println("fingerprint :" + Hex.encode(this.fingerprint));
        System.out.println("childnumber :" + this.childnumber);
        System.out.println("chaincode   :" + Hex.encode(this.chainCode));
        System.out.println("pri         :" + Hex.encode(this.getPri()));
        System.out.println("pub         :" + Hex.encode(this.getPub(true)));
        System.out.println("serial priv :" + serialExtPriKey());
        System.out.println("serial pub  :" + serialExtPubKey());
    }

}
