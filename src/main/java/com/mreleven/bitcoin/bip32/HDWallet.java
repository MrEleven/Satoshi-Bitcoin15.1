package com.mreleven.bitcoin.bip32;

import com.sun.tools.javac.util.Assert;
import org.spongycastle.util.encoders.Hex;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * 分层确定性钱包
 *
 * @author eleven@creditfolder.io
 * @since 2018年04月17日 14:54
 */
public class HDWallet {
    private CExtKey master;
    private static final String MASTER_HMACSHA512_KEY = "Bitcoin seed";

    public HDWallet(byte[] seed) throws Exception {
        init(seed);
    }

    public CExtKey getExtKey(String path) throws NoSuchAlgorithmException, InvalidKeyException {
        String[] pathList = path.split("/");
        CExtKey result = master;
        for (int i = 1; i < pathList.length; i++) {
            String tempPath = pathList[i];
            if (tempPath.toUpperCase().contains("H")) {
                long index = Long.parseLong(tempPath.substring(0, tempPath.length() - 1));
                result = result.derive(index + Integer.MAX_VALUE + 1L);
            }
            else {
                result = result.derive(Long.parseLong(tempPath));
            }
        }
        return result;
    }

    /**
     * 通过种子生成master密钥
     * @param seed
     * @throws Exception
     */
    private void init(byte[] seed) throws Exception {
        byte[] pri = new byte[32];
        byte[] chaincode = new byte[32];
        byte[] hash = HMACSHA512.hash(MASTER_HMACSHA512_KEY.getBytes(), seed);
        Assert.check(hash.length == 64, "hash length error");
        System.arraycopy(hash, 0, pri, 0, 32);
        System.arraycopy(hash, 32, chaincode, 0, 32);
        this.master = new CExtKey(pri, chaincode);
        this.master.setDepth((byte)0);
        this.master.setFingerprint(Hex.decode("00000000"));
        this.master.setChildnumber(0);
    }
}
