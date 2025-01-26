package org.openhitls.crypto.jce.key;

import java.math.BigInteger;
import java.security.interfaces.DSAPrivateKey;

public class HiTlsDSAPrivateKey extends HiTlsDSAKey implements DSAPrivateKey {
    private static final long serialVersionUID = 1L;
    
    private BigInteger x;
    private byte[] encoded;

    public HiTlsDSAPrivateKey(BigInteger p, BigInteger q, BigInteger g, BigInteger x, byte[] encoded) {
        super(p, q, g);
        this.x = x;
        this.encoded = encoded;
    }

    @Override
    public BigInteger getX() {
        return x;
    }

    @Override
    public String getAlgorithm() {
        return "DSA";
    }

    @Override
    public String getFormat() {
        return "PKCS#8";
    }

    @Override
    public byte[] getEncoded() {
        return encoded.clone();
    }
} 