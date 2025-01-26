package org.openhitls.crypto.jce.key;

import java.math.BigInteger;
import java.security.interfaces.DSAPublicKey;

public class HiTlsDSAPublicKey extends HiTlsDSAKey implements DSAPublicKey {
    private static final long serialVersionUID = 1L;
    
    private BigInteger y;
    private byte[] encoded;

    public HiTlsDSAPublicKey(BigInteger p, BigInteger q, BigInteger g, BigInteger y, byte[] encoded) {
        super(p, q, g);
        this.y = y;
        this.encoded = encoded;
    }

    @Override
    public BigInteger getY() {
        return y;
    }

    @Override
    public String getAlgorithm() {
        return "DSA";
    }

    @Override
    public String getFormat() {
        return "X.509";
    }

    @Override
    public byte[] getEncoded() {
        return encoded.clone();
    }
} 