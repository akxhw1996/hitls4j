package org.openhitls.crypto.jce.key;

import java.math.BigInteger;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAParameterSpec;

public class HiTlsDSAPublicKey implements DSAPublicKey {
    private static final long serialVersionUID = 1L;
    
    private final BigInteger y;  // public key
    private final DSAParameterSpec params;

    public HiTlsDSAPublicKey(BigInteger y, DSAParameterSpec params) {
        this.y = y;
        this.params = params;
    }

    @Override
    public BigInteger getY() {
        return y;
    }

    @Override
    public DSAParameterSpec getParams() {
        return params;
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
        // TODO: Implement X.509 encoding
        return null;
    }
} 