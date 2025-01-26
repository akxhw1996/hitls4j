package org.openhitls.crypto.jce.key;

import java.math.BigInteger;
import java.security.interfaces.DSAPrivateKey;
import java.security.spec.DSAParameterSpec;

public class HiTlsDSAPrivateKey implements DSAPrivateKey {
    private static final long serialVersionUID = 1L;
    
    private final BigInteger x;  // private key
    private final DSAParameterSpec params;

    public HiTlsDSAPrivateKey(BigInteger x, DSAParameterSpec params) {
        this.x = x;
        this.params = params;
    }

    @Override
    public BigInteger getX() {
        return x;
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
        return "PKCS#8";
    }

    @Override
    public byte[] getEncoded() {
        // TODO: Implement PKCS#8 encoding
        return null;
    }
} 