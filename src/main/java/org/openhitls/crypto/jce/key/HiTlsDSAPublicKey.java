package org.openhitls.crypto.jce.key;

import java.math.BigInteger;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAParameterSpec;

public class HiTlsDSAPublicKey implements DSAPublicKey {
    private static final long serialVersionUID = 1L;
    
    private BigInteger y;  // public key value
    private BigInteger p;  // prime modulus
    private BigInteger q;  // prime divisor of p-1
    private BigInteger g;  // generator
    
    public HiTlsDSAPublicKey(byte[] p, byte[] q, byte[] g, byte[] y) {
        this.p = new BigInteger(1, p);
        this.q = new BigInteger(1, q);
        this.g = new BigInteger(1, g);
        this.y = new BigInteger(1, y);
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
        // TODO: Implement ASN.1 DER encoding
        return null;
    }
    
    @Override
    public BigInteger getY() {
        return y;
    }
    
    @Override
    public DSAParameterSpec getParams() {
        return new DSAParameterSpec(p, q, g);
    }

    public BigInteger getP() {
        return p;
    }

    public BigInteger getQ() {
        return q;
    }

    public BigInteger getG() {
        return g;
    }
} 