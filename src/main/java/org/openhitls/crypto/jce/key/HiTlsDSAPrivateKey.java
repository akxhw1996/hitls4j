package org.openhitls.crypto.jce.key;

import java.math.BigInteger;
import java.security.interfaces.DSAPrivateKey;
import java.security.spec.DSAParameterSpec;

public class HiTlsDSAPrivateKey implements DSAPrivateKey {
    private static final long serialVersionUID = 1L;
    
    private BigInteger x;  // private key value
    private BigInteger p;  // prime modulus
    private BigInteger q;  // prime divisor of p-1
    private BigInteger g;  // generator
    
    public HiTlsDSAPrivateKey(byte[] p, byte[] q, byte[] g, byte[] x) {
        this.p = new BigInteger(1, p);
        this.q = new BigInteger(1, q);
        this.g = new BigInteger(1, g);
        this.x = new BigInteger(1, x);
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
        // TODO: Implement ASN.1 DER encoding
        return null;
    }
    
    @Override
    public BigInteger getX() {
        return x;
    }
    
    @Override
    public DSAParameterSpec getParams() {
        return new DSAParameterSpec(p, q, g);
    }
} 