package org.openhitls.crypto.jce.params;

import java.io.IOException;
import java.math.BigInteger;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.DSAParameterSpec;
import java.security.spec.InvalidParameterSpecException;

public class DSAParameters extends AlgorithmParametersSpi {
    private BigInteger p;
    private BigInteger q;
    private BigInteger g;

    public DSAParameters() {
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec paramSpec) throws InvalidParameterSpecException {
        if (!(paramSpec instanceof DSAParameterSpec)) {
            throw new InvalidParameterSpecException("Only DSAParameterSpec is supported");
        }
        DSAParameterSpec dsaSpec = (DSAParameterSpec) paramSpec;
        this.p = dsaSpec.getP();
        this.q = dsaSpec.getQ();
        this.g = dsaSpec.getG();
    }

    @Override
    protected void engineInit(byte[] params) throws IOException {
        throw new UnsupportedOperationException("Not implemented");
    }

    @Override
    protected void engineInit(byte[] params, String format) throws IOException {
        throw new UnsupportedOperationException("Not implemented");
    }

    @Override
    protected <T extends AlgorithmParameterSpec> T engineGetParameterSpec(Class<T> paramSpec)
            throws InvalidParameterSpecException {
        if (paramSpec.isAssignableFrom(DSAParameterSpec.class)) {
            return paramSpec.cast(new DSAParameterSpec(p, q, g));
        }
        throw new InvalidParameterSpecException("Only DSAParameterSpec is supported");
    }

    @Override
    protected byte[] engineGetEncoded() throws IOException {
        throw new UnsupportedOperationException("Not implemented");
    }

    @Override
    protected byte[] engineGetEncoded(String format) throws IOException {
        throw new UnsupportedOperationException("Not implemented");
    }

    @Override
    protected String engineToString() {
        return "DSA Parameters";
    }
} 