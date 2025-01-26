package org.openhitls.crypto.jce.key;

import java.math.BigInteger;
import java.security.interfaces.DSAKey;
import java.security.interfaces.DSAParams;

public abstract class HiTlsDSAKey implements DSAKey {
    protected BigInteger p;
    protected BigInteger q;
    protected BigInteger g;

    protected HiTlsDSAKey(BigInteger p, BigInteger q, BigInteger g) {
        this.p = p;
        this.q = q;
        this.g = g;
    }

    @Override
    public DSAParams getParams() {
        return new DSAParams() {
            @Override
            public BigInteger getP() {
                return p;
            }

            @Override
            public BigInteger getQ() {
                return q;
            }

            @Override
            public BigInteger getG() {
                return g;
            }
        };
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