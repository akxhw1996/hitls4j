package org.openhitls.crypto.jce.signer;

import org.openhitls.crypto.core.CryptoNative;
import org.openhitls.crypto.jce.key.HiTlsDSAPrivateKey;
import org.openhitls.crypto.jce.key.HiTlsDSAPublicKey;

import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

public class DSASigner extends SignatureSpi {
    private long context;
    protected int hashAlgorithm;
    private boolean isInitialized;
    private MessageDigest messageDigest;

    protected DSASigner(String hashAlg) throws NoSuchAlgorithmException {
        this.context = CryptoNative.dsaCreateContext();
        this.messageDigest = MessageDigest.getInstance(hashAlg);
        this.isInitialized = false;
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        if (!(publicKey instanceof HiTlsDSAPublicKey)) {
            throw new InvalidKeyException("Key must be an instance of HiTlsDSAPublicKey");
        }
        HiTlsDSAPublicKey dsaKey = (HiTlsDSAPublicKey) publicKey;
        byte[] p = dsaKey.getP().toByteArray();
        byte[] q = dsaKey.getQ().toByteArray();
        byte[] g = dsaKey.getG().toByteArray();
        CryptoNative.dsaSetParameters(context, p, q, g);
        CryptoNative.dsaSetKeys(context, dsaKey.getEncoded(), null);
        messageDigest.reset();
        isInitialized = true;
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        if (!(privateKey instanceof HiTlsDSAPrivateKey)) {
            throw new InvalidKeyException("Key must be an instance of HiTlsDSAPrivateKey");
        }
        HiTlsDSAPrivateKey dsaKey = (HiTlsDSAPrivateKey) privateKey;
        byte[] p = dsaKey.getP().toByteArray();
        byte[] q = dsaKey.getQ().toByteArray();
        byte[] g = dsaKey.getG().toByteArray();
        CryptoNative.dsaSetParameters(context, p, q, g);
        CryptoNative.dsaSetKeys(context, null, dsaKey.getEncoded());
        messageDigest.reset();
        isInitialized = true;
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {
        if (!isInitialized) {
            throw new SignatureException("DSA is not initialized");
        }
        messageDigest.update(b);
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
        if (!isInitialized) {
            throw new SignatureException("DSA is not initialized");
        }
        messageDigest.update(b, off, len);
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        if (!isInitialized) {
            throw new SignatureException("DSA is not initialized");
        }
        byte[] hash = messageDigest.digest();
        return CryptoNative.dsaSign(context, hash, hashAlgorithm);
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        if (!isInitialized) {
            throw new SignatureException("DSA is not initialized");
        }
        byte[] hash = messageDigest.digest();
        return CryptoNative.dsaVerify(context, hash, sigBytes, hashAlgorithm);
    }

    @Override
    protected void engineSetParameter(AlgorithmParameterSpec params) throws InvalidAlgorithmParameterException {
        throw new UnsupportedOperationException("setParameter() not supported");
    }

    @Override
    protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
        throw new UnsupportedOperationException("setParameter() not supported");
    }

    @Override
    protected Object engineGetParameter(String param) throws InvalidParameterException {
        throw new UnsupportedOperationException("getParameter() not supported");
    }

    @Override
    protected void finalize() throws Throwable {
        try {
            if (context != 0) {
                CryptoNative.dsaFreeContext(context);
                context = 0;
            }
        } finally {
            super.finalize();
        }
    }

    public static final class SHA1withDSA extends DSASigner {
        private static final int HASH_ALG_SHA1 = 2;
        
        public SHA1withDSA() throws NoSuchAlgorithmException {
            super("SHA-1");
            this.hashAlgorithm = HASH_ALG_SHA1;
        }
    }

    public static final class SHA224withDSA extends DSASigner {
        private static final int HASH_ALG_SHA224 = 3;
        
        public SHA224withDSA() throws NoSuchAlgorithmException {
            super("SHA-224");
            this.hashAlgorithm = HASH_ALG_SHA224;
        }
    }

    public static final class SHA256withDSA extends DSASigner {
        private static final int HASH_ALG_SHA256 = 4;
        
        public SHA256withDSA() throws NoSuchAlgorithmException {
            super("SHA-256");
            this.hashAlgorithm = HASH_ALG_SHA256;
        }
    }

    public static final class SHA384withDSA extends DSASigner {
        private static final int HASH_ALG_SHA384 = 5;
        
        public SHA384withDSA() throws NoSuchAlgorithmException {
            super("SHA-384");
            this.hashAlgorithm = HASH_ALG_SHA384;
        }
    }

    public static final class SHA512withDSA extends DSASigner {
        private static final int HASH_ALG_SHA512 = 6;
        
        public SHA512withDSA() throws NoSuchAlgorithmException {
            super("SHA-512");
            this.hashAlgorithm = HASH_ALG_SHA512;
        }
    }
} 