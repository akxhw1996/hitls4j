package org.openhitls.crypto.core.asymmetric;

import org.openhitls.crypto.core.CryptoNative;
import org.openhitls.crypto.core.NativeResource;
import java.security.SecureRandom;

public class DSAImpl extends NativeResource {
    private byte[] publicKey;
    private byte[] privateKey;
    private final int keySize;
    private final int hashAlgorithm;

    public DSAImpl(int keySize) {
        this(keySize, 0);  // Default hash algorithm
    }

    public DSAImpl(int keySize, int hashAlgorithm) {
        super(initContext(), CryptoNative::dsaFreeContext);
        this.keySize = keySize;
        this.hashAlgorithm = hashAlgorithm;
        
        // Set key size before generating key pair
        byte[] seed = new byte[32];
        new SecureRandom().nextBytes(seed);
        CryptoNative.dsaGenerateParameters(nativeContext, keySize, seed);
        
        // Generate key pair
        byte[][] keyPair = CryptoNative.dsaGenerateKeyPair(nativeContext);
        setKeys(keyPair[0], keyPair[1]);
    }

    public DSAImpl(int keySize, byte[] publicKey, byte[] privateKey) {
        this(keySize, 0, publicKey, privateKey);
    }

    public DSAImpl(int keySize, int hashAlgorithm, byte[] publicKey, byte[] privateKey) {
        super(initContext(), CryptoNative::dsaFreeContext);
        this.keySize = keySize;
        this.hashAlgorithm = hashAlgorithm;
        setKeys(publicKey, privateKey);
    }

    private static long initContext() {
        return CryptoNative.dsaCreateContext();
    }

    void setKeys(byte[] publicKey, byte[] privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
        CryptoNative.dsaSetKeys(nativeContext, publicKey, privateKey);
    }

    public byte[] getPublicKey() {
        return publicKey;
    }

    public byte[] getPrivateKey() {
        return privateKey;
    }

    public long getNativeContext() {
        return nativeContext;
    }

    public void setParameters(byte[] p, byte[] q, byte[] g) {
        CryptoNative.dsaSetParameters(nativeContext, p, q, g);
    }

    /**
     * Signs data using DSA private key
     * @param data The data to sign
     * @return The signature
     * @throws RuntimeException if signing fails
     */
    public byte[] signData(byte[] data) {
        if (data == null) {
            throw new IllegalArgumentException("Input data cannot be null");
        }
        if (privateKey == null) {
            throw new IllegalStateException("Private key not initialized");
        }
        return CryptoNative.dsaSign(nativeContext, data, hashAlgorithm);
    }

    /**
     * Verifies a signature using DSA public key
     * @param data The original data
     * @param signature The signature to verify
     * @return true if signature is valid, false otherwise
     * @throws RuntimeException if verification fails
     */
    public boolean verifySignature(byte[] data, byte[] signature) {
        if (data == null || signature == null) {
            throw new IllegalArgumentException("Input data and signature cannot be null");
        }
        if (publicKey == null) {
            throw new IllegalStateException("Public key not initialized");
        }
        return CryptoNative.dsaVerify(nativeContext, data, signature, hashAlgorithm);
    }

    public int getKeySize() {
        return keySize;
    }
} 