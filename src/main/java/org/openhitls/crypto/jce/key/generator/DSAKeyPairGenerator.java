package org.openhitls.crypto.jce.key.generator;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.DSAParameterSpec;

import org.openhitls.crypto.core.CryptoNative;
import org.openhitls.crypto.jce.key.HiTlsDSAPrivateKey;
import org.openhitls.crypto.jce.key.HiTlsDSAPublicKey;

public class DSAKeyPairGenerator extends KeyPairGeneratorSpi {
    private int keySize = 2048; // Default key size
    private long context;
    private boolean initialized = false;

    public DSAKeyPairGenerator() {
        context = CryptoNative.dsaCreateContext();
    }

    @Override
    public void initialize(int keySize, SecureRandom random) {
        if (keySize != 1024 && keySize != 2048 && keySize != 3072) {
            throw new InvalidParameterException("DSA key size must be 1024, 2048, or 3072");
        }
        this.keySize = keySize;
        this.initialized = true;
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        if (!(params instanceof DSAParameterSpec)) {
            throw new InvalidAlgorithmParameterException("Only DSAParameterSpec is supported");
        }
        DSAParameterSpec dsaParams = (DSAParameterSpec) params;
        
        // Set the parameters in the native context
        byte[] p = dsaParams.getP().toByteArray();
        byte[] q = dsaParams.getQ().toByteArray();
        byte[] g = dsaParams.getG().toByteArray();
        CryptoNative.dsaSetParameters(context, p, q, g);
        
        // Set key size based on parameter P's length
        this.keySize = dsaParams.getP().bitLength();
        this.initialized = true;
    }

    @Override
    public KeyPair generateKeyPair() {
        if (!initialized) {
            // Use default key size if not initialized
            initialize(keySize, null);
        }

        // Generate parameters first
        CryptoNative.dsaGenerateParameters(context, keySize, null);

        // Get the parameters
        byte[][] params = CryptoNative.dsaGetParameters(context);
        if (params == null || params.length != 3) {
            throw new RuntimeException("Failed to get DSA parameters");
        }

        // Generate the key pair
        byte[][] keyPair = CryptoNative.dsaGenerateKeyPair(context);
        if (keyPair == null || keyPair.length != 2) {
            throw new RuntimeException("Failed to generate DSA key pair");
        }

        // Create the public and private key objects
        HiTlsDSAPublicKey publicKey = new HiTlsDSAPublicKey(params[0], params[1], params[2], keyPair[0]);
        HiTlsDSAPrivateKey privateKey = new HiTlsDSAPrivateKey(params[0], params[1], params[2], keyPair[1]);

        return new KeyPair(publicKey, privateKey);
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
} 