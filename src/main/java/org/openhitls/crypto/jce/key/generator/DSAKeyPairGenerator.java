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
import org.openhitls.crypto.jce.key.generator.DSAParameters;

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

        try {
            // Generate parameters first
            int qSize = (keySize == 1024) ? 160 : 256;
            DSAParameterSpec params = DSAParameters.generateParameters(keySize, qSize);
            
            // Set the parameters
            byte[] p = params.getP().toByteArray();
            byte[] q = params.getQ().toByteArray();
            byte[] g = params.getG().toByteArray();
            CryptoNative.dsaSetParameters(context, p, q, g);

            // Generate the key pair
            byte[][] keyPair = CryptoNative.dsaGenerateKeyPair(context);
            if (keyPair == null || keyPair.length != 2) {
                throw new RuntimeException("Failed to generate DSA key pair");
            }

            // Create the public and private key objects
            HiTlsDSAPublicKey publicKey = new HiTlsDSAPublicKey(p, q, g, keyPair[0]);
            HiTlsDSAPrivateKey privateKey = new HiTlsDSAPrivateKey(p, q, g, keyPair[1]);

            return new KeyPair(publicKey, privateKey);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to generate DSA key pair: " + e.getMessage(), e);
        }
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