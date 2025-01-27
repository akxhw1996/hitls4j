package org.openhitls.crypto.jce.key.generator;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.DSAParameterSpec;

import org.openhitls.crypto.core.CryptoNative;
import org.openhitls.crypto.core.asymmetric.DSAImpl;
import org.openhitls.crypto.jce.key.HiTlsDSAPrivateKey;
import org.openhitls.crypto.jce.key.HiTlsDSAPublicKey;

public class DSAKeyPairGenerator extends KeyPairGeneratorSpi {
    private int keySize = 2048; // Default key size
    private boolean initialized = false;
    private DSAImpl dsaImpl;

    public DSAKeyPairGenerator() {
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
        
        // Create DSAImpl with key size based on parameter P's length
        int paramKeySize = dsaParams.getP().bitLength();
        dsaImpl = new DSAImpl(paramKeySize);
        
        // Set the parameters
        byte[] p = dsaParams.getP().toByteArray();
        byte[] q = dsaParams.getQ().toByteArray();
        byte[] g = dsaParams.getG().toByteArray();
        dsaImpl.setParameters(p, q, g);
        
        this.keySize = paramKeySize;
        this.initialized = true;
    }

    @Override
    public KeyPair generateKeyPair() {
        if (!initialized) {
            // Use default key size if not initialized
            initialize(keySize, null);
        }

        try {
            // Create DSAImpl if not already created
            if (dsaImpl == null) {
                dsaImpl = new DSAImpl(keySize);
            }
            
            // Get the parameters and keys
            byte[][] params = CryptoNative.dsaGetParameters(dsaImpl.getNativeContext());
            if (params == null || params.length != 3) {
                throw new RuntimeException("Failed to get DSA parameters");
            }

            // Create the public and private key objects
            HiTlsDSAPublicKey publicKey = new HiTlsDSAPublicKey(params[0], params[1], params[2], dsaImpl.getPublicKey());
            HiTlsDSAPrivateKey privateKey = new HiTlsDSAPrivateKey(params[0], params[1], params[2], dsaImpl.getPrivateKey());

            return new KeyPair(publicKey, privateKey);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to generate DSA key pair: " + e.getMessage(), e);
        }
    }
}