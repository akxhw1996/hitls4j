package org.openhitls.crypto.jce.keypair;

import org.openhitls.crypto.core.CryptoNative;
import org.openhitls.crypto.jce.key.HiTlsDSAPrivateKey;
import org.openhitls.crypto.jce.key.HiTlsDSAPublicKey;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.DSAParameterSpec;

public class DSAKeyPairGenerator extends KeyPairGeneratorSpi {
    private int keySize = 2048;
    private SecureRandom random;
    private DSAParameterSpec params;

    public DSAKeyPairGenerator() {
        this.random = new SecureRandom();
    }

    @Override
    public void initialize(int keySize, SecureRandom random) {
        if (keySize != 1024 && keySize != 2048 && keySize != 3072) {
            throw new InvalidParameterException("Key size must be 1024, 2048, or 3072 bits");
        }
        this.keySize = keySize;
        this.random = random;
        this.params = null;
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random) throws InvalidAlgorithmParameterException {
        if (!(params instanceof DSAParameterSpec)) {
            throw new InvalidAlgorithmParameterException("Only DSAParameterSpec is supported");
        }
        this.params = (DSAParameterSpec) params;
        this.random = random;
    }

    @Override
    public KeyPair generateKeyPair() {
        long context = CryptoNative.dsaCreateContext();
        try {
            byte[] seed = new byte[32];
            random.nextBytes(seed);

            if (params == null) {
                // Generate parameters
                CryptoNative.dsaGenerateParameters(context, keySize, seed);
            } else {
                // Use provided parameters
                byte[] p = params.getP().toByteArray();
                byte[] q = params.getQ().toByteArray();
                byte[] g = params.getG().toByteArray();
                CryptoNative.dsaSetParameters(context, p, q, g);
            }

            // Generate key pair
            byte[][] keyPair = CryptoNative.dsaGenerateKeyPair(context);
            byte[] pubKeyEncoded = keyPair[0];
            byte[] privKeyEncoded = keyPair[1];

            // Get parameters from context
            byte[][] dsaParams = CryptoNative.dsaGetParameters(context);
            BigInteger p = new BigInteger(1, dsaParams[0]);
            BigInteger q = new BigInteger(1, dsaParams[1]);
            BigInteger g = new BigInteger(1, dsaParams[2]);

            // Get public and private values
            byte[][] keyValues = CryptoNative.dsaGetKeyValues(context);
            BigInteger y = new BigInteger(1, keyValues[0]); // public value
            BigInteger x = new BigInteger(1, keyValues[1]); // private value

            PublicKey publicKey = new HiTlsDSAPublicKey(p, q, g, y, pubKeyEncoded);
            PrivateKey privateKey = new HiTlsDSAPrivateKey(p, q, g, x, privKeyEncoded);

            return new KeyPair(publicKey, privateKey);
        } finally {
            CryptoNative.dsaFreeContext(context);
        }
    }
} 