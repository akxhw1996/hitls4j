package org.openhitls.crypto.jce.key.generator;

import java.math.BigInteger;
import java.security.spec.DSAParameterSpec;
import org.openhitls.crypto.core.CryptoNative;

public class DSAParameters {
    private DSAParameters() {
        // Utility class, no instantiation
    }

    /**
     * Generates DSA parameters with specified sizes for P and Q
     * @param pSize size of P in bits (1024, 2048, or 3072)
     * @param qSize size of Q in bits (160 for 1024-bit P, 256 for 2048/3072-bit P)
     * @return DSAParameterSpec containing the generated parameters
     * @throws IllegalArgumentException if invalid sizes are provided
     */
    public static DSAParameterSpec generateParameters(int pSize, int qSize) {
        validateSizes(pSize, qSize);
        
        long context = CryptoNative.dsaCreateContext();

        // Generate parameters using OpenHiTLS
        CryptoNative.dsaGenerateParameters(context, pSize, null);
        byte[][] params = CryptoNative.dsaGetParameters(context);
        
        if (params == null || params.length != 3) {
            throw new IllegalStateException("Failed to generate DSA parameters");
        }
        
        // Convert parameters to BigInteger
        BigInteger p = new BigInteger(1, params[0]);
        BigInteger q = new BigInteger(1, params[1]);
        BigInteger g = new BigInteger(1, params[2]);
        
        return new DSAParameterSpec(p, q, g);

    }

    private static void validateSizes(int pSize, int qSize) {
        if (pSize != 1024 && pSize != 2048 && pSize != 3072) {
            throw new IllegalArgumentException("P size must be 1024, 2048, or 3072 bits");
        }
        
        if (pSize == 1024 && qSize != 160) {
            throw new IllegalArgumentException("Q size must be 160 bits for 1024-bit P");
        }
        
        if ((pSize == 2048 || pSize == 3072) && qSize != 256) {
            throw new IllegalArgumentException("Q size must be 256 bits for 2048/3072-bit P");
        }
    }
}
