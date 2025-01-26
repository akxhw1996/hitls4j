package org.openhitls.crypto.core;

public class CryptoNative {
    // Hash native methods
    public static native long messageDigestInit(String algorithm);
    public static native void messageDigestUpdate(long contextPtr, byte[] data, int offset, int length);
    public static native byte[] messageDigestFinal(long contextPtr);
    public static native void messageDigestFree(long contextPtr);

    // HMAC native methods
    public static native long hmacInit(String algorithm, byte[] key);
    public static native void hmacUpdate(long contextPtr, byte[] data, int offset, int length);
    public static native byte[] hmacFinal(long contextPtr);
    public static native void hmacReinit(long contextPtr);
    public static native int hmacGetMacLength(long contextPtr);
    public static native void hmacFree(long contextPtr);

    // ECDSA native methods
    public static native long ecdsaCreateContext(String curveName);
    public static native void ecdsaFreeContext(long nativeRef);
    public static native void ecdsaSetKeys(long nativeRef, String curveName, byte[] publicKey, byte[] privateKey);
    public static native void ecdsaSetUserId(long nativeRef, byte[] userId);
    public static native byte[][] ecdsaGenerateKeyPair(long nativeRef, String curveName);
    public static native byte[] ecdsaEncrypt(long nativeRef, byte[] data);
    public static native byte[] ecdsaDecrypt(long nativeRef, byte[] encryptedData);
    public static native byte[] ecdsaSign(long nativeRef, byte[] data, int hashAlg);
    public static native boolean ecdsaVerify(long nativeRef, byte[] data, byte[] signature, int hashAlg);

    // SM4 native methods
    public static native long symmetricCipherInit(String algorithm, String cipherMode, byte[] key, byte[] iv, int mode);
    public static native void symmetricCipherSetPadding(long contextPtr, int paddingType);
    public static native void symmetricCipherUpdate(long contextPtr, byte[] input, int inputOffset, int inputLen,
                                             byte[] output, int outputOffset, int[] outLen);
    public static native byte[] symmetricCipherFinal(long contextPtr);
    public static native void symmetricCipherFree(long contextPtr);

    // DSA methods
    public static native long dsaCreateContext();
    public static native void dsaFreeContext(long context);
    public static native void dsaSetParameters(long context, byte[] p, byte[] q, byte[] g);
    public static native void dsaGenerateParameters(long context, int keySize, byte[] seed);
    public static native byte[][] dsaGenerateKeyPair(long context);
    public static native byte[][] dsaGetParameters(long context);
    public static native byte[][] dsaGetKeyValues(long context);
    public static native byte[] dsaSign(long context, byte[] hash, int hashAlgorithm);
    public static native boolean dsaVerify(long context, byte[] hash, byte[] signature, int hashAlgorithm);
    public static native void dsaSetKeys(long context, byte[] publicKey, byte[] privateKey);
} 