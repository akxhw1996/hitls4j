/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class org_openhitls_crypto_SM2 */

#ifndef _Included_org_openhitls_crypto_SM2
#define _Included_org_openhitls_crypto_SM2
#ifdef __cplusplus
extern "C" {
#endif

/*
 * Class:     org_openhitls_crypto_SM2
 * Method:    generateKeyPair
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_org_openhitls_crypto_SM2_generateKeyPair
  (JNIEnv *, jobject);

/*
 * Class:     org_openhitls_crypto_SM2
 * Method:    encrypt
 * Signature: ([B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_openhitls_crypto_SM2_encrypt
  (JNIEnv *, jobject, jbyteArray);

/*
 * Class:     org_openhitls_crypto_SM2
 * Method:    decrypt
 * Signature: ([B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_openhitls_crypto_SM2_decrypt
  (JNIEnv *, jobject, jbyteArray);

/*
 * Class:     org_openhitls_crypto_SM2
 * Method:    sign
 * Signature: ([B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_openhitls_crypto_SM2_sign
  (JNIEnv *, jobject, jbyteArray);

/*
 * Class:     org_openhitls_crypto_SM2
 * Method:    verify
 * Signature: ([B[B)Z
 */
JNIEXPORT jboolean JNICALL Java_org_openhitls_crypto_SM2_verify
  (JNIEnv *, jobject, jbyteArray, jbyteArray);

#ifdef __cplusplus
}
#endif
#endif 