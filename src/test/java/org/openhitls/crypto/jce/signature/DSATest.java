package org.openhitls.crypto.jce.signature;

import org.junit.BeforeClass;
import org.junit.Test;
import org.openhitls.crypto.BaseTest;
import org.openhitls.crypto.jce.provider.HiTls4jProvider;
import org.openhitls.crypto.jce.key.HiTlsDSAPrivateKey;
import org.openhitls.crypto.jce.param.DSAParameters;

import javax.crypto.KeyGenerator;
import java.security.*;
import java.security.spec.DSAParameterSpec;
import java.nio.charset.StandardCharsets;

import static org.junit.Assert.*;

public class DSATest extends BaseTest {
    
    @BeforeClass
    public static void setUp() {
        Security.addProvider(new HiTls4jProvider());
    }

    private KeyPair generateKeyPair(int keySize) throws Exception {
        System.out.println("[DEBUG] Generating DSA key pair with size: " + keySize);
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", HiTls4jProvider.PROVIDER_NAME);
        System.out.println("[DEBUG] KeyPairGenerator created successfully");
        keyGen.initialize(keySize);
        System.out.println("[DEBUG] KeyPairGenerator initialized with size: " + keySize);
        KeyPair keyPair = keyGen.generateKeyPair();
        System.out.println("[DEBUG] Key pair generated successfully");
        return keyPair;
    }

    private KeyPair generateSunKeyPair(int keySize) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", "SUN");
        keyGen.initialize(keySize);
        return keyGen.generateKeyPair();
    }

    @Test
    public void testKeyGeneration() throws Exception {
        // Test key pair generation with different key sizes
        int[] keySizes = {1024, 2048, 3072};
        for (int keySize : keySizes) {
            System.out.println("\n[DEBUG] Testing key size: " + keySize);
            KeyPair keyPair = generateKeyPair(keySize);
            assertNotNull("Private key should not be null", keyPair.getPrivate());
            assertNotNull("Public key should not be null", keyPair.getPublic());
            assertEquals("Key size should match", keySize, ((HiTlsDSAPrivateKey)keyPair.getPrivate()).getParams().getP().bitLength());
        }
    }

    // @Test
    // public void testSignAndVerify() throws Exception {
    //     // Test signing and verification with different hash algorithms
    //     String[] hashAlgs = {"SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512"};
    //     for (String hashAlg : hashAlgs) {
    //         KeyPair keyPair = generateKeyPair(2048);
    //         Signature signer = Signature.getInstance("DSAwith" + hashAlg, HiTls4jProvider.PROVIDER_NAME);
            
    //         // Sign data
    //         byte[] data = "Test data for DSA signing".getBytes(StandardCharsets.UTF_8);
    //         signer.initSign(keyPair.getPrivate());
    //         signer.update(data);
    //         byte[] signature = signer.sign();

    //         // Verify signature
    //         signer.initVerify(keyPair.getPublic());
    //         signer.update(data);
    //         assertTrue("Signature verification should succeed", signer.verify(signature));
    //     }
    // }

    // @Test
    // public void testInvalidSignatures() throws Exception {
    //     KeyPair keyPair = generateKeyPair(2048);
    //     Signature signer = Signature.getInstance("DSAwithSHA256", HiTls4jProvider.PROVIDER_NAME);
        
    //     byte[] data = "Original data".getBytes(StandardCharsets.UTF_8);
    //     signer.initSign(keyPair.getPrivate());
    //     signer.update(data);
    //     byte[] signature = signer.sign();

    //     // Test with modified data
    //     byte[] tamperedData = "Modified data".getBytes(StandardCharsets.UTF_8);
    //     signer.initVerify(keyPair.getPublic());
    //     signer.update(tamperedData);
    //     assertFalse("Signature verification should fail with modified data", signer.verify(signature));

    //     // Test with modified signature
    //     signature[0] ^= 1;  // Flip one bit
    //     signer.initVerify(keyPair.getPublic());
    //     signer.update(data);
    //     assertFalse("Signature verification should fail with modified signature", signer.verify(signature));
    // }

    // @Test
    // public void testParameterGeneration() throws Exception {
    //     // Test DSA parameter generation
    //     DSAParameterSpec params = DSAParameters.generateParameters(2048, 256);
    //     assertNotNull("P parameter should not be null", params.getP());
    //     assertNotNull("Q parameter should not be null", params.getQ());
    //     assertNotNull("G parameter should not be null", params.getG());
    //     assertEquals("P size should be 2048 bits", 2048, params.getP().bitLength());
    //     assertEquals("Q size should be 256 bits", 256, params.getQ().bitLength());
    // }

    // @Test(expected = InvalidKeyException.class)
    // public void testInvalidKeySize() throws Exception {
    //     // Test invalid key size
    //     KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", HiTls4jProvider.PROVIDER_NAME);
    //     keyGen.initialize(1536);  // Invalid key size
    // }

    // @Test
    // public void testInteroperability() throws Exception {
    //     // Test interoperability with SUN provider
    //     KeyPair sunKeyPair = generateSunKeyPair(2048);
    //     Signature hitlsSigner = Signature.getInstance("DSAwithSHA256", HiTls4jProvider.PROVIDER_NAME);
    //     Signature sunSigner = Signature.getInstance("DSAwithSHA256", "SUN");
        
    //     // Sign with SUN, verify with HiTls4j
    //     byte[] data = "Interop test data".getBytes(StandardCharsets.UTF_8);
    //     sunSigner.initSign(sunKeyPair.getPrivate());
    //     sunSigner.update(data);
    //     byte[] signature = sunSigner.sign();

    //     hitlsSigner.initVerify(sunKeyPair.getPublic());
    //     hitlsSigner.update(data);
    //     assertTrue("HiTls4j should verify SUN signature", hitlsSigner.verify(signature));

    //     // Sign with HiTls4j, verify with SUN
    //     KeyPair hitlsKeyPair = generateKeyPair(2048);
    //     hitlsSigner.initSign(hitlsKeyPair.getPrivate());
    //     hitlsSigner.update(data);
    //     signature = hitlsSigner.sign();

    //     sunSigner.initVerify(hitlsKeyPair.getPublic());
    //     sunSigner.update(data);
    //     assertTrue("SUN should verify HiTls4j signature", sunSigner.verify(signature));
    // }

    // @Test
    // public void testMultipleUpdates() throws Exception {
    //     KeyPair keyPair = generateKeyPair(2048);
    //     Signature signer = Signature.getInstance("DSAwithSHA256", HiTls4jProvider.PROVIDER_NAME);
        
    //     // Sign with multiple updates
    //     signer.initSign(keyPair.getPrivate());
    //     signer.update("Part 1 ".getBytes(StandardCharsets.UTF_8));
    //     signer.update("Part 2 ".getBytes(StandardCharsets.UTF_8));
    //     signer.update("Part 3".getBytes(StandardCharsets.UTF_8));
    //     byte[] signature = signer.sign();

    //     // Verify with multiple updates
    //     signer.initVerify(keyPair.getPublic());
    //     signer.update("Part 1 ".getBytes(StandardCharsets.UTF_8));
    //     signer.update("Part 2 ".getBytes(StandardCharsets.UTF_8));
    //     signer.update("Part 3".getBytes(StandardCharsets.UTF_8));
    //     assertTrue("Signature verification should succeed with multiple updates", signer.verify(signature));
    // }

    // @Test
    // public void testLargeData() throws Exception {
    //     KeyPair keyPair = generateKeyPair(2048);
    //     Signature signer = Signature.getInstance("DSAwithSHA256", HiTls4jProvider.PROVIDER_NAME);
        
    //     // Generate 1MB of random data
    //     byte[] largeData = new byte[1024 * 1024];
    //     new SecureRandom().nextBytes(largeData);

    //     // Sign large data
    //     signer.initSign(keyPair.getPrivate());
    //     signer.update(largeData);
    //     byte[] signature = signer.sign();

    //     // Verify large data
    //     signer.initVerify(keyPair.getPublic());
    //     signer.update(largeData);
    //     assertTrue("Signature verification should succeed with large data", signer.verify(signature));
    // }

    // @Test
    // public void testThreadSafety() throws Exception {
    //     final int threadCount = 10;
    //     final KeyPair keyPair = generateKeyPair(2048);
    //     final byte[] data = "Test data for thread safety".getBytes(StandardCharsets.UTF_8);
        
    //     Thread[] threads = new Thread[threadCount];
    //     final boolean[] results = new boolean[threadCount];

    //     for (int i = 0; i < threadCount; i++) {
    //         final int threadIndex = i;
    //         threads[i] = new Thread(() -> {
    //             try {
    //                 Signature signer = Signature.getInstance("DSAwithSHA256", HiTls4jProvider.PROVIDER_NAME);
    //                 signer.initSign(keyPair.getPrivate());
    //                 signer.update(data);
    //                 byte[] signature = signer.sign();

    //                 signer.initVerify(keyPair.getPublic());
    //                 signer.update(data);
    //                 results[threadIndex] = signer.verify(signature);
    //             } catch (Exception e) {
    //                 results[threadIndex] = false;
    //             }
    //         });
    //         threads[i].start();
    //     }

    //     for (Thread thread : threads) {
    //         thread.join();
    //     }

    //     for (boolean result : results) {
    //         assertTrue("All thread operations should succeed", result);
    //     }
    // }
} 