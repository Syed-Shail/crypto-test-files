import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.Base64;

/**
 * Comprehensive Java Cryptography Test
 * For IBM CBOMKit comparison
 * 
 * Expected detections: 25+ cryptographic algorithms
 */
public class ComprehensiveCryptoTest {
    
    // === HASH FUNCTIONS ===
    
    /**
     * MD5 - BROKEN (HIGH RISK)
     */
    public static String hashWithMD5(String data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] hash = md.digest(data.getBytes());
        return Base64.getEncoder().encodeToString(hash);
    }
    
    /**
     * SHA-1 - DEPRECATED (HIGH RISK)
     */
    public static String hashWithSHA1(String data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] hash = md.digest(data.getBytes());
        return Base64.getEncoder().encodeToString(hash);
    }
    
    /**
     * SHA-256 - SECURE (LOW RISK)
     */
    public static String hashWithSHA256(String data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(data.getBytes());
        return Base64.getEncoder().encodeToString(hash);
    }
    
    /**
     * SHA-512 - SECURE (LOW RISK)
     */
    public static String hashWithSHA512(String data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-512");
        byte[] hash = md.digest(data.getBytes());
        return Base64.getEncoder().encodeToString(hash);
    }
    
    /**
     * SHA3-256 - MODERN (LOW RISK)
     */
    public static String hashWithSHA3_256(String data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA3-256");
        byte[] hash = md.digest(data.getBytes());
        return Base64.getEncoder().encodeToString(hash);
    }
    
    // === SYMMETRIC ENCRYPTION ===
    
    /**
     * AES-GCM - SECURE (LOW RISK)
     */
    public static byte[] encryptAES_GCM(String plaintext, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        return cipher.doFinal(plaintext.getBytes());
    }
    
    /**
     * AES-CBC - SECURE (LOW RISK)
     */
    public static byte[] encryptAES_CBC(String plaintext, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(plaintext.getBytes());
    }
    
    /**
     * AES-ECB - WEAK (MEDIUM RISK)
     */
    public static byte[] encryptAES_ECB(String plaintext, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(plaintext.getBytes());
    }
    
    /**
     * DES - BROKEN (HIGH RISK)
     */
    public static byte[] encryptDES(String plaintext, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(plaintext.getBytes());
    }
    
    /**
     * TripleDES/3DES - DEPRECATED (HIGH RISK)
     */
    public static byte[] encryptTripleDES(String plaintext, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(plaintext.getBytes());
    }
    
    /**
     * Blowfish - OUTDATED (HIGH RISK)
     */
    public static byte[] encryptBlowfish(String plaintext, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("Blowfish/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(plaintext.getBytes());
    }
    
    /**
     * RC4 - BROKEN (HIGH RISK)
     */
    public static byte[] encryptRC4(String plaintext, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("RC4");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(plaintext.getBytes());
    }
    
    /**
     * ChaCha20 - MODERN (LOW RISK)
     */
    public static byte[] encryptChaCha20(String plaintext, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("ChaCha20");
        byte[] nonce = new byte[12];
        new SecureRandom().nextBytes(nonce);
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(nonce));
        return cipher.doFinal(plaintext.getBytes());
    }
    
    // === ASYMMETRIC CRYPTOGRAPHY ===
    
    /**
     * RSA - QUANTUM-VULNERABLE (HIGH RISK)
     */
    public static KeyPair generateRSAKeyPair(int keySize) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(keySize);
        return keyGen.generateKeyPair();
    }
    
    public static byte[] encryptRSA(String plaintext, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(plaintext.getBytes());
    }
    
    public static byte[] signRSA(String message, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(message.getBytes());
        return signature.sign();
    }
    
    /**
     * DSA - QUANTUM-VULNERABLE (HIGH RISK)
     */
    public static KeyPair generateDSAKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }
    
    public static byte[] signDSA(String message, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withDSA");
        signature.initSign(privateKey);
        signature.update(message.getBytes());
        return signature.sign();
    }
    
    /**
     * ECDSA - QUANTUM-VULNERABLE (HIGH RISK)
     */
    public static KeyPair generateECDSAKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
        keyGen.initialize(ecSpec);
        return keyGen.generateKeyPair();
    }
    
    public static byte[] signECDSA(String message, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(privateKey);
        signature.update(message.getBytes());
        return signature.sign();
    }
    
    /**
     * Diffie-Hellman - QUANTUM-VULNERABLE (HIGH RISK)
     */
    public static KeyPair generateDHKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }
    
    // === MESSAGE AUTHENTICATION CODES ===
    
    /**
     * HMAC-SHA256 - SECURE (LOW RISK)
     */
    public static byte[] hmacSHA256(String message, SecretKey key) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(key);
        return mac.doFinal(message.getBytes());
    }
    
    /**
     * HMAC-SHA512 - SECURE (LOW RISK)
     */
    public static byte[] hmacSHA512(String message, SecretKey key) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA512");
        mac.init(key);
        return mac.doFinal(message.getBytes());
    }
    
    /**
     * HMAC-MD5 - WEAK (MEDIUM RISK)
     */
    public static byte[] hmacMD5(String message, SecretKey key) throws Exception {
        Mac mac = Mac.getInstance("HmacMD5");
        mac.init(key);
        return mac.doFinal(message.getBytes());
    }
    
    // === KEY DERIVATION ===
    
    /**
     * PBKDF2 - Password-based Key Derivation
     */
    public static byte[] deriveKeyPBKDF2(String password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 100000, 256);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        return factory.generateSecret(spec).getEncoded();
    }
    
    // === SECURE RANDOM ===
    
    /**
     * Secure Random Number Generation
     */
    public static byte[] generateSecureRandom(int length) {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return bytes;
    }
    
    public static byte[] generateSecureRandomSHA1PRNG(int length) throws Exception {
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return bytes;
    }
    
    // === MAIN TEST ===
    
    public static void main(String[] args) {
        System.out.println("Comprehensive Java Cryptography Test");
        System.out.println("=" + "=".repeat(50));
        
        try {
            // Hash functions
            System.out.println("\n[HASH FUNCTIONS]");
            System.out.println("MD5: " + hashWithMD5("test"));
            System.out.println("SHA-1: " + hashWithSHA1("test"));
            System.out.println("SHA-256: " + hashWithSHA256("test"));
            System.out.println("SHA-512: " + hashWithSHA512("test"));
            
            // Symmetric encryption
            System.out.println("\n[SYMMETRIC ENCRYPTION]");
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            SecretKey aesKey = keyGen.generateKey();
            
            System.out.println("AES-GCM: Testing");
            System.out.println("AES-CBC: Testing");
            System.out.println("AES-ECB: Testing (WEAK)");
            System.out.println("DES: Testing (BROKEN)");
            System.out.println("3DES: Testing (DEPRECATED)");
            System.out.println("Blowfish: Testing (OUTDATED)");
            System.out.println("ChaCha20: Testing (MODERN)");
            
            // Asymmetric cryptography
            System.out.println("\n[ASYMMETRIC CRYPTOGRAPHY]");
            KeyPair rsaKeyPair = generateRSAKeyPair(2048);
            System.out.println("RSA-2048: Generated (QUANTUM-VULNERABLE)");
            
            KeyPair dsaKeyPair = generateDSAKeyPair();
            System.out.println("DSA-2048: Generated (QUANTUM-VULNERABLE)");
            
            KeyPair ecdsaKeyPair = generateECDSAKeyPair();
            System.out.println("ECDSA: Generated (QUANTUM-VULNERABLE)");
            
            KeyPair dhKeyPair = generateDHKeyPair();
            System.out.println("Diffie-Hellman: Generated (QUANTUM-VULNERABLE)");
            
            // MACs
            System.out.println("\n[MESSAGE AUTHENTICATION]");
            System.out.println("HMAC-SHA256: Testing");
            System.out.println("HMAC-SHA512: Testing");
            System.out.println("HMAC-MD5: Testing (WEAK)");
            
            // Key derivation
            System.out.println("\n[KEY DERIVATION]");
            System.out.println("PBKDF2: Testing");
            
            System.out.println("\n" + "=".repeat(50));
            System.out.println("Test complete!");
            System.out.println("\nExpected detections: 25+ cryptographic algorithms");
            System.out.println("High Risk: MD5, SHA-1, DES, 3DES, Blowfish, RC4, RSA, DSA, ECDSA, DH");
            System.out.println("Medium Risk: AES-ECB, HMAC-MD5");
            System.out.println("Low Risk: SHA-256, SHA-512, AES-GCM, AES-CBC, ChaCha20, HMAC-SHA256/512");
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
