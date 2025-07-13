package com.blubit;

import android.util.Base64;
import android.util.Log;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.security.KeyFactory;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.GCMParameterSpec;

public class CryptographyManager {
    private static final String TAG = "CryptographyManager";
    private static final String RSA_ALGORITHM = "RSA/ECB/PKCS1Padding";
    private static final String AES_ALGORITHM = "AES/GCM/NoPadding";
    private static final int RSA_KEY_SIZE = 2048;
    private static final int AES_KEY_SIZE = 256;
    
    private KeyPair rsaKeyPair;
    private SecretKey aesKey;
    
    public CryptographyManager() {
        generateRSAKeyPair();
        generateAESKey();
    }
    
    private void generateRSAKeyPair() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(RSA_KEY_SIZE);
            rsaKeyPair = keyPairGenerator.generateKeyPair();
            Log.d(TAG, "RSA key pair generated");
        } catch (Exception e) {
            Log.e(TAG, "Error generating RSA key pair", e);
        }
    }
    
    private void generateAESKey() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(AES_KEY_SIZE);
            aesKey = keyGenerator.generateKey();
            Log.d(TAG, "AES key generated");
        } catch (Exception e) {
            Log.e(TAG, "Error generating AES key", e);
        }
    }
    
    public String getPublicKeyString() {
        if (rsaKeyPair != null) {
            byte[] publicKeyBytes = rsaKeyPair.getPublic().getEncoded();
            return Base64.encodeToString(publicKeyBytes, Base64.DEFAULT);
        }
        return null;
    }
    
    public PublicKey getPublicKeyFromString(String publicKeyString) {
        try {
            byte[] publicKeyBytes = Base64.decode(publicKeyString, Base64.DEFAULT);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePublic(keySpec);
        } catch (Exception e) {
            Log.e(TAG, "Error converting string to public key", e);
            return null;
        }
    }
    
    public String encryptMessage(String message, PublicKey recipientPublicKey) {
        try {
            // Generate a random AES key for this message
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(AES_KEY_SIZE);
            SecretKey sessionKey = keyGen.generateKey();

            // Encrypt the message with AES-GCM
            Cipher aesCipher = Cipher.getInstance(AES_ALGORITHM);
            byte[] iv = new byte[12]; // 12 bytes is standard for GCM
            SecureRandom random = new SecureRandom();
            random.nextBytes(iv);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv); // 128-bit auth tag
            aesCipher.init(Cipher.ENCRYPT_MODE, sessionKey, gcmSpec);
            byte[] encryptedMessage = aesCipher.doFinal(message.getBytes(StandardCharsets.UTF_8));

            // Encrypt the AES key with RSA
            Cipher rsaCipher = Cipher.getInstance(RSA_ALGORITHM);
            rsaCipher.init(Cipher.ENCRYPT_MODE, recipientPublicKey);
            byte[] encryptedAESKey = rsaCipher.doFinal(sessionKey.getEncoded());

            // Combine encrypted AES key, IV, and encrypted message
            String encryptedKeyB64 = Base64.encodeToString(encryptedAESKey, Base64.DEFAULT);
            String ivB64 = Base64.encodeToString(iv, Base64.DEFAULT);
            String encryptedMessageB64 = Base64.encodeToString(encryptedMessage, Base64.DEFAULT);

            return encryptedKeyB64 + "|" + ivB64 + "|" + encryptedMessageB64;
        } catch (Exception e) {
            Log.e(TAG, "Error encrypting message", e);
            return null;
        }
    }

    public String decryptMessage(String encryptedData) {
        try {
            String[] parts = encryptedData.split("\\|");
            if (parts.length != 3) {
                Log.e(TAG, "Invalid encrypted data format");
                return null;
            }

            byte[] encryptedAESKey = Base64.decode(parts[0], Base64.DEFAULT);
            byte[] iv = Base64.decode(parts[1], Base64.DEFAULT);
            byte[] encryptedMessage = Base64.decode(parts[2], Base64.DEFAULT);

            // Decrypt the AES key with RSA
            Cipher rsaCipher = Cipher.getInstance(RSA_ALGORITHM);
            rsaCipher.init(Cipher.DECRYPT_MODE, rsaKeyPair.getPrivate());
            byte[] decryptedAESKey = rsaCipher.doFinal(encryptedAESKey);

            // Reconstruct AES key
            SecretKey sessionKey = new SecretKeySpec(decryptedAESKey, "AES");

            // Decrypt the message with AES-GCM
            Cipher aesCipher = Cipher.getInstance(AES_ALGORITHM);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
            aesCipher.init(Cipher.DECRYPT_MODE, sessionKey, gcmSpec);
            byte[] decryptedMessage = aesCipher.doFinal(encryptedMessage);

            return new String(decryptedMessage, StandardCharsets.UTF_8);
        } catch (Exception e) {
            Log.e(TAG, "Error decrypting message", e);
            return null;
        }
    }
    
    public String signMessage(String message) {
        try {
            Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, rsaKeyPair.getPrivate());
            byte[] signature = cipher.doFinal(message.getBytes());
            return Base64.encodeToString(signature, Base64.DEFAULT);
        } catch (Exception e) {
            Log.e(TAG, "Error signing message", e);
            return null;
        }
    }
    
    public boolean verifySignature(String message, String signature, PublicKey senderPublicKey) {
        try {
            byte[] signatureBytes = Base64.decode(signature, Base64.DEFAULT);
            Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, senderPublicKey);
            byte[] decryptedSignature = cipher.doFinal(signatureBytes);
            String decryptedMessage = new String(decryptedSignature);
            return message.equals(decryptedMessage);
        } catch (Exception e) {
            Log.e(TAG, "Error verifying signature", e);
            return false;
        }
    }
    
    /**
     * Get the current public key for this device
     * @return the public key
     */
    public PublicKey getPublicKey() {
        return rsaKeyPair.getPublic();
    }
    
    /**
     * Convert a public key to a string for transmission
     * @param publicKey the public key to convert
     * @return the key as a Base64 encoded string
     */
    public String getPublicKeyAsString(PublicKey publicKey) {
        try {
            return Base64.encodeToString(publicKey.getEncoded(), Base64.DEFAULT);
        } catch (Exception e) {
            Log.e(TAG, "Error converting public key to string: " + e.getMessage());
            return null;
        }
    }
}