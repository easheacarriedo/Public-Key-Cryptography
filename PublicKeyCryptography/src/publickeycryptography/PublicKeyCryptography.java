package cryptography;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * This class provides functionality for Public Key Cryptography.
 */
public class PublicKeyCryptography {

    /**
     * Generates a pair of public and private keys using the RSA algorithm.
     *
     * @param keySize The size of the key to be generated.
     * @return Returns a KeyPair object containing the generated public and private keys.
     * @throws NoSuchAlgorithmException if the RSA algorithm is not available.
     */
    public static KeyPair generateKeyPair(int keySize) throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keySize);
        return keyPairGenerator.generateKeyPair();
    }

    /**
     * Encrypts a message using the public key.
     *
     * @param message   The message to be encrypted.
     * @param publicKey The public key used for encryption.
     * @return Returns the encrypted message as a BigInteger.
     */
    public static BigInteger encrypt(String message, PublicKey publicKey) {
        byte[] messageBytes = message.getBytes();
        BigInteger messageInt = new BigInteger(messageBytes);
        BigInteger encryptedMessage = messageInt.modPow(((java.security.interfaces.RSAPublicKey) publicKey).getPublicExponent(),
                ((java.security.interfaces.RSAPublicKey) publicKey).getModulus());
        return encryptedMessage;
    }

    /**
     * Decrypts an encrypted message using the private key.
     *
     * @param encryptedMessage The encrypted message to be decrypted.
     * @param privateKey       The private key used for decryption.
     * @return Returns the decrypted message as a String.
     */
    public static String decrypt(BigInteger encryptedMessage, PrivateKey privateKey) {
        BigInteger decryptedMessage = encryptedMessage.modPow(((java.security.interfaces.RSAPrivateKey) privateKey).getPrivateExponent(),
                ((java.security.interfaces.RSAPrivateKey) privateKey).getModulus());
        byte[] decryptedMessageBytes = decryptedMessage.toByteArray();
        String decryptedMessageString = new String(decryptedMessageBytes);
        return decryptedMessageString;
    }

    /**
     * Main method to demonstrate the usage of the PublicKeyCryptography class.
     */
    public static void main(String[] args) {
        try {
            // Generate key pair
            KeyPair keyPair = generateKeyPair(1024);
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();

            // Encrypt and decrypt a message
            String message = "Hello, World!";
            BigInteger encryptedMessage = encrypt(message, publicKey);
            String decryptedMessage = decrypt(encryptedMessage, privateKey);

            // Print the original and decrypted messages
            System.out.println("Original Message: " + message);
            System.out.println("Encrypted Message: " + encryptedMessage);
            System.out.println("Decrypted Message: " + decryptedMessage);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }
}
