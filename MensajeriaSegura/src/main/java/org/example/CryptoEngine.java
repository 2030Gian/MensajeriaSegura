package org.example;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.crypto.digests.SHA256Digest;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.Arrays;

public class CryptoEngine {

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public static KeyPair generateX25519KeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("X25519", "BC");
        return generator.generateKeyPair();
    }

    public static KeyPair generateEd25519KeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("Ed25519", "BC");
        return generator.generateKeyPair();
    }

    public static byte[] generateSalt() {
        byte[] salt = new byte[32];
        new SecureRandom().nextBytes(salt);
        return salt;
    }

    public static byte[] performKeyExchange(PrivateKey myPrivateKey, PublicKey otherPublicKey, byte[] salt) throws Exception {
        KeyAgreement agreement = KeyAgreement.getInstance("X25519", "BC");
        agreement.init(myPrivateKey);
        agreement.doPhase(otherPublicKey, true);
        byte[] rawSecret = agreement.generateSecret();

        return deriveKeyHKDF(rawSecret, salt);
    }

    private static byte[] deriveKeyHKDF(byte[] inputKeyMaterial, byte[] salt) {
        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
        byte[] infoContext = "MensajeriaSegura_v1_AES_Key".getBytes();
        hkdf.init(new HKDFParameters(inputKeyMaterial, salt, infoContext));

        byte[] aesKey = new byte[32];
        hkdf.generateBytes(aesKey, 0, 32);
        return aesKey;
    }

    public static byte[] signData(PrivateKey signingKey, byte[] dataToSign) throws Exception {
        Signature signature = Signature.getInstance("Ed25519", "BC");
        signature.initSign(signingKey);
        signature.update(dataToSign);
        return signature.sign();
    }

    public static boolean verifySignature(PublicKey verifyingKey, byte[] dataToVerify, byte[] signatureBytes) throws Exception {
        Signature signature = Signature.getInstance("Ed25519", "BC");
        signature.initVerify(verifyingKey);
        signature.update(dataToVerify);
        return signature.verify(signatureBytes);
    }

    public static byte[] encryptMessage(byte[] aesKey, String message) throws Exception {
        byte[] nonce = new byte[12];
        new SecureRandom().nextBytes(nonce);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        GCMParameterSpec spec = new GCMParameterSpec(128, nonce);
        SecretKeySpec keySpec = new SecretKeySpec(aesKey, "AES");

        cipher.init(Cipher.ENCRYPT_MODE, keySpec, spec);

        byte[] ciphertext = cipher.doFinal(message.getBytes());

        byte[] packet = new byte[nonce.length + ciphertext.length];
        System.arraycopy(nonce, 0, packet, 0, nonce.length);
        System.arraycopy(ciphertext, 0, packet, nonce.length, ciphertext.length);

        return packet;
    }

    public static String decryptMessage(byte[] aesKey, byte[] packet) throws Exception {
        byte[] nonce = Arrays.copyOfRange(packet, 0, 12);
        byte[] ciphertext = Arrays.copyOfRange(packet, 12, packet.length);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        GCMParameterSpec spec = new GCMParameterSpec(128, nonce);
        SecretKeySpec keySpec = new SecretKeySpec(aesKey, "AES");

        cipher.init(Cipher.DECRYPT_MODE, keySpec, spec);

        byte[] plaintext = cipher.doFinal(ciphertext);
        return new String(plaintext);
    }
}