package org.example;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class KeyStorage {
    private static final int ITERATIONS = 65536;
    private static final int KEY_LENGTH = 256;

    private static String getFileName(String username) {
        return username + "_keys.enc";
    }

    public static void guardarLlaves(String username, KeyPair parCifrado, KeyPair parFirma, String password) throws Exception {
        byte[] salt = CryptoEngine.generateSalt();

        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_LENGTH);
        byte[] keyMaestra = skf.generateSecret(spec).getEncoded();

        String data = Base64.getEncoder().encodeToString(parCifrado.getPrivate().getEncoded()) + ":" +
                Base64.getEncoder().encodeToString(parCifrado.getPublic().getEncoded()) + ":" +
                Base64.getEncoder().encodeToString(parFirma.getPrivate().getEncoded()) + ":" +
                Base64.getEncoder().encodeToString(parFirma.getPublic().getEncoded());

        byte[] archivoCifrado = CryptoEngine.encryptMessage(keyMaestra, data);

        try (FileOutputStream fos = new FileOutputStream(getFileName(username))) {
            fos.write(salt);
            fos.write(archivoCifrado);
        }
    }

    public static KeyPair[] cargarLlaves(String username, String password) throws Exception {
        String fileName = getFileName(username);
        if (!Files.exists(Paths.get(fileName))) return null;

        byte[] fileContent = Files.readAllBytes(Paths.get(fileName));

        byte[] salt = new byte[32];
        System.arraycopy(fileContent, 0, salt, 0, 32);

        byte[] encryptedData = new byte[fileContent.length - 32];
        System.arraycopy(fileContent, 32, encryptedData, 0, encryptedData.length);

        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_LENGTH);
        byte[] keyMaestra = skf.generateSecret(spec).getEncoded();

        String decryptedData = CryptoEngine.decryptMessage(keyMaestra, encryptedData);

        String[] parts = decryptedData.split(":");
        KeyFactory kfX = KeyFactory.getInstance("X25519", "BC");
        KeyFactory kfEd = KeyFactory.getInstance("Ed25519", "BC");

        KeyPair kpCifrado = new KeyPair(
                kfX.generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(parts[1]))),
                kfX.generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(parts[0])))
        );

        KeyPair kpFirma = new KeyPair(
                kfEd.generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(parts[3]))),
                kfEd.generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(parts[2])))
        );

        return new KeyPair[]{kpCifrado, kpFirma};
    }
}