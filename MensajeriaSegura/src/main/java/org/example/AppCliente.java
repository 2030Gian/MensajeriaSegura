package org.example;

import javax.swing.*;
import java.awt.*;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.concurrent.CompletableFuture;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class AppCliente extends JFrame {
    private JTextArea areaChat;
    private JTextField campoMensaje;
    private JTextField campoUsuario;
    private JPasswordField campoPassword;
    private JTextField campoDestinatario;
    private JButton botonAccion;
    private JButton botonEnviar;
    private JButton botonRecibir;

    private final HttpClient httpClient = HttpClient.newHttpClient();
    private final String BASE_URL = "http://localhost:8080/api";

    private KeyPair misLlavesCifrado;
    private KeyPair misLlavesFirma;

    public AppCliente() {
        super("Mensajería Segura (PRODUCCIÓN)");
        setSize(600, 750);
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        inicializarUI();
    }

    private void inicializarUI() {
        setLayout(new BorderLayout());

        JPanel panelNorte = new JPanel(new GridLayout(4, 1));

        JPanel p1 = new JPanel(new FlowLayout(FlowLayout.LEFT));
        p1.add(new JLabel("Usuario:"));
        campoUsuario = new JTextField("", 10);
        p1.add(campoUsuario);

        JPanel p2 = new JPanel(new FlowLayout(FlowLayout.LEFT));
        p2.add(new JLabel("Contraseña:"));
        campoPassword = new JPasswordField(10);
        p2.add(campoPassword);

        botonAccion = new JButton("🔓 Iniciar / Registrarse");
        botonAccion.setBackground(new Color(255, 193, 7));
        botonAccion.addActionListener(e -> manejarInicioSesion());
        p2.add(botonAccion);

        JPanel p3 = new JPanel(new FlowLayout(FlowLayout.LEFT));
        p3.add(new JLabel("Hablar con:"));
        campoDestinatario = new JTextField("Bob", 10);
        botonRecibir = new JButton("📩 Recibir");
        botonRecibir.setBackground(new Color(40, 167, 69));
        botonRecibir.setForeground(Color.WHITE);
        botonRecibir.addActionListener(e -> recibirMensajes());
        p3.add(campoDestinatario);
        p3.add(botonRecibir);

        panelNorte.add(p1);
        panelNorte.add(p2);
        panelNorte.add(p3);
        add(panelNorte, BorderLayout.NORTH);

        areaChat = new JTextArea();
        areaChat.setEditable(false);
        areaChat.setFont(new Font("Monospaced", Font.PLAIN, 12));
        add(new JScrollPane(areaChat), BorderLayout.CENTER);

        JPanel panelSur = new JPanel(new BorderLayout());
        campoMensaje = new JTextField();
        botonEnviar = new JButton("Enviar 🚀");
        botonEnviar.setBackground(new Color(0, 120, 215));
        botonEnviar.setForeground(Color.WHITE);
        botonEnviar.addActionListener(e -> enviarMensaje());

        panelSur.add(campoMensaje, BorderLayout.CENTER);
        panelSur.add(botonEnviar, BorderLayout.EAST);
        add(panelSur, BorderLayout.SOUTH);

        addWindowListener(new java.awt.event.WindowAdapter() {
            public void windowOpened(java.awt.event.WindowEvent e) {
                campoUsuario.requestFocus();
            }
        });
    }

    private void manejarInicioSesion() {
        String user = campoUsuario.getText().trim();
        String pass = new String(campoPassword.getPassword());

        if (user.isEmpty() || pass.isEmpty()) {
            log("❌ Error: Ingresa usuario y contraseña.");
            return;
        }

        try {
            KeyPair[] keys = KeyStorage.cargarLlaves(user, pass);

            if (keys != null) {
                misLlavesCifrado = keys[0];
                misLlavesFirma = keys[1];
                log("✅ Identidad de " + user + " desbloqueada.");
            } else {
                log("⚠️ Usuario nuevo (" + user + "). Generando llaves...");
                misLlavesCifrado = CryptoEngine.generateX25519KeyPair();
                misLlavesFirma = CryptoEngine.generateEd25519KeyPair();

                KeyStorage.guardarLlaves(user, misLlavesCifrado, misLlavesFirma, pass);
                log("💾 Llaves guardadas en disco.");
            }
            registrarseEnServidor(user, pass);

        } catch (Exception e) {
            log("❌ Contraseña incorrecta o error de llaves.");
        }
    }

    private void registrarseEnServidor(String user, String pass) {
        try {
            String pkCifrado = Base64.getEncoder().encodeToString(misLlavesCifrado.getPublic().getEncoded());
            String pkFirma = Base64.getEncoder().encodeToString(misLlavesFirma.getPublic().getEncoded());

            String json = String.format(
                    "{\"username\":\"%s\", \"passwordHash\":\"%s\", \"pkCifrado\":\"%s\", \"pkFirma\":\"%s\"}",
                    user, pass, pkCifrado, pkFirma
            );

            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(BASE_URL + "/auth/register"))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(json))
                    .build();

            httpClient.sendAsync(req, HttpResponse.BodyHandlers.ofString())
                    .thenAccept(res -> SwingUtilities.invokeLater(() -> {
                        if (res.statusCode() == 200) log("🌐 Sincronizado con servidor.");
                        else log("⚠️ Servidor: " + res.body());
                    }));
        } catch (Exception e) { log("❌ Error de red: " + e.getMessage()); }
    }

    private void enviarMensaje() {
        String texto = campoMensaje.getText().trim();
        String yo = campoUsuario.getText().trim();
        String dest = campoDestinatario.getText().trim();

        if (texto.isEmpty() || misLlavesCifrado == null) {
            log("❌ Primero inicia sesión o escribe algo.");
            return;
        }

        HttpRequest reqKey = HttpRequest.newBuilder()
                .uri(URI.create(BASE_URL + "/auth/key?type=cifrado&username=" + dest))
                .GET().build();

        log("🔄 Buscando llave pública de " + dest + "...");

        httpClient.sendAsync(reqKey, HttpResponse.BodyHandlers.ofString())
                .thenAccept(res -> {
                    if (res.statusCode() != 200) {
                        SwingUtilities.invokeLater(() -> log("❌ No encontré a " + dest));
                        return;
                    }

                    try {
                        byte[] bobPkBytes = Base64.getDecoder().decode(res.body());
                        KeyFactory kf = KeyFactory.getInstance("X25519", "BC");
                        PublicKey bobPublicKey = kf.generatePublic(new X509EncodedKeySpec(bobPkBytes));

                        byte[] salt = CryptoEngine.generateSalt();
                        byte[] llaveAES = CryptoEngine.performKeyExchange(misLlavesCifrado.getPrivate(), bobPublicKey, salt);

                        byte[] cifrado = CryptoEngine.encryptMessage(llaveAES, texto);

                        byte[] firmaBytes = CryptoEngine.signData(misLlavesFirma.getPrivate(), cifrado);

                        String json = String.format(
                                "{\"sender\":\"%s\", \"recipient\":\"%s\", \"ciphertext\":\"%s\", \"salt\":\"%s\", \"nonce\":\"\", \"signature\":\"%s\"}",
                                yo, dest,
                                Base64.getEncoder().encodeToString(cifrado),
                                Base64.getEncoder().encodeToString(salt),
                                Base64.getEncoder().encodeToString(firmaBytes) // Enviamos la firma
                        );

                        HttpRequest reqSend = HttpRequest.newBuilder()
                                .uri(URI.create(BASE_URL + "/messages/send"))
                                .header("Content-Type", "application/json")
                                .POST(HttpRequest.BodyPublishers.ofString(json))
                                .build();

                        httpClient.sendAsync(reqSend, HttpResponse.BodyHandlers.ofString())
                                .thenAccept(r -> SwingUtilities.invokeLater(() -> {
                                    log("YO: " + texto);
                                    campoMensaje.setText("");
                                    campoMensaje.requestFocus();
                                }));

                    } catch (Exception e) {
                        SwingUtilities.invokeLater(() -> log("❌ Error Cifrando/Firmando: " + e.getMessage()));
                    }
                });
    }

    private void recibirMensajes() {
        String yo = campoUsuario.getText().trim();
        if (misLlavesCifrado == null) return;

        HttpRequest req = HttpRequest.newBuilder().uri(URI.create(BASE_URL + "/messages/inbox?username=" + yo)).GET().build();

        httpClient.sendAsync(req, HttpResponse.BodyHandlers.ofString())
                .thenAccept(res -> {
                    String json = res.body();

                    Pattern pSender = Pattern.compile("\"sender\":\"([^\"]+)\"");
                    Pattern pCipher = Pattern.compile("\"ciphertext\":\"([^\"]+)\"");
                    Pattern pSalt = Pattern.compile("\"salt\":\"([^\"]+)\"");
                    Pattern pSignature = Pattern.compile("\"signature\":\"([^\"]+)\""); // NUEVO

                    Matcher mSender = pSender.matcher(json);
                    Matcher mCipher = pCipher.matcher(json);
                    Matcher mSalt = pSalt.matcher(json);
                    Matcher mSignature = pSignature.matcher(json);

                    SwingUtilities.invokeLater(() -> {
                        boolean hayMensajes = false;
                        // Ajustamos el loop para buscar todas las coincidencias
                        while (mSender.find() && mCipher.find() && mSalt.find() && mSignature.find()) {
                            hayMensajes = true;
                            String sender = mSender.group(1);
                            String cipherB64 = mCipher.group(1);
                            String saltB64 = mSalt.group(1);
                            String signatureB64 = mSignature.group(1); // Extraemos la firma

                            descargarLlaveYDescifrar(sender, cipherB64, saltB64, signatureB64);
                        }
                        if (!hayMensajes) log("📭 Sin novedades.");
                    });
                });
    }

    private void descargarLlaveYDescifrar(String sender, String cipherB64, String saltB64, String signatureB64) {
        HttpRequest reqCifradoKey = HttpRequest.newBuilder()
                .uri(URI.create(BASE_URL + "/auth/key?type=cifrado&username=" + sender))
                .GET().build();

        HttpRequest reqFirmaKey = HttpRequest.newBuilder()
                .uri(URI.create(BASE_URL + "/auth/key?type=firma&username=" + sender))
                .GET().build();

        httpClient.sendAsync(reqFirmaKey, HttpResponse.BodyHandlers.ofString())
                .thenCompose(resFirma -> {
                    try {
                        byte[] senderPkFirmaBytes = Base64.getDecoder().decode(resFirma.body());
                        KeyFactory kfEd = KeyFactory.getInstance("Ed25519", "BC");
                        PublicKey senderFirmaPublicKey = kfEd.generatePublic(new X509EncodedKeySpec(senderPkFirmaBytes));

                        byte[] cipherBytes = Base64.getDecoder().decode(cipherB64);
                        byte[] signatureBytes = Base64.getDecoder().decode(signatureB64);

                        boolean firmaValida = CryptoEngine.verifySignature(senderFirmaPublicKey, cipherBytes, signatureBytes);

                        if (!firmaValida) {
                            SwingUtilities.invokeLater(() -> log("🔴 ⚠️ ERROR DE FIRMA: Mensaje de " + sender + " alterado."));
                            return CompletableFuture.completedFuture(null);
                        }

                        return httpClient.sendAsync(reqCifradoKey, HttpResponse.BodyHandlers.ofString());

                    } catch (Exception e) {
                        SwingUtilities.invokeLater(() -> log("❌ Error crítico en verificación: " + e.getMessage()));
                        return CompletableFuture.completedFuture(null);
                    }
                })
                .thenAccept(resCifrado -> {
                    if (resCifrado == null) return;

                    try {
                        byte[] senderPkCifradoBytes = Base64.getDecoder().decode(resCifrado.body());
                        KeyFactory kfX = KeyFactory.getInstance("X25519", "BC");
                        PublicKey senderCifradoPublicKey = kfX.generatePublic(new X509EncodedKeySpec(senderPkCifradoBytes));

                        byte[] salt = Base64.getDecoder().decode(saltB64);
                        byte[] cipherBytes = Base64.getDecoder().decode(cipherB64);

                        byte[] llaveRecuperada = CryptoEngine.performKeyExchange(misLlavesCifrado.getPrivate(), senderCifradoPublicKey, salt);

                        String mensaje = CryptoEngine.decryptMessage(llaveRecuperada, cipherBytes);

                        SwingUtilities.invokeLater(() -> log("🟢 📩 " + sender + " (Verificado): " + mensaje));

                    } catch (Exception e) {
                        SwingUtilities.invokeLater(() -> log("⚠️ Error descifrando: " + e.getMessage()));
                    }
                });
    }

    private void log(String msg) {
        areaChat.append(msg + "\n");
        areaChat.setCaretPosition(areaChat.getDocument().getLength());
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new AppCliente().setVisible(true));
    }
}