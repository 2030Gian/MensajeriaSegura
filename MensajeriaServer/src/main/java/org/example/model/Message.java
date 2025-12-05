package org.example.model;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.time.LocalDateTime;

@Entity
@Table(name = "messages")
@Data
@NoArgsConstructor
public class Message {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String sender;
    private String recipient;

    @Column(columnDefinition = "TEXT")
    private String ciphertext;

    private String nonce;
    private String salt;

    @Column(columnDefinition = "TEXT")
    private String signature;

    private LocalDateTime timestamp;

    public Message(String sender, String recipient, String ciphertext, String nonce, String salt, String signature) {
        this.sender = sender;
        this.recipient = recipient;
        this.ciphertext = ciphertext;
        this.nonce = nonce;
        this.salt = salt;
        this.signature = signature;
        this.timestamp = LocalDateTime.now();
    }
}