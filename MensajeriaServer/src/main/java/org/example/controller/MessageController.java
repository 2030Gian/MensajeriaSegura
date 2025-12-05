package org.example.controller;

import lombok.RequiredArgsConstructor;
import org.example.model.Message;
import org.example.repository.MessageRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/messages")
@RequiredArgsConstructor
public class MessageController {

    private final MessageRepository messageRepository;

    @PostMapping("/send")
    public ResponseEntity<String> sendMessage(@RequestBody Message msg) {
        if (msg.getRecipient() == null || msg.getCiphertext() == null) {
            return ResponseEntity.badRequest().body("Datos incompletos.");
        }

        msg.setTimestamp(java.time.LocalDateTime.now());
        messageRepository.save(msg);

        return ResponseEntity.ok("Mensaje guardado en base de datos.");
    }

    @GetMapping("/inbox")
    public ResponseEntity<List<Message>> getMessages(@RequestParam String username) {
        List<Message> messages = messageRepository.findByRecipient(username);

        if (!messages.isEmpty()) {
            messageRepository.deleteAll(messages);
        }

        return ResponseEntity.ok(messages);
    }
}