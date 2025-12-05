package org.example.controller;

import lombok.RequiredArgsConstructor;
import org.example.model.User;
import org.example.repository.UserRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final UserRepository userRepository;

    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody Map<String, String> payload) {
        try {
            String username = payload.get("username");

            User user = userRepository.findById(username).orElse(new User());

            user.setUsername(username);
            user.setPasswordHash(payload.get("passwordHash"));
            user.setPublicKeyCifrado(payload.get("pkCifrado"));
            user.setPublicKeyFirma(payload.get("pkFirma"));

            userRepository.save(user);

            return ResponseEntity.ok("Registro/Actualización exitosa.");
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body("Error: " + e.getMessage());
        }
    }

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody Map<String, String> payload) {
        Optional<User> userOpt = userRepository.findById(payload.get("username"));

        if (userOpt.isPresent() && userOpt.get().getPasswordHash().equals(payload.get("passwordHash"))) {
            return ResponseEntity.ok("TOKEN_VALIDO");
        }
        return ResponseEntity.status(401).body("Credenciales inválidas.");
    }

    @GetMapping("/key")
    public ResponseEntity<String> getPublicKey(@RequestParam String username, @RequestParam String type) {
        Optional<User> userOpt = userRepository.findById(username);

        if (userOpt.isEmpty()) {
            return ResponseEntity.status(404).body("Usuario no encontrado");
        }

        User user = userOpt.get();
        if ("cifrado".equals(type)) return ResponseEntity.ok(user.getPublicKeyCifrado());
        if ("firma".equals(type)) return ResponseEntity.ok(user.getPublicKeyFirma());

        return ResponseEntity.badRequest().body("Tipo desconocido");
    }
}