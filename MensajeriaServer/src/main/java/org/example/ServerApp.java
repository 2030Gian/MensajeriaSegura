package org.example;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class ServerApp {
    public static void main(String[] args) {
        // Esto arranca el servidor en el puerto 8080
        SpringApplication.run(ServerApp.class, args);
    }
}