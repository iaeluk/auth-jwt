package com.iaeluk.auth_jwt.controller;

import com.iaeluk.auth_jwt.config.TokenService;
import com.iaeluk.auth_jwt.model.User;
import com.iaeluk.auth_jwt.model.dto.LoginRequestDTO;
import com.iaeluk.auth_jwt.model.dto.RegisterRequestDTO;
import com.iaeluk.auth_jwt.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final UserService userService;
    private final PasswordEncoder passwordEncoder;
    private final TokenService tokenService;

    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> login(@RequestBody LoginRequestDTO body) {
        User user = userService.findByEmail(body.email())
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (passwordEncoder.matches(body.password(), user.getPassword())) {
            String accessToken = tokenService.generateAccessToken(user);
            String refreshToken = tokenService.generateRefreshToken(user);

            Map<String, String> response = new LinkedHashMap<>();
            response.put("name", user.getName());
            response.put("access_token", accessToken);
            response.put("refresh_token", refreshToken);

            return ResponseEntity.ok(response);
        }
        return ResponseEntity.badRequest().build();
    }

    @PostMapping("/register")
    public ResponseEntity<Map<String, String>> register(@RequestBody RegisterRequestDTO body) {
        Optional<User> existingUser = this.userService.findByEmail(body.email());

        if (existingUser.isEmpty()) {
            User newUser = new User();
            newUser.setPassword(passwordEncoder.encode(body.password()));
            newUser.setEmail(body.email());
            newUser.setName(body.name());
            this.userService.save(newUser);

            String accessToken = this.tokenService.generateAccessToken(newUser);
            String refreshToken = this.tokenService.generateRefreshToken(newUser);

            Map<String, String> response = new LinkedHashMap<>();
            response.put("name", newUser.getName());
            response.put("access_token", accessToken);
            response.put("refresh_token", refreshToken);

            return ResponseEntity.ok(response);
        }
        return ResponseEntity.badRequest().build();
    }

    @PostMapping("/refresh")
    public ResponseEntity<Map<String, String>> refreshToken(@RequestBody Map<String, String> request) {
        String refreshToken = request.get("refresh_token");
        if (refreshToken != null && !refreshToken.isEmpty()) {
            try {
                String email = tokenService.validateToken(refreshToken);
                User user = userService.findByEmail(email).orElseThrow(() -> new RuntimeException("User not found"));

                String newAccessToken = tokenService.generateAccessToken(user);
                String newRefreshToken = tokenService.generateRefreshToken(user);

                Map<String, String> tokens = new HashMap<>();
                tokens.put("access_token", newAccessToken);
                tokens.put("refresh_token", newRefreshToken);

                return ResponseEntity.ok(tokens);
            } catch (Exception e) {
                return ResponseEntity.badRequest().body(Map.of("error", "Invalid refresh token"));
            }
        }
        return ResponseEntity.badRequest().body(Map.of("error", "Refresh token is missing"));
    }
}
