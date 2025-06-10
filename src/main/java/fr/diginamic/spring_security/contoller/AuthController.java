package fr.diginamic.spring_security.contoller;

import fr.diginamic.spring_security.dto.LoginRequestDto;
import fr.diginamic.spring_security.entity.UserApp;
import fr.diginamic.spring_security.exception.AuthException;
import fr.diginamic.spring_security.service.AuthService;
import fr.diginamic.spring_security.service.JwtService;
import fr.diginamic.spring_security.service.UserAppService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@RestController
@RequestMapping("/auth")
public class AuthController {
    @Autowired
    private AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody LoginRequestDto request) {
        try {
            authService.registerUser(request.getEmail(), request.getPassword());
            return ResponseEntity.status(HttpStatus.CREATED).body("Utilisateur créé avec succès");
        } catch (AuthException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PostMapping("/login")
        public ResponseEntity<String> login(@RequestBody LoginRequestDto request, HttpServletResponse response){
            try {
                authService.loginUser(request.getEmail(), request.getPassword(), response);
                return ResponseEntity.ok("Connexion réussie");
            } catch (AuthException e) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(e.getMessage());
            }
        }

    @PostMapping("/logout")
    public ResponseEntity<String> logout(HttpServletResponse response) {
        try {
            authService.logoutUser(response);
            return ResponseEntity.ok("Déconnexion réussie");
        } catch (AuthException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

}
