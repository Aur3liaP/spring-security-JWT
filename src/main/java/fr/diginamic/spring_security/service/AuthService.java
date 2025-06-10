package fr.diginamic.spring_security.service;

import fr.diginamic.spring_security.entity.UserApp;
import fr.diginamic.spring_security.exception.AuthException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class AuthService {

    @Value("${auth.cookie.name}")
    private String COOKIE_NAME;

    @Value("${auth.cookie.expiration}")
    private int COOKIE_MAX_AGE;

    @Autowired
    private UserAppService userAppService;

    @Autowired
    private JwtService jwtService;

    public void registerUser(String email, String password) throws AuthException {
        validateEmail(email);
        validatePassword(password);

        if (userAppService.findByEmail(email).isPresent()) {
            throw new AuthException("Un utilisateur avec cet email existe déjà");
        }

        try {
            userAppService.createUser(email, password);
        } catch (Exception e) {
            throw new AuthException("Erreur lors de la création de l'utilisateur");
        }
    }

    public void loginUser(String email, String password, HttpServletResponse response) throws AuthException {
        if (email == null || password == null) {
            throw new AuthException("Email et mot de passe requis");
        }

        try {
            Optional<UserApp> userOpt = userAppService.findByEmail(email);

            if (userOpt.isEmpty()) {
                throw new AuthException("Identifiants invalides");
            }

            UserApp user = userOpt.get();

            if (!userAppService.checkPassword(password, user.getPassword())) {
                throw new AuthException("Identifiants invalides");
            }

            String token = jwtService.generateToken(user.getEmail(), user.getRole());
            addJwtCookie(response, token);

        } catch (Exception e) {
            throw new AuthException("Erreur lors de la connexion");
        }
    }

    public void logoutUser(HttpServletResponse response) throws AuthException {
        try {
            removeJwtCookie(response);
        } catch (Exception e) {
            throw new AuthException("Erreur lors de la déconnexion");
        }
    }


    private void validateEmail(String email) throws AuthException {
        if (email == null || email.trim().isEmpty()) {
            throw new AuthException("L'email est requis");
        }
        if (!email.matches("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$")) {
            throw new AuthException("Format d'email invalide");
        }
    }

    private void validatePassword(String password) throws AuthException {
        if (password == null || password.length() < 6) {
            throw new AuthException("Le mot de passe doit contenir au moins 6 caractères");
        }
    }

    private void addJwtCookie(HttpServletResponse response, String token) {
        Cookie jwtCookie = new Cookie(COOKIE_NAME, token);
        jwtCookie.setHttpOnly(true);
        jwtCookie.setSecure(false);
        jwtCookie.setPath("/");
        jwtCookie.setMaxAge(COOKIE_MAX_AGE);
        response.addCookie(jwtCookie);
    }

    private void removeJwtCookie(HttpServletResponse response) {
        Cookie jwtCookie = new Cookie(COOKIE_NAME, "");
        jwtCookie.setHttpOnly(true);
        jwtCookie.setSecure(false);
        jwtCookie.setPath("/");
        jwtCookie.setMaxAge(0);
        response.addCookie(jwtCookie);
    }
}
