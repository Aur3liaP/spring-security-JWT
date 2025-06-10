package fr.diginamic.spring_security.service;

import fr.diginamic.spring_security.entity.UserApp;
import fr.diginamic.spring_security.repository.UserAppRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserAppService {

    @Autowired
    private UserAppRepository userAppRepository;

    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    public UserApp createUser(String email, String password) {
        String encodedPassword = passwordEncoder.encode(password);
        UserApp user = new UserApp(email, encodedPassword);
        return userAppRepository.save(user);
    }

    public Optional<UserApp> findByEmail(String email) {
        return userAppRepository.findByEmail(email);
    }

    public boolean checkPassword(String rawPassword, String encodedPassword) {
        return passwordEncoder.matches(rawPassword, encodedPassword);
    }
}
