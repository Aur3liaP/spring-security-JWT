package fr.diginamic.spring_security.entity;

import jakarta.persistence.*;
import lombok.Data;

@Data
@Entity
@Table(name = "user_app")
public class UserApp {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String email;

    @Column(nullable = false)
    private String password;

    @Column(nullable = false)
    private String role = "ROLE_USER";

    public UserApp() {}

    public UserApp(String email, String password) {
        this.email = email;
        this.password = password;
    }

    public UserApp(String email, String password, String role) {
        this.email = email;
        this.password = password;
        this.role = role;
    }
}