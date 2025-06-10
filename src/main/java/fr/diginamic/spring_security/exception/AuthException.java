package fr.diginamic.spring_security.exception;

public class AuthException extends RuntimeException {
  public AuthException(String message) {
    super(message);
  }
}
