package fr.diginamic.spring_security.exception;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@ControllerAdvice
public class ExceptionsHandler {
    @ExceptionHandler(AuthException.class)
    public ResponseEntity<String> traiterErreur(AuthException e){
        return ResponseEntity.badRequest().body(e.getMessage());
    }
}
