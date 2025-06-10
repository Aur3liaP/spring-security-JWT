package fr.diginamic.spring_security.security;

import fr.diginamic.spring_security.service.JwtService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.stream.Stream;

@Component
public class JwtFilter extends OncePerRequestFilter {

    //Etape 1 :
//    @Override
//    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
//
//        System.out.println("doFilterInternal");
//
//        UsernamePasswordAuthenticationToken fakeAuth =
//                new UsernamePasswordAuthenticationToken(
//                        "dev@fake.com",
//                        null,
//                        List.of(new SimpleGrantedAuthority("ROLE_USER"))
//                );
//
//        SecurityContextHolder.getContext().setAuthentication(fakeAuth);
//
//        filterChain.doFilter(request, response);
//    }

//    @Override
//    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
//
//        System.out.println("doFilterInternal");
//        String authHeader = request.getHeader("Authorization");
//        String token = null;
//
//        if (authHeader != null && authHeader.startsWith("Bearer ")) {
//            token = authHeader;
//        }
//        if (token != null && token.equals("Bearer toto") && SecurityContextHolder.getContext().getAuthentication() == null) {
//            System.out.println("doFilterInternal authorization");
//
//            UsernamePasswordAuthenticationToken totoAuth =
//                    new UsernamePasswordAuthenticationToken(
//                            "dev@fake.com",
//                            null,
//                            List.of(new SimpleGrantedAuthority("ROLE_USER"))
//                    );
//            SecurityContextHolder.getContext().setAuthentication(totoAuth);
//        }
//
//        filterChain.doFilter(request, response);
//    }

//    @Override
//    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
//
//        if (request.getCookies() != null) {
//            Stream.of(request.getCookies()).filter(cookie -> cookie.getName().equals("COOKIE_NAME")).map(Cookie::getValue)
//                    .forEach(token -> {
//                        System.out.println(token);
//                        UsernamePasswordAuthenticationToken totoAuth =
//                                new UsernamePasswordAuthenticationToken(
//                                        "dev@fake.com",
//                                        null,
//                                        List.of(new SimpleGrantedAuthority("ROLE_USER"))
//                                );
//                        SecurityContextHolder.getContext().setAuthentication(totoAuth);
//                    }
//                    );
//        }
//
//        filterChain.doFilter(request, response);
//    }

//    private final String SECRET = "maSuperCleSecrete123maSuperCleSecrete123maSuperCleSecrete123";
//    private final SecretKey key = Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8));
//
//    @Override
//    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
//
//        if (request.getCookies() != null) {
//            Stream.of(request.getCookies()).filter(cookie -> cookie.getName().equals("COOKIE_NAME")).map(Cookie::getValue)
//                    .forEach(token -> {
//                        Claims claims = Jwts.parser()
//                                .verifyWith(key)
//                                .build()
//                                .parseSignedClaims(token)
//                                .getPayload();
//
//                        if (claims.getSubject().equals("dev@fake.com")) {
//                            UsernamePasswordAuthenticationToken totoAuth =
//                                    new UsernamePasswordAuthenticationToken(
//                                            "dev@fake.com",
//                                            null,
//                                            List.of(new SimpleGrantedAuthority("ROLE_USER"))
//                                    );
//                            SecurityContextHolder.getContext().setAuthentication(totoAuth);
//                        }
//                    }
//                    );
//        }
//
//        filterChain.doFilter(request, response);
//    }


    //Etape 2 :
    @Autowired
    private JwtService jwtService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        if (request.getCookies() != null) {
            Stream.of(request.getCookies())
                    .filter(cookie -> cookie.getName().equals("AUTH_TOKEN"))
                    .map(Cookie::getValue)
                    .forEach(token -> {
                        try {
                            if (jwtService.isTokenValid(token)) {
                                String email = jwtService.getEmailFromToken(token);

                                UsernamePasswordAuthenticationToken auth =
                                        new UsernamePasswordAuthenticationToken(
                                                email,
                                                null,
                                                List.of(new SimpleGrantedAuthority("ROLE_USER"))
                                        );
                                SecurityContextHolder.getContext().setAuthentication(auth);
                            }
                        } catch (Exception e) {
                            System.err.println("Erreur lors du parsing du JWT : " + e.getMessage());
                        }
                    });
        }

        filterChain.doFilter(request, response);
    }
}