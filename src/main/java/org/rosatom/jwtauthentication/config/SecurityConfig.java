package org.rosatom.jwtauthentication.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import net.devh.boot.grpc.server.security.authentication.BearerAuthenticationReader;
import net.devh.boot.grpc.server.security.authentication.GrpcAuthenticationReader;
import net.devh.boot.grpc.server.security.check.AccessPredicate;
import net.devh.boot.grpc.server.security.check.AccessPredicateVoter;
import net.devh.boot.grpc.server.security.check.GrpcSecurityMetadataSource;
import net.devh.boot.grpc.server.security.check.ManualGrpcSecurityMetadataSource;
import org.rosatom.jwtauthentication.UserServiceGrpc;
import org.rosatom.jwtauthentication.jwt.JwtAuthProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.vote.UnanimousBased;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Configuration
public class SecurityConfig {

    @Value("${jwt.signing.key}")
    String jwtSecretKey;

    private final JwtAuthProvider jwtAuthProvider;

    public SecurityConfig(JwtAuthProvider jwtAuthProvider) {
        this.jwtAuthProvider = jwtAuthProvider;
    }

    @Bean
    AuthenticationManager authenticationManager() {
        return new ProviderManager(jwtAuthProvider);
    }

    @Bean
    GrpcAuthenticationReader grpcAuthenticationReader() {
        return new BearerAuthenticationReader(token -> {
            Claims claims = Jwts.parser().setSigningKey(jwtSecretKey).parseClaimsJws(token).getBody();
            List<SimpleGrantedAuthority> authorities = Arrays.stream(claims.get("auth").toString().split((",")))
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());
            User user = new User(claims.getSubject(), "", authorities);
            return new UsernamePasswordAuthenticationToken(user, token, authorities);
        });
    }

    @Bean
    GrpcSecurityMetadataSource grpcSecurityMetadataSource(){
        ManualGrpcSecurityMetadataSource manualGrpcSecurityMetadataSource = new ManualGrpcSecurityMetadataSource();
        manualGrpcSecurityMetadataSource.setDefault(AccessPredicate.permitAll());
        manualGrpcSecurityMetadataSource.set(UserServiceGrpc.getGetUserInfoMethod(),AccessPredicate.hasRole("ROLE_ADMIN"));
        return manualGrpcSecurityMetadataSource;
    }

    @Bean
    AccessDecisionManager accessDecisionManager(){
        List<AccessDecisionVoter<?>> accessDecisionVoters = new ArrayList<>();
        accessDecisionVoters.add(new AccessPredicateVoter());
        return new UnanimousBased(accessDecisionVoters);
    }
}

