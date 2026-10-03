package com.gnax.identity.service;

import com.gnax.identity.dto.RegisterRequest;
import com.gnax.identity.dto.UserResponse;
import com.gnax.identity.entity.Role;
import com.gnax.identity.entity.User;
import com.gnax.identity.exception.AuthException;
import com.gnax.identity.repository.RoleRepository;
import com.gnax.identity.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class UserService implements UserDetailsService {

    public static final String DEFAULT_ROLE = "USER";

    private final UserRepository users;
    private final RoleRepository roles;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    public UserResponse register(RegisterRequest req) {
        if (users.existsByUsernameIgnoreCase(req.username())) {
            throw new AuthException(HttpStatus.CONFLICT, "Username already taken");
        }
        if (users.existsByEmailIgnoreCase(req.email())) {
            throw new AuthException(HttpStatus.CONFLICT, "Email already registered");
        }
        Role role = roles.findByName(DEFAULT_ROLE)
                .orElseThrow(() -> new IllegalStateException("Default role missing"));
        User user = new User();
        user.setUsername(req.username());
        user.setEmail(req.email().toLowerCase());
        user.setPasswordHash(passwordEncoder.encode(req.password()));
        user.setRoles(Set.of(role));
        return toResponse(users.save(user));
    }

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) {
        User u = users.findByUsernameIgnoreCase(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        return org.springframework.security.core.userdetails.User.withUsername(u.getUsername())
                .password(u.getPasswordHash())
                .disabled(!u.isEnabled())
                .authorities(u.getRoles().stream()
                        .map(r -> new SimpleGrantedAuthority("ROLE_" + r.getName())).toList())
                .build();
    }

    @Transactional(readOnly = true)
    public User getByUsername(String username) {
        return users.findByUsernameIgnoreCase(username)
                .orElseThrow(() -> new AuthException(HttpStatus.UNAUTHORIZED, "Invalid credentials"));
    }

    public static UserResponse toResponse(User u) {
        return new UserResponse(u.getId(), u.getUsername(), u.getEmail(),
                u.getRoles().stream().map(Role::getName).collect(Collectors.toSet()));
    }
}
