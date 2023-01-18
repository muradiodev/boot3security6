package com.alibou.security.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.alibou.security.config.JwtService;
import com.alibou.security.user.User;
import com.alibou.security.user.UserRepository;

import java.util.Optional;

import org.junit.jupiter.api.Disabled;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;

@ContextConfiguration(classes = {AuthenticationService.class})
@ExtendWith(SpringExtension.class)
class AuthenticationServiceTest {
    @MockBean
    private AuthenticationManager authenticationManager;

    @Autowired
    private AuthenticationService authenticationService;

    @MockBean
    private JwtService jwtService;

    @MockBean
    private PasswordEncoder passwordEncoder;

    @MockBean
    private UserRepository userRepository;

    /**
     * Method under test: {@link AuthenticationService#register(RegisterRequest)}
     */
    @Test
    void testRegister() {
        when(userRepository.save((User) any())).thenReturn(new User());
        when(jwtService.generateToken((UserDetails) any())).thenReturn("ABC123");
        when(passwordEncoder.encode((CharSequence) any())).thenReturn("secret");
        assertEquals("ABC123",
                authenticationService.register(new RegisterRequest("Jane", "Doe", "jane.doe@example.org", "iloveyou"))
                        .getToken());
        verify(userRepository).save((User) any());
        verify(jwtService).generateToken((UserDetails) any());
        verify(passwordEncoder).encode((CharSequence) any());
    }

    /**
     * Method under test: {@link AuthenticationService#register(RegisterRequest)}
     */
    @Test
    @Disabled("TODO: Complete this test")
    void testRegister2() {
        // TODO: Complete this test.
        //   Reason: R013 No inputs found that don't throw a trivial exception.
        //   Diffblue Cover tried to run the arrange/act section, but the method under
        //   test threw
        //   java.lang.NullPointerException: Cannot invoke "com.alibou.security.auth.RegisterRequest.getFirstname()" because "request" is null
        //       at com.alibou.security.auth.AuthenticationService.register(AuthenticationService.java:23)
        //   See https://diff.blue/R013 to resolve this issue.

        when(userRepository.save((User) any())).thenReturn(new User());
        when(jwtService.generateToken((UserDetails) any())).thenReturn("ABC123");
        when(passwordEncoder.encode((CharSequence) any())).thenReturn("secret");
        authenticationService.register(null);
    }

    /**
     * Method under test: {@link AuthenticationService#authenticate(AuthenticationRequest)}
     */
    @Test
    void testAuthenticate() throws AuthenticationException {
        when(userRepository.findByEmail((String) any())).thenReturn(Optional.of(new User()));
        when(jwtService.generateToken((UserDetails) any())).thenReturn("ABC123");
        when(authenticationManager.authenticate((Authentication) any()))
                .thenReturn(new TestingAuthenticationToken("Principal", "Credentials"));
        assertEquals("ABC123",
                authenticationService.authenticate(new AuthenticationRequest("jane.doe@example.org", "iloveyou")).getToken());
        verify(userRepository).findByEmail((String) any());
        verify(jwtService).generateToken((UserDetails) any());
        verify(authenticationManager).authenticate((Authentication) any());
    }

    /**
     * Method under test: {@link AuthenticationService#authenticate(AuthenticationRequest)}
     */
    @Test
    @Disabled("TODO: Complete this test")
    void testAuthenticate2() throws AuthenticationException {
        // TODO: Complete this test.
        //   Reason: R013 No inputs found that don't throw a trivial exception.
        //   Diffblue Cover tried to run the arrange/act section, but the method under
        //   test threw
        //   java.util.NoSuchElementException: No value present
        //       at java.util.Optional.orElseThrow(Optional.java:377)
        //       at com.alibou.security.auth.AuthenticationService.authenticate(AuthenticationService.java:44)
        //   See https://diff.blue/R013 to resolve this issue.

        when(userRepository.findByEmail((String) any())).thenReturn(Optional.empty());
        when(jwtService.generateToken((UserDetails) any())).thenReturn("ABC123");
        when(authenticationManager.authenticate((Authentication) any()))
                .thenReturn(new TestingAuthenticationToken("Principal", "Credentials"));
        authenticationService.authenticate(new AuthenticationRequest("jane.doe@example.org", "iloveyou"));
    }

    /**
     * Method under test: {@link AuthenticationService#authenticate(AuthenticationRequest)}
     */
    @Test
    @Disabled("TODO: Complete this test")
    void testAuthenticate3() throws AuthenticationException {
        // TODO: Complete this test.
        //   Reason: R013 No inputs found that don't throw a trivial exception.
        //   Diffblue Cover tried to run the arrange/act section, but the method under
        //   test threw
        //   java.lang.NullPointerException: Cannot invoke "com.alibou.security.auth.AuthenticationRequest.getEmail()" because "request" is null
        //       at com.alibou.security.auth.AuthenticationService.authenticate(AuthenticationService.java:39)
        //   See https://diff.blue/R013 to resolve this issue.

        when(userRepository.findByEmail((String) any())).thenReturn(Optional.of(new User()));
        when(jwtService.generateToken((UserDetails) any())).thenReturn("ABC123");
        when(authenticationManager.authenticate((Authentication) any()))
                .thenReturn(new TestingAuthenticationToken("Principal", "Credentials"));
        authenticationService.authenticate(null);
    }
}

