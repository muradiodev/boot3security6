package com.alibou.security.config;

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.alibou.security.user.User;
import com.alibou.security.user.UserRepository;

import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;

@ContextConfiguration(classes = {ApplicationConfig.class, AuthenticationConfiguration.class})
@ExtendWith(SpringExtension.class)
class ApplicationConfigTest {
    @Autowired
    private ApplicationConfig applicationConfig;

    @MockBean
    private UserRepository userRepository;

    /**
     * Method under test: {@link ApplicationConfig#userDetailsService()}
     */
    @Test
    void testUserDetailsService() throws UsernameNotFoundException {
        //   Diffblue Cover was unable to write a Spring test,
        //   so wrote a non-Spring test instead.
        //   Reason: R002 Missing observers.
        //   Diffblue Cover was unable to create an assertion.
        //   Add getters for the following fields or make them package-private:
        //     932/0x00000008012b4f38.arg$1

        UserRepository userRepository = mock(UserRepository.class);
        User user = new User();
        when(userRepository.findByEmail((String) any())).thenReturn(Optional.of(user));
        UserDetails actualLoadUserByUsernameResult = (new ApplicationConfig(userRepository)).userDetailsService()
                .loadUserByUsername("foo");
        verify(userRepository).findByEmail((String) any());
        assertSame(user, actualLoadUserByUsernameResult);
    }

    /**
     * Method under test: {@link ApplicationConfig#userDetailsService()}
     */
    @Test
    void testUserDetailsService2() throws UsernameNotFoundException {
        //   Diffblue Cover was unable to write a Spring test,
        //   so wrote a non-Spring test instead.
        //   Reason: R002 Missing observers.
        //   Diffblue Cover was unable to create an assertion.
        //   Add getters for the following fields or make them package-private:
        //     932/0x00000008012b4f38.arg$1

        UserRepository userRepository = mock(UserRepository.class);
        when(userRepository.findByEmail((String) any())).thenReturn(Optional.empty());
        assertThrows(UsernameNotFoundException.class,
                () -> (new ApplicationConfig(userRepository)).userDetailsService().loadUserByUsername("foo"));
        verify(userRepository).findByEmail((String) any());
    }

    /**
     * Method under test: {@link ApplicationConfig#userDetailsService()}
     */
    @Test
    void testUserDetailsService3() throws UsernameNotFoundException {
        //   Diffblue Cover was unable to write a Spring test,
        //   so wrote a non-Spring test instead.
        //   Reason: R002 Missing observers.
        //   Diffblue Cover was unable to create an assertion.
        //   Add getters for the following fields or make them package-private:
        //     932/0x00000008012b4f38.arg$1

        UserRepository userRepository = mock(UserRepository.class);
        when(userRepository.findByEmail((String) any())).thenThrow(new UsernameNotFoundException("User not found"));
        assertThrows(UsernameNotFoundException.class,
                () -> (new ApplicationConfig(userRepository)).userDetailsService().loadUserByUsername("foo"));
        verify(userRepository).findByEmail((String) any());
    }

    /**
     * Method under test: {@link ApplicationConfig#authenticationProvider()}
     */
    @Test
    void testAuthenticationProvider() {
        assertTrue(applicationConfig.authenticationProvider() instanceof DaoAuthenticationProvider);
    }

    /**
     * Method under test: {@link ApplicationConfig#authenticationManager(AuthenticationConfiguration)}
     */
    @Test
    void testAuthenticationManager() throws Exception {
        assertTrue(applicationConfig.authenticationManager(new AuthenticationConfiguration()) instanceof ProviderManager);
    }

    /**
     * Method under test: {@link ApplicationConfig#authenticationManager(AuthenticationConfiguration)}
     */
    @Test
    void testAuthenticationManager2() throws Exception {
        AuthenticationConfiguration authenticationConfiguration = new AuthenticationConfiguration();
        authenticationConfiguration.setApplicationContext(mock(AnnotationConfigApplicationContext.class));
        assertTrue(applicationConfig.authenticationManager(authenticationConfiguration) instanceof ProviderManager);
    }

    /**
     * Method under test: {@link ApplicationConfig#passwordEncoder()}
     */
    @Test
    void testPasswordEncoder() {
        assertTrue(applicationConfig.passwordEncoder() instanceof BCryptPasswordEncoder);
    }
}

