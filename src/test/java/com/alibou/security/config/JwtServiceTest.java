package com.alibou.security.config;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.alibou.security.user.User;
import io.jsonwebtoken.Claims;

import java.util.HashMap;
import java.util.Map;

import java.util.function.Function;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;

@ContextConfiguration(classes = {JwtService.class})
@ExtendWith(SpringExtension.class)
class JwtServiceTest {
    @Autowired
    private JwtService jwtService;

    /**
     * Method under test: {@link JwtService#extractUsername(String)}
     */
    @Test
    @Disabled("TODO: Complete this test")
    void testExtractUsername() {
        // TODO: Complete this test.
        //   Reason: R013 No inputs found that don't throw a trivial exception.
        //   Diffblue Cover tried to run the arrange/act section, but the method under
        //   test threw
        //   io.jsonwebtoken.MalformedJwtException: JWT strings must contain exactly 2 period characters. Found: 0
        //       at io.jsonwebtoken.impl.DefaultJwtParser.parse(DefaultJwtParser.java:275)
        //       at io.jsonwebtoken.impl.DefaultJwtParser.parse(DefaultJwtParser.java:529)
        //       at io.jsonwebtoken.impl.DefaultJwtParser.parseClaimsJws(DefaultJwtParser.java:589)
        //       at io.jsonwebtoken.impl.ImmutableJwtParser.parseClaimsJws(ImmutableJwtParser.java:173)
        //       at com.alibou.security.config.JwtService.extractAllClaims(JwtService.java:66)
        //       at com.alibou.security.config.JwtService.extractClaim(JwtService.java:26)
        //       at com.alibou.security.config.JwtService.extractUsername(JwtService.java:22)
        //   See https://diff.blue/R013 to resolve this issue.

        jwtService.extractUsername("ABC123");
    }

    /**
     * Method under test: {@link JwtService#extractUsername(String)}
     */
    @Test
    @Disabled("TODO: Complete this test")
    void testExtractUsername2() {
        // TODO: Complete this test.
        //   Reason: R013 No inputs found that don't throw a trivial exception.
        //   Diffblue Cover tried to run the arrange/act section, but the method under
        //   test threw
        //   java.lang.IllegalArgumentException: JWT String argument cannot be null or empty.
        //       at io.jsonwebtoken.lang.Assert.hasText(Assert.java:132)
        //       at io.jsonwebtoken.impl.DefaultJwtParser.parse(DefaultJwtParser.java:527)
        //       at io.jsonwebtoken.impl.DefaultJwtParser.parseClaimsJws(DefaultJwtParser.java:589)
        //       at io.jsonwebtoken.impl.ImmutableJwtParser.parseClaimsJws(ImmutableJwtParser.java:173)
        //       at com.alibou.security.config.JwtService.extractAllClaims(JwtService.java:66)
        //       at com.alibou.security.config.JwtService.extractClaim(JwtService.java:26)
        //       at com.alibou.security.config.JwtService.extractUsername(JwtService.java:22)
        //   See https://diff.blue/R013 to resolve this issue.

        jwtService.extractUsername("");
    }

    /**
     * Method under test: {@link JwtService#extractClaim(String, Function)}
     */
    @Test
    @Disabled("TODO: Complete this test")
    void testExtractClaim() {
        // TODO: Complete this test.
        //   Reason: R005 Unable to load class.
        //   Class: reactor.netty.http.server.HttpServer
        //   Please check that the class is available on your test runtime classpath.
        //   See https://diff.blue/R005 to resolve this issue.

        // Arrange
        // TODO: Populate arranged inputs
        String token = "";
        Function<Claims, Object> claimsResolver = null;

        // Act
        Object actualExtractClaimResult = this.jwtService.extractClaim(token, claimsResolver);

        // Assert
        // TODO: Add assertions on result
    }

    /**
     * Method under test: {@link JwtService#generateToken(Map, UserDetails)}
     */
    @Test
    @Disabled("TODO: Complete this test")
    void testGenerateToken() {
        // TODO: Complete this test.
        //   Reason: R031 Method may be time-sensitive.
        //   Diffblue Cover was only able to write tests which were time-sensitive.
        //   The assertions no longer passed when run at an alternate date, time and
        //   timezone. Try refactoring the method to take a java.time.Clock instance so
        //   that the time can be parameterized during testing.
        //   Please see https://diff.blue/R031

        HashMap<String, Object> extraClaims = new HashMap<>();
        jwtService.generateToken(extraClaims, new User());
    }

    /**
     * Method under test: {@link JwtService#generateToken(Map, UserDetails)}
     */
    @Test
    @Disabled("TODO: Complete this test")
    void testGenerateToken2() {
        // TODO: Complete this test.
        //   Reason: R031 Method may be time-sensitive.
        //   Diffblue Cover was only able to write tests which were time-sensitive.
        //   The assertions no longer passed when run at an alternate date, time and
        //   timezone. Try refactoring the method to take a java.time.Clock instance so
        //   that the time can be parameterized during testing.
        //   Please see https://diff.blue/R031

        HashMap<String, Object> stringObjectMap = new HashMap<>();
        stringObjectMap.put("404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970", "Value");
        jwtService.generateToken(stringObjectMap, new User());
    }

    /**
     * Method under test: {@link JwtService#generateToken(Map, UserDetails)}
     */
    @Test
    @Disabled("TODO: Complete this test")
    void testGenerateToken3() {
        // TODO: Complete this test.
        //   Reason: R013 No inputs found that don't throw a trivial exception.
        //   Diffblue Cover tried to run the arrange/act section, but the method under
        //   test threw
        //   java.lang.NullPointerException: Cannot invoke "org.springframework.security.core.userdetails.UserDetails.getUsername()" because "userDetails" is null
        //       at com.alibou.security.config.JwtService.generateToken(JwtService.java:41)
        //   See https://diff.blue/R013 to resolve this issue.

        jwtService.generateToken(new HashMap<>(), null);
    }

    /**
     * Method under test: {@link JwtService#generateToken(Map, UserDetails)}
     */
    @Test
    void testGenerateToken4() {
        HashMap<String, Object> stringObjectMap = new HashMap<>();
        stringObjectMap.put("404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970", "Value");
        stringObjectMap.put("404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970", "Value");
        User user = mock(User.class);
        when(user.getUsername()).thenReturn("janedoe");
        jwtService.generateToken(stringObjectMap, user);
        verify(user).getUsername();
    }

    /**
     * Method under test: {@link JwtService#generateToken(UserDetails)}
     */
    @Test
    @Disabled("TODO: Complete this test")
    void testGenerateToken5() {
        // TODO: Complete this test.
        //   Reason: R031 Method may be time-sensitive.
        //   Diffblue Cover was only able to write tests which were time-sensitive.
        //   The assertions no longer passed when run at an alternate date, time and
        //   timezone. Try refactoring the method to take a java.time.Clock instance so
        //   that the time can be parameterized during testing.
        //   Please see https://diff.blue/R031

        jwtService.generateToken(new User());
    }

    /**
     * Method under test: {@link JwtService#generateToken(UserDetails)}
     */
    @Test
    @Disabled("TODO: Complete this test")
    void testGenerateToken6() {
        // TODO: Complete this test.
        //   Reason: R013 No inputs found that don't throw a trivial exception.
        //   Diffblue Cover tried to run the arrange/act section, but the method under
        //   test threw
        //   java.lang.NullPointerException: Cannot invoke "org.springframework.security.core.userdetails.UserDetails.getUsername()" because "userDetails" is null
        //       at com.alibou.security.config.JwtService.generateToken(JwtService.java:41)
        //       at com.alibou.security.config.JwtService.generateToken(JwtService.java:31)
        //   See https://diff.blue/R013 to resolve this issue.

        jwtService.generateToken(null);
    }

    /**
     * Method under test: {@link JwtService#isTokenValid(String, UserDetails)}
     */
    @Test
    @Disabled("TODO: Complete this test")
    void testIsTokenValid() {
        // TODO: Complete this test.
        //   Reason: R013 No inputs found that don't throw a trivial exception.
        //   Diffblue Cover tried to run the arrange/act section, but the method under
        //   test threw
        //   io.jsonwebtoken.MalformedJwtException: JWT strings must contain exactly 2 period characters. Found: 0
        //       at io.jsonwebtoken.impl.DefaultJwtParser.parse(DefaultJwtParser.java:275)
        //       at io.jsonwebtoken.impl.DefaultJwtParser.parse(DefaultJwtParser.java:529)
        //       at io.jsonwebtoken.impl.DefaultJwtParser.parseClaimsJws(DefaultJwtParser.java:589)
        //       at io.jsonwebtoken.impl.ImmutableJwtParser.parseClaimsJws(ImmutableJwtParser.java:173)
        //       at com.alibou.security.config.JwtService.extractAllClaims(JwtService.java:66)
        //       at com.alibou.security.config.JwtService.extractClaim(JwtService.java:26)
        //       at com.alibou.security.config.JwtService.extractUsername(JwtService.java:22)
        //       at com.alibou.security.config.JwtService.isTokenValid(JwtService.java:49)
        //   See https://diff.blue/R013 to resolve this issue.

        jwtService.isTokenValid("ABC123", new User());
    }

    /**
     * Method under test: {@link JwtService#isTokenValid(String, UserDetails)}
     */
    @Test
    @Disabled("TODO: Complete this test")
    void testIsTokenValid2() {
        // TODO: Complete this test.
        //   Reason: R013 No inputs found that don't throw a trivial exception.
        //   Diffblue Cover tried to run the arrange/act section, but the method under
        //   test threw
        //   java.lang.IllegalArgumentException: JWT String argument cannot be null or empty.
        //       at io.jsonwebtoken.lang.Assert.hasText(Assert.java:132)
        //       at io.jsonwebtoken.impl.DefaultJwtParser.parse(DefaultJwtParser.java:527)
        //       at io.jsonwebtoken.impl.DefaultJwtParser.parseClaimsJws(DefaultJwtParser.java:589)
        //       at io.jsonwebtoken.impl.ImmutableJwtParser.parseClaimsJws(ImmutableJwtParser.java:173)
        //       at com.alibou.security.config.JwtService.extractAllClaims(JwtService.java:66)
        //       at com.alibou.security.config.JwtService.extractClaim(JwtService.java:26)
        //       at com.alibou.security.config.JwtService.extractUsername(JwtService.java:22)
        //       at com.alibou.security.config.JwtService.isTokenValid(JwtService.java:49)
        //   See https://diff.blue/R013 to resolve this issue.

        jwtService.isTokenValid("", new User());
    }

    /**
     * Method under test: {@link JwtService#isTokenValid(String, UserDetails)}
     */
    @Test
    @Disabled("TODO: Complete this test")
    void testIsTokenValid3() {
        // TODO: Complete this test.
        //   Reason: R013 No inputs found that don't throw a trivial exception.
        //   Diffblue Cover tried to run the arrange/act section, but the method under
        //   test threw
        //   io.jsonwebtoken.MalformedJwtException: JWT strings must contain exactly 2 period characters. Found: 0
        //       at io.jsonwebtoken.impl.DefaultJwtParser.parse(DefaultJwtParser.java:275)
        //       at io.jsonwebtoken.impl.DefaultJwtParser.parse(DefaultJwtParser.java:529)
        //       at io.jsonwebtoken.impl.DefaultJwtParser.parseClaimsJws(DefaultJwtParser.java:589)
        //       at io.jsonwebtoken.impl.ImmutableJwtParser.parseClaimsJws(ImmutableJwtParser.java:173)
        //       at com.alibou.security.config.JwtService.extractAllClaims(JwtService.java:66)
        //       at com.alibou.security.config.JwtService.extractClaim(JwtService.java:26)
        //       at com.alibou.security.config.JwtService.extractUsername(JwtService.java:22)
        //       at com.alibou.security.config.JwtService.isTokenValid(JwtService.java:49)
        //   See https://diff.blue/R013 to resolve this issue.

        jwtService.isTokenValid("404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970", mock(User.class));
    }
}

