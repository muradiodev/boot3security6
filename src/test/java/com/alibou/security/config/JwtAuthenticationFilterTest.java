package com.alibou.security.config;

import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyBoolean;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.alibou.security.user.Role;
import com.alibou.security.user.User;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

import org.apache.catalina.connector.Response;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.web.WebAppConfiguration;

@ContextConfiguration(classes = {JwtAuthenticationFilter.class})
@WebAppConfiguration
@ExtendWith(SpringExtension.class)
class JwtAuthenticationFilterTest {
    @Autowired
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    @MockBean
    private JwtService jwtService;

    @MockBean
    private UserDetailsService userDetailsService;

    /**
     * Method under test: {@link JwtAuthenticationFilter#doFilterInternal(HttpServletRequest, HttpServletResponse, FilterChain)}
     */
    @Test
    void testDoFilterInternal() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        Response response = new Response();
        FilterChain filterChain = mock(FilterChain.class);
        doNothing().when(filterChain).doFilter((ServletRequest) any(), (ServletResponse) any());
        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);
        verify(filterChain).doFilter((ServletRequest) any(), (ServletResponse) any());
    }

    /**
     * Method under test: {@link JwtAuthenticationFilter#doFilterInternal(HttpServletRequest, HttpServletResponse, FilterChain)}
     */
    @Test
    @Disabled("TODO: Complete this test")
    void testDoFilterInternal2() throws ServletException, IOException {
        // TODO: Complete this test.
        //   Reason: R013 No inputs found that don't throw a trivial exception.
        //   Diffblue Cover tried to run the arrange/act section, but the method under
        //   test threw
        //   java.lang.NullPointerException: Cannot invoke "jakarta.servlet.http.HttpServletRequest.getHeader(String)" because "request" is null
        //       at com.alibou.security.config.JwtAuthenticationFilter.doFilterInternal(JwtAuthenticationFilter.java:32)
        //   See https://diff.blue/R013 to resolve this issue.

        Response response = new Response();
        FilterChain filterChain = mock(FilterChain.class);
        doNothing().when(filterChain).doFilter((ServletRequest) any(), (ServletResponse) any());
        jwtAuthenticationFilter.doFilterInternal(null, response, filterChain);
    }

    /**
     * Method under test: {@link JwtAuthenticationFilter#doFilterInternal(HttpServletRequest, HttpServletResponse, FilterChain)}
     */
    @Test
    void testDoFilterInternal3() throws ServletException, IOException {
        HttpServletRequestWrapper httpServletRequestWrapper = mock(HttpServletRequestWrapper.class);
        when(httpServletRequestWrapper.getHeader((String) any())).thenReturn("https://example.org/example");
        Response response = new Response();
        FilterChain filterChain = mock(FilterChain.class);
        doNothing().when(filterChain).doFilter((ServletRequest) any(), (ServletResponse) any());
        jwtAuthenticationFilter.doFilterInternal(httpServletRequestWrapper, response, filterChain);
        verify(httpServletRequestWrapper).getHeader((String) any());
        verify(filterChain).doFilter((ServletRequest) any(), (ServletResponse) any());
    }

    /**
     * Method under test: {@link JwtAuthenticationFilter#doFilterInternal(HttpServletRequest, HttpServletResponse, FilterChain)}
     */
    @Test
    @Disabled("TODO: Complete this test")
    void testDoFilterInternal4() throws ServletException, IOException, UsernameNotFoundException {
        // TODO: Complete this test.
        //   Reason: R013 No inputs found that don't throw a trivial exception.
        //   Diffblue Cover tried to run the arrange/act section, but the method under
        //   test threw
        //   java.lang.NullPointerException: Cannot invoke "com.alibou.security.user.Role.name()" because "this.role" is null
        //       at com.alibou.security.user.User.getAuthorities(User.java:40)
        //       at com.alibou.security.config.JwtAuthenticationFilter.doFilterInternal(JwtAuthenticationFilter.java:47)
        //   See https://diff.blue/R013 to resolve this issue.

        when(jwtService.isTokenValid((String) any(), (UserDetails) any())).thenReturn(true);
        when(jwtService.extractUsername((String) any())).thenReturn("janedoe");
        when(userDetailsService.loadUserByUsername((String) any())).thenReturn(new User());
        HttpServletRequestWrapper httpServletRequestWrapper = mock(HttpServletRequestWrapper.class);
        when(httpServletRequestWrapper.getHeader((String) any())).thenReturn("Bearer ");
        Response response = new Response();
        FilterChain filterChain = mock(FilterChain.class);
        doNothing().when(filterChain).doFilter((ServletRequest) any(), (ServletResponse) any());
        jwtAuthenticationFilter.doFilterInternal(httpServletRequestWrapper, response, filterChain);
    }

    /**
     * Method under test: {@link JwtAuthenticationFilter#doFilterInternal(HttpServletRequest, HttpServletResponse, FilterChain)}
     */
    @Test
    void testDoFilterInternal5() throws ServletException, IOException, UsernameNotFoundException {
        when(jwtService.isTokenValid((String) any(), (UserDetails) any())).thenReturn(true);
        when(jwtService.extractUsername((String) any())).thenReturn("janedoe");

        User user = new User();
        user.setRole(Role.USER);
        when(userDetailsService.loadUserByUsername((String) any())).thenReturn(user);
        HttpServletRequestWrapper httpServletRequestWrapper = mock(HttpServletRequestWrapper.class);
        when(httpServletRequestWrapper.getSession(anyBoolean())).thenReturn(new MockHttpSession());
        when(httpServletRequestWrapper.getRemoteAddr()).thenReturn("42 Main St");
        when(httpServletRequestWrapper.getHeader((String) any())).thenReturn("Bearer ");
        Response response = new Response();
        FilterChain filterChain = mock(FilterChain.class);
        doNothing().when(filterChain).doFilter((ServletRequest) any(), (ServletResponse) any());
        jwtAuthenticationFilter.doFilterInternal(httpServletRequestWrapper, response, filterChain);
        verify(jwtService).isTokenValid((String) any(), (UserDetails) any());
        verify(jwtService).extractUsername((String) any());
        verify(userDetailsService).loadUserByUsername((String) any());
        verify(httpServletRequestWrapper).getSession(anyBoolean());
        verify(httpServletRequestWrapper).getRemoteAddr();
        verify(httpServletRequestWrapper).getHeader((String) any());
        verify(filterChain).doFilter((ServletRequest) any(), (ServletResponse) any());
    }

    /**
     * Method under test: {@link JwtAuthenticationFilter#doFilterInternal(HttpServletRequest, HttpServletResponse, FilterChain)}
     */
    @Test
    void testDoFilterInternal6() throws ServletException, IOException, UsernameNotFoundException {
        when(jwtService.isTokenValid((String) any(), (UserDetails) any())).thenReturn(false);
        when(jwtService.extractUsername((String) any())).thenReturn("janedoe");

        User user = new User();
        user.setRole(Role.USER);
        when(userDetailsService.loadUserByUsername((String) any())).thenReturn(user);
        HttpServletRequestWrapper httpServletRequestWrapper = mock(HttpServletRequestWrapper.class);
        when(httpServletRequestWrapper.getSession(anyBoolean())).thenReturn(new MockHttpSession());
        when(httpServletRequestWrapper.getRemoteAddr()).thenReturn("42 Main St");
        when(httpServletRequestWrapper.getHeader((String) any())).thenReturn("Bearer ");
        Response response = new Response();
        FilterChain filterChain = mock(FilterChain.class);
        doNothing().when(filterChain).doFilter((ServletRequest) any(), (ServletResponse) any());
        jwtAuthenticationFilter.doFilterInternal(httpServletRequestWrapper, response, filterChain);
        verify(jwtService).isTokenValid((String) any(), (UserDetails) any());
        verify(jwtService).extractUsername((String) any());
        verify(userDetailsService).loadUserByUsername((String) any());
        verify(httpServletRequestWrapper).getHeader((String) any());
        verify(filterChain).doFilter((ServletRequest) any(), (ServletResponse) any());
    }

    /**
     * Method under test: {@link JwtAuthenticationFilter#doFilterInternal(HttpServletRequest, HttpServletResponse, FilterChain)}
     */
    @Test
    void testDoFilterInternal7() throws ServletException, IOException, UsernameNotFoundException {
        when(jwtService.isTokenValid((String) any(), (UserDetails) any())).thenReturn(true);
        when(jwtService.extractUsername((String) any())).thenReturn(null);

        User user = new User();
        user.setRole(Role.USER);
        when(userDetailsService.loadUserByUsername((String) any())).thenReturn(user);
        HttpServletRequestWrapper httpServletRequestWrapper = mock(HttpServletRequestWrapper.class);
        when(httpServletRequestWrapper.getSession(anyBoolean())).thenReturn(new MockHttpSession());
        when(httpServletRequestWrapper.getRemoteAddr()).thenReturn("42 Main St");
        when(httpServletRequestWrapper.getHeader((String) any())).thenReturn("Bearer ");
        Response response = new Response();
        FilterChain filterChain = mock(FilterChain.class);
        doNothing().when(filterChain).doFilter((ServletRequest) any(), (ServletResponse) any());
        jwtAuthenticationFilter.doFilterInternal(httpServletRequestWrapper, response, filterChain);
        verify(jwtService).extractUsername((String) any());
        verify(httpServletRequestWrapper).getHeader((String) any());
        verify(filterChain).doFilter((ServletRequest) any(), (ServletResponse) any());
    }
}

