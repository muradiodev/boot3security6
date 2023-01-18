package com.alibou.security.demo;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;

class DemoControllerTest {
    /**
     * Method under test: {@link DemoController#sayHello()}
     */
    @Test
    void testSayHello() {
        //   Diffblue Cover was unable to write a Spring test,
        //   so wrote a non-Spring test instead.
        //   Diffblue AI was unable to find a test

        ResponseEntity<String> actualSayHelloResult = (new DemoController()).sayHello();
        assertEquals("Hello from secured endpoint", actualSayHelloResult.getBody());
        assertEquals(200, actualSayHelloResult.getStatusCodeValue());
        assertTrue(actualSayHelloResult.getHeaders().isEmpty());
    }
}

