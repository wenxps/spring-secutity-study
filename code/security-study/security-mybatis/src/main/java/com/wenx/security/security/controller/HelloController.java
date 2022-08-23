package com.wenx.security.security.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {

    @GetMapping("/hello")
    String hello(){
        return "hello";
    }

    @GetMapping("/dba/hello")
    String dbaHello(){
        return "DBA hello";
    }

    @GetMapping("/admin/hello")
    String adminHello(){
        return "admin hello";
    }

    @GetMapping("/user/hello")
    String userHello(){
        return "user hello";
    }

}