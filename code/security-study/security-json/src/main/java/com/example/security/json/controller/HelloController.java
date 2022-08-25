package com.example.security.json.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {

    @GetMapping("/user/hello")
    String user(){
        return "user";
    }

    @GetMapping("/admin/hello")
    String admin(){
        return "admin";
    }
}