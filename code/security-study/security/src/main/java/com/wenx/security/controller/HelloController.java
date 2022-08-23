package com.wenx.security.controller;

import com.wenx.security.service.MethodService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {

    @GetMapping("/hello")
    public String hello(){
        return "SECURITY";
    }

    @GetMapping("/admin/hello")
    String helloAdmin(){
        return "hello admin";
    }

    @GetMapping("/user/hello")
    String userAdmin(){
        return "hello user";
    }

    @GetMapping("/login")
    String userLogin(){
        return "请登录";
    }

    @Autowired
    MethodService methodService;

    @GetMapping("/admin/hello1")
    String hello1(){
        return methodService.admin();
    }

    @GetMapping("/user/hello2")
    String hello2(){
        return methodService.user();
    }

    @GetMapping("/user/hello3")
    String hello3(){
        return methodService.hello();
    }
}