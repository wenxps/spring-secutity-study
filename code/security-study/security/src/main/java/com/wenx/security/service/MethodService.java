package com.wenx.security.service;

import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

@Service
public class MethodService {

    @PreAuthorize("hasRole('admin')")
    public String admin(){
        return "method admin";
    }


    @Secured("ROLE_user")
    public String user(){
        return "method user";
    }

    @PreAuthorize("hasAnyRole('admin','user')")
    public String hello(){
        return "method hello";
    }


}