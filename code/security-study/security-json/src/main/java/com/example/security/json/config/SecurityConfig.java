package com.example.security.json.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.*;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Bean
    JsonFilter jsonFilter() throws Exception {
        JsonFilter loginFilter = new JsonFilter();
        loginFilter.setAuthenticationSuccessHandler(new AuthenticationSuccessHandler() {
            @Override
            public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                response.setContentType("application/json;charset=utf-8");
                PrintWriter out = response.getWriter();
//                User principal = (User) authentication.getPrincipal();
//                org.springframework.security.core.userdetails.User hr = (User) authentication.getPrincipal();
//                principal.setPassword(null);



                Map<String,Object> map = new HashMap<>();
                map.put("message","登陆成功");
                map.put("data",authentication.getPrincipal());
//                map.put("data",principal);
                String s = new ObjectMapper().writeValueAsString(map);
                System.out.println("success=>"+s);
                out.write(s);
                out.flush();
                out.close();
            }
        });
        loginFilter.setAuthenticationFailureHandler(new AuthenticationFailureHandler() {
            @Override
            public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                response.setContentType("application/json;charset=utf-8");
                PrintWriter out = response.getWriter();
                Map<String,String> map = new HashMap<>();
                map.put("error",exception.getMessage());
                if (exception instanceof LockedException) {
                    map.put("message","账户被锁定，请联系管理员!");
                } else if (exception instanceof CredentialsExpiredException) {
                    map.put("message","密码过期，请联系管理员!");
                } else if (exception instanceof AccountExpiredException) {
                    map.put("message","账户过期，请联系管理员!");
                } else if (exception instanceof BadCredentialsException) {
                    map.put("message","用户名或者密码输入错误，请联系管理员!");
                }
                out.write(new ObjectMapper().writeValueAsString(map));
                out.flush();
                out.close();
            }
        });
        loginFilter.setAuthenticationManager(authenticationManagerBean());
        loginFilter.setFilterProcessesUrl("/doLogin");
        return loginFilter;
    }


    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("user").password(passwordEncoder().encode("123")).roles("user")
                .and()
                .withUser("admin").password("123").roles("admin");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/admin/**").hasRole("admin")
                .antMatchers("/user/**").hasRole("user")
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .permitAll()
                .and()
                .csrf().disable();

        http.addFilterAt(jsonFilter(), UsernamePasswordAuthenticationFilter.class);
    }
}