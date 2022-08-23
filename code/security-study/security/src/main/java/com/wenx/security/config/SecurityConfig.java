package com.wenx.security.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Configurable;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.*;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.security.auth.login.CredentialExpiredException;
import java.io.PrintWriter;
import java.util.HashMap;

@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true,securedEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().withUser("admin").password(passwordEncoder().encode("123")).roles("admin");
        auth.inMemoryAuthentication().withUser("user").password(passwordEncoder().encode("123")).roles("user");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // 请求规则
        http.authorizeRequests()
                .antMatchers("/admin/**").hasRole("admin")
                .antMatchers("/user/**").hasAnyRole("user","admin")
                // 所有请求都进行认证
                .anyRequest().authenticated()
                .and()
                // 开启表单登陆
                .formLogin()
                // 用户登录请求 URL
                .loginProcessingUrl("/doLogin")
                // 登录页面 URL
                .loginPage("/login")
                // 自定义用户名参数
                .usernameParameter("uname")
                // 自定义密码参数
                .passwordParameter("passwd")
                // 登陆成功跳转的请求
                //.successForwardUrl("/success/toPage")
                // 登陆成功处理器[前后端分离]
                .successHandler((req,resp,auth)->{
                    resp.setContentType("application/json;charset=utf-8");
                    PrintWriter writer = resp.getWriter();
                    HashMap<String, Object> map = new HashMap<>();
                    map.put("status",200);
                    map.put("message",auth.getPrincipal());
                    writer.write(new ObjectMapper().writeValueAsString(map));
                    writer.flush();
                    writer.close();
                })
                // 登录失败页面跳转页面
                //.failureForwardUrl("/fail/toPage")
                // 登陆失败处理器[前后端分离]
                .failureHandler((req,resp,e)->{
                    resp.setContentType("application/json;charset=utf-8");
                    PrintWriter writer = resp.getWriter();
                    HashMap<String, Object> map = new HashMap<>();
                    map.put("status",401);
                    if(e instanceof LockedException){
                        map.put("message","账户被锁定");
                    }else if(e instanceof BadCredentialsException){
                        map.put("message","用户名或密码输入错误");
                    }else if(e instanceof DisabledException){
                        map.put("message","账户被禁用");
                    }else if(e instanceof AccountExpiredException){
                        map.put("message","账户过期");
                    }else if(e instanceof CredentialsExpiredException){
                        map.put("message","密码过期");
                    }else {
                        map.put("message","登录失败");
                    }
                    writer.write(new ObjectMapper().writeValueAsString(map));
                    writer.flush();
                    writer.close();
                })
                // 登录请求都放行
                .permitAll()
                .and()
                //关闭 CSRF 攻击
                .csrf().disable()
                // 未认证
                .exceptionHandling()
                .authenticationEntryPoint((req, resp, authException) -> {
                            resp.setContentType("application/json;charset=utf-8");
                            PrintWriter out = resp.getWriter();
                            out.write("尚未登录，请先登录");
                            out.flush();
                            out.close();
                        }
                );
    }
}