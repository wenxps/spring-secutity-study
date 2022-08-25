title: '前后端分离中，使用 JSON进行登录'

---

## 服务端接口实现

首先大家知道，用户登录的用户名/密码是在 `UsernamePasswordAuthenticationFilter` 类中处理的，具体的处理代码如下：

```java
public Authentication attemptAuthentication(HttpServletRequest request,
		HttpServletResponse response) throws AuthenticationException {
	String username = obtainUsername(request);
	String password = obtainPassword(request);
    //省略
}
protected String obtainPassword(HttpServletRequest request) {
	return request.getParameter(passwordParameter);
}
protected String obtainUsername(HttpServletRequest request) {
	return request.getParameter(usernameParameter);
}
```

从这段代码中，我们就可以看出来为什么 Spring Security 默认是通过 key/value 的形式来传递登录参数，因为它处理的方式就是 request.getParameter。

所以我们要定义成 JSON 的，思路很简单，就是自定义来定义一个过滤器代替 `UsernamePasswordAuthenticationFilter` ，然后在获取参数的时候，换一种方式就行了。

## 自定义过滤器

接下来我们来自定义一个过滤器代替 `UsernamePasswordAuthenticationFilter` ，如下：

```java
package com.example.security.json.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class JsonFilter extends UsernamePasswordAuthenticationFilter {

    private static final Log log = LogFactory.getLog(JsonFilter.class);


    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        if (!"POST".equals(request.getMethod())) {
            throw new AuthenticationServiceException(
                    "Authentication method not supported: " + request.getMethod());
        }

        if (request.getContentType().equals(MediaType.APPLICATION_JSON_VALUE) || request.getContentType().equals(MediaType.APPLICATION_JSON_UTF8_VALUE)) {
            log.info("JSON登录");
            Map<String, String> loginData = new HashMap<>();
            try {
                loginData = new ObjectMapper().readValue(request.getInputStream(), Map.class);
            } catch (IOException e) {
            }


            String username = loginData.get(getUsernameParameter());
            String password = loginData.get(getPasswordParameter());



            if (username == null) {
                username = "";
            }
            if (password == null) {
                password = "";
            }



            username = username.trim();
            UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(
                    username, password);
            setDetails(request, authRequest);
            return this.getAuthenticationManager().authenticate(authRequest);
        }
        else {
            System.out.println("kv登录");
            return super.attemptAuthentication(request, response);
        }
    }

}
```

这段逻辑我们基本上是模仿官方提供的 `UsernamePasswordAuthenticationFilter` 来写的，我来给大家稍微解释下：

1. 首先登录请求肯定是 POST，如果不是 POST ，直接抛出异常，后面的也不处理了。
2. 因为要在这里处理验证码，所以第二步从 session 中把已经下发过的验证码的值拿出来。
3. 接下来通过 contentType 来判断当前请求是否通过 JSON 来传递参数，如果是通过 JSON 传递参数，则按照 JSON 的方式解析，如果不是，则调用 super.attemptAuthentication 方法，进入父类的处理逻辑中，也就是说，我们自定义的这个类，既支持 JSON 形式传递参数，也支持 key/value 形式传递参数。
4. 如果是 JSON 形式的数据，我们就通过读取 request 中的 I/O 流，将 JSON 映射到一个 Map 上。

5. 接下来从 Map 中取出 username 和 password，构造 UsernamePasswordAuthenticationToken 对象并作校验

过滤器定义完成后，接下来用我们自定义的过滤器代替默认的 `UsernamePasswordAuthenticationFilter`，首先我们需要提供一个 JsonFilter的实例：

```java
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
```

当我们代替了 `UsernamePasswordAuthenticationFilter` 之后，原本在 SecurityConfig#configure 方法中关于 form 表单的配置就会失效，那些失效的属性，都可以在配置 LoginFilter 实例的时候配置。

另外记得配置一个 AuthenticationManager，根据 WebSecurityConfigurerAdapter 中提供的配置即可。

FilterProcessUrl 则可以根据实际情况配置，如果不配置，默认的就是 `/login`。

最后，我们用自定义的 JsonFilter 实例代替 `UsernamePasswordAuthenticationFilter`，如下：

```java
@Override
protected void configure(HttpSecurity http) throws Exception {
    http.authorizeRequests()
        ...
        //省略
    http.addFilterAt(loginFilter(), UsernamePasswordAuthenticationFilter.class);
}
```

调用 addFilterAt 方法完成替换操作。