# 简易搭建 Security OAuth2 项目基于 password 模式

## 引入依赖

```xml
    <dependencies>
        <!-- https://mvnrepository.com/artifact/org.springframework.security.oauth/spring-security-oauth2 -->
        <dependency>
            <groupId>org.springframework.security.oauth</groupId>
            <artifactId>spring-security-oauth2</artifactId>
            <version>2.5.2.RELEASE</version>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-data-redis</artifactId>
        </dependency>

        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>

        <dependency>
            <groupId>org.projectlombok</groupId>
            <artifactId>lombok</artifactId>
            <optional>true</optional>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-test</artifactId>
            <scope>test</scope>
            <exclusions>
                <exclusion>
                    <groupId>org.junit.vintage</groupId>
                    <artifactId>junit-vintage-engine</artifactId>
                </exclusion>
            </exclusions>
        </dependency>
        <dependency>
            <groupId>org.springframework.security</groupId>
            <artifactId>spring-security-test</artifactId>
            <scope>test</scope>
        </dependency>
    </dependencies>

```

## 引入授权服务器

```java
@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    RedisConnectionFactory redisConnectionFactory;

    @Autowired
    UserDetailsService userDetailsService;

    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory()
                .withClient("password")
                .authorizedGrantTypes("password","refresh_token")
                .accessTokenValiditySeconds(1800)
                .resourceIds("rid")
                .scopes("all")
                .secret("$2a$10$igDDIJWXnYW3ZT7w.DkLx.IU4KInjbtZMXK4gjYXyyrowcx.mKjpO");
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints.tokenStore(new RedisTokenStore(redisConnectionFactory))
                .authenticationManager(authenticationManager)
                .userDetailsService(userDetailsService);
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        security.allowFormAuthenticationForClients();
    }
}
```

## 引入资源服务器

```java
@Configuration
@EnableResourceServer
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {

    @Override
    public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
        resources.resourceId("rid")
                .stateless(true) //基于令牌认证
        ;
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests().antMatchers("/admin/**")
                .hasRole("admin")
                .antMatchers("/user/**").hasRole("user")
                .anyRequest().authenticated();
    }
}
```

## 客户端搭建

```java
@EnableWebSecurity
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    @Bean
    protected AuthenticationManager authenticationManager() throws Exception {
        return super.authenticationManager();
    }

    @Override
    @Bean
    protected UserDetailsService userDetailsService() {
        return super.userDetailsService();
    }



    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("admin").password("123").roles("admin")
                .and()
                .withUser("user").password("123").roles("user");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.antMatcher("/oauth/**")
                .authorizeRequests()
                .antMatchers("/oauth/**")
                .permitAll()
                .and()
                .csrf().disable();
    }
}
```

## 测试

首先在postman中发送 post 请求：`http://localhost:8080/oauth/token`获取到参数

需要携带的参数：

> client_id=password&client_secret=123&grant_type=password&username=admin&password=123&scpoe=all
>
> - client_id:客户端ID
> - client_secret: 客户端密钥
> - grant_type:权限类型
> - username:用户名
> - password:密码
> - scope:范围

返回如下：

```xml
{
    "access_token": "aPmB0d6pK4ZKqnmQDEoWUqtww5M",
    "token_type": "bearer",
    "refresh_token": "zAgClPAjmXvjs6VA_DaDjuvMj2Y",
    "expires_in": 1799,
    "scope": "all"
}
```

当我们需要访问资源的时候发送请求需要携带请求头：

`Authorization=Bearer aPmB0d6pK4ZKqnmQDEoWUqtww5M`

这样就可以成功获取到资源

我们的 token 是有过期时间的，当我们需要刷新 token 的时候需要发送请求：

携带参数：

```java
client_id=password&client_secret=123&grant_type=refresh_token&refresh_token=zAgClPAjmXvjs6VA_DaDjuvMj2Y&
```

> - client_id
> - client_secret
> - grant_type
> - refresh_token

返回如下：

```json
{
    "access_token": "tJjJfcmCwHx-vGPraXlwyPcsCz8",
    "token_type": "bearer",
    "refresh_token": "zAgClPAjmXvjs6VA_DaDjuvMj2Y",
    "expires_in": 1799,
    "scope": "all"
}
```

这样就可以重新访问资源了。