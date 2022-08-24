title: Spring Security 基本配置
cover: /gallery/covers/cover.jpg
categories: spring-boot spring-security
date: '2022-08-23 18:05:01'

---

## 1.新建项目

首先新建一个 Spring Boot 项目，创建时引入 Spring Security 依赖和 web 依赖

```xml
<dependencies>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-security</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
</dependencies>
```

项目创建成功后，我们添加一个测试的 HelloController，内容如下：

```java
@RestController
public class HelloController {

    @GetMapping("/hello")
    public String hello(){
        return "SECURITY";
    }
}
```

接下来什么事情都不用做，我们直接来启动项目。

在项目启动过程中，我们会看到如下一行日志：

```shell
Using generated security password: 30abfb1f-36e1-446a-a79b-f70024f589ab
```

这就是 Spring Security 为默认用户 user 生成的临时密码，是一个 UUID 字符串。

接下来我们去访问 `http://localhost:8080/hello` 接口，就可以看到自动重定向到登录页面了

在登录页面，默认的用户名就是 user，默认的登录密码则是项目启动时控制台打印出来的密码，输入用户名密码之后，就登录成功了，登录成功后，我们就可以访问到 /hello 接口了。

在 Spring Security 中，默认的登录页面和登录接口，都是 `/login` ，只不过一个是 get 请求（登录页面），另一个是 post 请求（登录接口）。

**大家可以看到，非常方便，一个依赖就保护了所有接口。**

有人说，你怎么知道知道生成的默认密码是一个 UUID 呢？

这个其实很好判断。

和用户相关的自动化配置类在 `UserDetailsServiceAutoConfiguration` 里边，在该类的 `getOrDeducePassword` 方法中，我们看到如下一行日志：

```java
if (user.isPasswordGenerated()) {
	logger.info(String.format("%n%nUsing generated security password: %s%n", user.getPassword()));
}
```

毫无疑问，我们在控制台看到的日志就是从这里打印出来的。打印的条件是 isPasswordGenerated 方法返回 true，即密码是默认生成的。

进而我们发现，user.getPassword 出现在 SecurityProperties 中，在 SecurityProperties 中我们看到如下定义：

```java
/**
 * Default user name.
 */
private String name = "user";
/**
 * Password for the default user name.
 */
private String password = UUID.randomUUID().toString();
private boolean passwordGenerated = true;
```

可以看到，默认的用户名就是 user，默认的密码则是 UUID，而默认情况下，passwordGenerated 也为 true。

## 2.用户配置

默认的密码有一个问题就是每次重启项目都会变，这很不方便。

在正式介绍数据库连接之前，松哥先和大家介绍两种非主流的用户名/密码配置方案。

### 2.1 配置文件

我们可以在 application.properties 中配置默认的用户名密码。

怎么配置呢？大家还记得上一小节我们说的 SecurityProperties，默认的用户就定义在它里边，是一个静态内部类，我们如果要定义自己的用户名密码，必然是要去覆盖默认配置，我们先来看下 SecurityProperties 的定义：

```java
@ConfigurationProperties(prefix = "spring.security")
public class SecurityProperties {
```

这就很清晰了，我们只需要以 spring.security.user 为前缀，去定义用户名密码即可：

```properties
spring.security.user.name=user
spring.security.user.password=123
spring.security.user.roles=admin
```

这就是我们新定义的用户名密码。

在 properties 中定义的用户名密码最终是通过 set 方法注入到属性中去的，这里我们顺便来看下 SecurityProperties.User#setPassword 方法:

从这里我们可以看到，application.properties 中定义的密码在注入进来之后，还顺便设置了 passwordGenerated 属性为 false，这个属性设置为 false 之后，控制台就不会打印默认的密码了。

此时重启项目，就可以使用自己定义的用户名/密码登录了。

### 2.2 配置类

除了上面的配置文件这种方式之外，我们也可以在配置类中配置用户名/密码。

在配置类中配置，我们就要指定 PasswordEncoder 了，这是一个非常关键的东西。

考虑到有的小伙伴对于 PasswordEncoder 还不太熟悉，因此，我这里先稍微给大家介绍一下 PasswordEncoder 到底是干嘛用的。要说 PasswordEncoder ，就得先说密码加密。

#### 2.2.1 为什么要加密

2011 年 12 月 21 日，有人在网络上公开了一个包含 600 万个 CSDN 用户资料的数据库，数据全部为明文储存，包含用户名、密码以及注册邮箱。事件发生后 CSDN 在微博、官方网站等渠道发出了声明，解释说此数据库系 2009 年备份所用，因不明原因泄露，已经向警方报案，后又在官网发出了公开道歉信。在接下来的十多天里，金山、网易、京东、当当、新浪等多家公司被卷入到这次事件中。整个事件中最触目惊心的莫过于 CSDN 把用户密码明文存储，由于很多用户是多个网站共用一个密码，因此一个网站密码泄露就会造成很大的安全隐患。由于有了这么多前车之鉴，我们现在做系统时，密码都要加密处理。

这次泄密，也留下了一些有趣的事情，特别是对于广大程序员设置密码这一项。人们从 CSDN 泄密的文件中，发现了一些好玩的密码，例如如下这些：

- `ppnn13%dkstFeb.1st` 这段密码的中文解析是：娉娉袅袅十三余，豆蔻梢头二月初。
- `csbt34.ydhl12s` 这段密码的中文解析是：池上碧苔三四点，叶底黄鹂一两声
- …

等等不一而足，你会发现很多程序员的人文素养还是非常高的，让人啧啧称奇。

#### 2.2.2 加密方案

密码加密我们一般会用到散列函数，又称散列算法、哈希函数，这是一种从任何数据中创建数字“指纹”的方法。散列函数把消息或数据压缩成摘要，使得数据量变小，将数据的格式固定下来，然后将数据打乱混合，重新创建一个散列值。散列值通常用一个短的随机字母和数字组成的字符串来代表。好的散列函数在输入域中很少出现散列冲突。在散列表和数据处理中，不抑制冲突来区别数据，会使得数据库记录更难找到。我们常用的散列函数有 MD5 消息摘要算法、安全散列算法（Secure Hash Algorithm）。

但是仅仅使用散列函数还不够，为了增加密码的安全性，一般在密码加密过程中还需要加盐，所谓的盐可以是一个随机数也可以是用户名，加盐之后，即使密码明文相同的用户生成的密码密文也不相同，这可以极大的提高密码的安全性。但是传统的加盐方式需要在数据库中有专门的字段来记录盐值，这个字段可能是用户名字段（因为用户名唯一），也可能是一个专门记录盐值的字段，这样的配置比较繁琐。

Spring Security 提供了多种密码加密方案，官方推荐使用 BCryptPasswordEncoder，BCryptPasswordEncoder 使用 BCrypt 强哈希函数，开发者在使用时可以选择提供 strength 和 SecureRandom 实例。strength 越大，密钥的迭代次数越多，密钥迭代次数为 2^strength。strength 取值在 4~31 之间，默认为 10。

不同于 Shiro 中需要自己处理密码加盐，在 Spring Security 中，BCryptPasswordEncoder 就自带了盐，处理起来非常方便。

而 BCryptPasswordEncoder 就是 PasswordEncoder 接口的实现类。

#### 2.2.3 PasswordEncoder

PasswordEncoder 这个接口中就定义了三个方法：

```java
public interface PasswordEncoder {
	String encode(CharSequence rawPassword);
	boolean matches(CharSequence rawPassword, String encodedPassword);
	default boolean upgradeEncoding(String encodedPassword) {
		return false;
	}
}
```

1. encode 方法用来对明文密码进行加密，返回加密之后的密文。
2. matches 方法是一个密码校对方法，在用户登录的时候，将用户传来的明文密码和数据库中保存的密文密码作为参数，传入到这个方法中去，根据返回的 Boolean 值判断用户密码是否输入正确。
3. upgradeEncoding 是否还要进行再次加密，这个一般来说就不用了。

#### 2.2.4 配置

预备知识讲完后，接下来我们来看具体如何配置：

`@EnableWebSecurity:才可生效 @Configurable 不生效`

```java
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().withUser("admin").password(passwordEncoder().encode("123")).roles("admin").authorities("index","detail");
        auth.inMemoryAuthentication().withUser("user").password(passwordEncoder().encode("123")).roles("user").authorities("index");
    }
}
```

1. 首先我们自定义 SecurityConfig 继承自 WebSecurityConfigurerAdapter，重写里边的 configure 方法。
2. 首先我们提供了一个 PasswordEncoder 的实例，因为目前的案例还比较简单，因此我暂时先不给密码进行加密，所以返回 NoOpPasswordEncoder 的实例即可。
3. configure 方法中，我们通过 inMemoryAuthentication 来开启在内存中定义用户，withUser 中是用户名，password 中则是用户密码，roles 中是用户角色。
4. 如果需要配置多个用户，用 and 相连。

为什么用 and 相连呢？

> 在没有 Spring Boot 的时候，我们都是 SSM 中使用 Spring Security，这种时候都是在 XML 文件中配置 Spring Security，既然是 XML 文件，标签就有开始有结束，现在的 and 符号相当于就是 XML 标签的结束符，表示结束当前标签，这是个时候上下文会回到 inMemoryAuthentication 方法中，然后开启新用户的配置。

配置完成后，再次启动项目，Java 代码中的配置会覆盖掉 XML 文件中的配置，此时再去访问 /hello 接口，就会发现只有 Java 代码中的用户名/密码才能访问成功。

## 3.HttpSecurity 配置

```java
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
                // 用户登录 URL
                .loginProcessingUrl("/doLogin")
                // 登录请求都放行
                .permitAll()
                .and()
                //关闭 CSRF 攻击
                .csrf().disable();
    }
```

创建两个用户请求接口

```java
    @GetMapping("/admin/hello")
    String helloAdmin(){
        return "hello admin";
    }

    @GetMapping("/user/hello")
    String userAdmin(){
        return "hello user";
    }
```



通过 postman 进行访问的时候，访问 `/admin/user`的时候，会跳转到`login页面`让你去登录，此时发送 `/doLogin【上面配置的登录请求URL】`拼接`?username=admin&password=123`就会重定向到 `/admin/user`，此时已经成功登录，security就会放行请求。

## 4.表单登陆详细配置

```java
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
                .csrf().disable();
    }
```

自定义登录页面的接口

```java
    @GetMapping("/login")
    String userLogin(){
        return "请登录";
    }
```



postman 发送请求 `http://localhost:8080/admin/hello`

页面会返回 `请登录`,这是因为自定义了前往登录页的请求`/login`

发送请求 `http://localhost:8080/doLogin?uname=admin&passwd=123`

页面返回 JSON 数据

```json
{
    "message": {
        "password": null,
        "username": "admin",
        "authorities": [
            {
                "authority": "ROLE_admin"
            }
        ],
        "accountNonExpired": true,
        "accountNonLocked": true,
        "credentialsNonExpired": true,
        "enabled": true
    },
    "status": 200
}
```

再次访问`http://localhost:8080/admin/hello`

```json
hello admin
```

### 4.1 登陆成功回调

在 Spring Security 中，和登录成功重定向 URL 相关的方法有两个：

- defaultSuccessUrl
- successForwardUrl

这两个咋看没什么区别，实际上内藏乾坤。

首先我们在配置的时候，defaultSuccessUrl 和 successForwardUrl 只需要配置一个即可，具体配置哪个，则要看你的需求，两个的区别如下：

1. defaultSuccessUrl 有一个重载的方法，我们先说一个参数的 defaultSuccessUrl 方法。如果我们在 defaultSuccessUrl 中指定登录成功的跳转页面为 `/index`，此时分两种情况，如果你是直接在浏览器中输入的登录地址，登录成功后，就直接跳转到 `/index`，如果你是在浏览器中输入了其他地址，例如 `http://localhost:8080/hello`，结果因为没有登录，又重定向到登录页面，此时登录成功后，就不会来到 `/index` ，而是来到 `/hello` 页面。
2. defaultSuccessUrl 还有一个重载的方法，第二个参数如果不设置默认为 false，也就是我们上面的的情况，如果手动设置第二个参数为 true，则 defaultSuccessUrl 的效果和 successForwardUrl 一致。
3. successForwardUrl 表示不管你是从哪里来的，登录后一律跳转到 successForwardUrl 指定的地址。例如 successForwardUrl 指定的地址为 `/index` ，你在浏览器地址栏输入 `http://localhost:8080/hello`，结果因为没有登录，重定向到登录页面，当你登录成功之后，就会服务端跳转到 `/index` 页面；或者你直接就在浏览器输入了登录页面地址，登录成功后也是来到 `/index`。

```java
.and()
.formLogin()
.loginPage("/login.html")
.loginProcessingUrl("/doLogin")
.usernameParameter("name")
.passwordParameter("passwd")
.defaultSuccessUrl("/index")
.successForwardUrl("/index")
.permitAll()
.and()
```

**「注意：实际操作中，defaultSuccessUrl 和 successForwardUrl 只需要配置一个即可。」**

### 4.2 登录失败回调

与登录成功相似，登录失败也是有两个方法：

- failureForwardUrl
- failureUrl

**「这两个方法在设置的时候也是设置一个即可」**。failureForwardUrl 是登录失败之后会发生服务端跳转，failureUrl 则在登录失败之后，会发生重定向。

### 4.3 注销登录

注销登录的默认接口是 `/logout`，我们也可以配置。

```java
.and()
.logout()
.logoutUrl("/logout")
.logoutRequestMatcher(new AntPathRequestMatcher("/logout","POST"))
.logoutSuccessUrl("/index")
.deleteCookies()
.clearAuthentication(true)
.invalidateHttpSession(true)
.permitAll()
.and()
```

注销登录的配置我来说一下：

1. 默认注销的 URL 是 `/logout`，是一个 GET 请求，我们可以通过 logoutUrl 方法来修改默认的注销 URL。
2. logoutRequestMatcher 方法不仅可以修改注销 URL，还可以修改请求方式，实际项目中，这个方法和 logoutUrl 任意设置一个即可。
3. logoutSuccessUrl 表示注销成功后要跳转的页面。
4. deleteCookies 用来清除 cookie。
5. clearAuthentication 和 invalidateHttpSession 分别表示清除认证信息和使 HttpSession 失效，默认可以不用配置，默认就会清除。

### 4.4 前后端分离登录

#### 无状态登录

##### 什么是有状态

有状态服务，即服务端需要记录每次会话的客户端信息，从而识别客户端身份，根据用户身份进行请求的处理，典型的设计如 Tomcat 中的 Session。例如登录：用户登录后，我们把用户的信息保存在服务端 session 中，并且给用户一个 cookie 值，记录对应的 session，然后下次请求，用户携带 cookie 值来（这一步有浏览器自动完成），我们就能识别到对应 session，从而找到用户的信息。这种方式目前来看最方便，但是也有一些缺陷，如下：

- 服务端保存大量数据，增加服务端压力
- 服务端保存用户状态，不支持集群化部署

##### 什么是无状态

微服务集群中的每个服务，对外提供的都使用 RESTful 风格的接口。而 RESTful 风格的一个最重要的规范就是：服务的无状态性，即：

- 服务端不保存任何客户端请求者信息
- 客户端的每次请求必须具备自描述信息，通过这些信息识别客户端身份

那么这种无状态性有哪些好处呢？

- 客户端请求不依赖服务端的信息，多次请求不需要必须访问到同一台服务器
- 服务端的集群和状态对客户端透明
- 服务端可以任意的迁移和伸缩（可以方便的进行集群化部署）
- 减小服务端存储压力

##### 如何实现无状态

无状态登录的流程：

- 首先客户端发送账户名/密码到服务端进行认证
- 认证通过后，服务端将用户信息加密并且编码成一个 token，返回给客户端
- 以后客户端每次发送请求，都需要携带认证的 token
- 服务端对客户端发送来的 token 进行解密，判断是否有效，并且获取用户登录信息

##### 各自优缺点

使用 session 最大的优点在于方便。你不用做过多的处理，一切都是默认的即可。

但是使用 session 有另外一个致命的问题就是如果你的前端是 Android、iOS、小程序等，这些 App 天然的就没有 cookie，如果非要用 session，就需要这些工程师在各自的设备上做适配，一般是模拟 cookie，从这个角度来说，在移动 App 遍地开花的今天，我们单纯的依赖 session 来做安全管理，似乎也不是特别理想。

这个时候 JWT 这样的无状态登录就展示出自己的优势了，这些登录方式所依赖的 token 你可以通过普通参数传递，也可以通过请求头传递，怎么样都行，具有很强的灵活性。

不过话说回来，如果你的前后端分离只是网页+服务端，其实没必要上无状态登录，基于 session 来做就可以了，省事又方便。

#### 登录交互

##### 前后端分离的数据交互

在前后端分离这样的开发架构下，前后端的交互都是通过 JSON 来进行，无论登录成功还是失败，都不会有什么服务端跳转或者客户端跳转之类。

登录成功了，服务端就返回一段登录成功的提示 JSON 给前端，前端收到之后，该跳转该展示，由前端自己决定，就和后端没有关系了。

登录失败了，服务端就返回一段登录失败的提示 JSON 给前端，前端收到之后，该跳转该展示，由前端自己决定，也和后端没有关系了。

首先把这样的思路确定了，基于这样的思路，我们来看一下登录配置。

##### 登录成功

之前我们配置登录成功的处理是通过如下两个方法来配置的：

- defaultSuccessUrl
- successForwardUrl

这两个都是配置跳转地址的，适用于前后端不分的开发。除了这两个方法之外，还有一个必杀技，那就是 successHandler。

successHandler 的功能十分强大，甚至已经囊括了 defaultSuccessUrl 和 successForwardUrl 的功能。我们来看一下：

```java
.successHandler((req, resp, authentication) -> {
    Object principal = authentication.getPrincipal();
    resp.setContentType("application/json;charset=utf-8");
    PrintWriter out = resp.getWriter();
    out.write(new ObjectMapper().writeValueAsString(principal));
    out.flush();
    out.close();
})
```

successHandler 方法的参数是一个 AuthenticationSuccessHandler 对象，这个对象中我们要实现的方法是 onAuthenticationSuccess。

onAuthenticationSuccess 方法有三个参数，分别是：

- HttpServletRequest
- HttpServletResponse
- Authentication

有了前两个参数，我们就可以在这里随心所欲的返回数据了。利用 HttpServletRequest 我们可以做服务端跳转，利用 HttpServletResponse 我们可以做客户端跳转，当然，也可以返回 JSON 数据。

第三个 Authentication 参数则保存了我们刚刚登录成功的用户信息。

配置完成后，我们再去登录，就可以看到登录成功的用户信息通过 JSON 返回到前端了，如下：

```json
{		
        "password": null,
        "username": "admin",
        "authorities": [
            {
                "authority": "ROLE_admin"
            }
        ],
        "accountNonExpired": true,
        "accountNonLocked": true,
        "credentialsNonExpired": true,
        "enabled": true
}
```

##### 登录失败

登录失败也有一个类似的回调，如下：

```java
.failureHandler((req, resp, e) -> {
    resp.setContentType("application/json;charset=utf-8");
    PrintWriter out = resp.getWriter();
    out.write(e.getMessage());
    out.flush();
    out.close();
})
```

失败的回调也是三个参数，前两个就不用说了，第三个是一个 Exception，对于登录失败，会有不同的原因，Exception 中则保存了登录失败的原因，我们可以将之通过 JSON 返回到前端。

当然大家也看到，在微人事中，我还挨个去识别了一下异常的类型，根据不同的异常类型，我们可以给用户一个更加明确的提示：

```java
resp.setContentType("application/json;charset=utf-8");
PrintWriter out = resp.getWriter();
RespBean respBean = RespBean.error(e.getMessage());
if (e instanceof LockedException) {
    respBean.setMsg("账户被锁定，请联系管理员!");
} elseif (e instanceof CredentialsExpiredException) {
    respBean.setMsg("密码过期，请联系管理员!");
} elseif (e instanceof AccountExpiredException) {
    respBean.setMsg("账户过期，请联系管理员!");
} elseif (e instanceof DisabledException) {
    respBean.setMsg("账户被禁用，请联系管理员!");
} elseif (e instanceof BadCredentialsException) {
    respBean.setMsg("用户名或者密码输入错误，请重新输入!");
}
out.write(new ObjectMapper().writeValueAsString(respBean));
out.flush();
out.close();
```

这里有一个需要注意的点。

我们知道，当用户登录时，用户名或者密码输入错误，我们一般只给一个模糊的提示，即**「用户名或者密码输入错误，请重新输入」**，而不会给一个明确的诸如“用户名输入错误”或“密码输入错误”这样精确的提示，但是对于很多不懂行的新手小伙伴，他可能就会给一个明确的错误提示，这会给系统带来风险。

但是使用了 Spring Security 这样的安全管理框架之后，即使你是一个新手，也不会犯这样的错误。

在 Spring Security 中，用户名查找失败对应的异常是：

- UsernameNotFoundException

密码匹配失败对应的异常是：

- BadCredentialsException

但是我们在登录失败的回调中，却总是看不到 UsernameNotFoundException 异常，无论用户名还是密码输入错误，抛出的异常都是 BadCredentialsException。

在登录中有一个关键的步骤，就是去加载用户数据，我们再来把这个方法拎出来看一下（部分）：

```java
public Authentication authenticate(Authentication authentication)
		throws AuthenticationException {
	try {
		user = retrieveUser(username,
				(UsernamePasswordAuthenticationToken) authentication);
	}
	catch (UsernameNotFoundException notFound) {
		logger.debug("User '" + username + "' not found");
		if (hideUserNotFoundExceptions) {
			thrownew BadCredentialsException(messages.getMessage(
					"AbstractUserDetailsAuthenticationProvider.badCredentials",
					"Bad credentials"));
		}
		else {
			throw notFound;
		}
	}
}
```

从这段代码中，我们看出，在查找用户时，如果抛出了 UsernameNotFoundException，这个异常会被捕获，捕获之后，如果 hideUserNotFoundExceptions 属性的值为 true，就抛出一个 BadCredentialsException。相当于将 UsernameNotFoundException 异常隐藏了，而默认情况下，hideUserNotFoundExceptions 的值就为 true。

看到这里大家就明白了为什么无论用户还是密码写错，你收到的都是 BadCredentialsException 异常。

一般来说这个配置是不需要修改的，如果你一定要区别出来 UsernameNotFoundException 和 BadCredentialsException，我这里给大家提供三种思路：

1. 自己定义 DaoAuthenticationProvider 代替系统默认的，在定义时将 hideUserNotFoundExceptions 属性设置为 false。
2. 当用户名查找失败时，不抛出 UsernameNotFoundException 异常，而是抛出一个自定义异常，这样自定义异常就不会被隐藏，进而在登录失败的回调中根据自定义异常信息给前端用户一个提示。
3. 当用户名查找失败时，直接抛出 BadCredentialsException，但是异常信息为 “用户名不存在”。

除非情况特殊，一般不用修改这一块的默认行为。

官方这样做的好处是什么呢？很明显可以强迫开发者给一个模糊的异常提示，这样即使是不懂行的新手，也不会将系统置于危险之中。

好了，这样配置完成后，无论是登录成功还是失败，后端都将只返回 JSON 给前端了。

#### 未认证处理方案

那未认证又怎么办呢？

有人说，那还不简单，没有认证就访问数据，直接重定向到登录页面就行了，这没错，系统默认的行为也是这样。

但是在前后端分离中，这个逻辑明显是有问题的，如果用户没有登录就访问一个需要认证后才能访问的页面，这个时候，我们不应该让用户重定向到登录页面，而是给用户一个尚未登录的提示，前端收到提示之后，再自行决定页面跳转。

要解决这个问题，就涉及到 Spring Security 中的一个接口 `AuthenticationEntryPoint` ，该接口有一个实现类：`LoginUrlAuthenticationEntryPoint` ，该类中有一个方法 `commence`，如下：

```java
/**
 * Performs the redirect (or forward) to the login form URL.
 */
public void commence(HttpServletRequest request, HttpServletResponse response,
		AuthenticationException authException) {
	String redirectUrl = null;
	if (useForward) {
		if (forceHttps && "http".equals(request.getScheme())) {
			redirectUrl = buildHttpsRedirectUrlForRequest(request);
		}
		if (redirectUrl == null) {
			String loginForm = determineUrlToUseForThisRequest(request, response,
					authException);
			if (logger.isDebugEnabled()) {
				logger.debug("Server side forward to: " + loginForm);
			}
			RequestDispatcher dispatcher = request.getRequestDispatcher(loginForm);
			dispatcher.forward(request, response);
			return;
		}
	}
	else {
		redirectUrl = buildRedirectUrlToLoginPage(request, response, authException);
	}
	redirectStrategy.sendRedirect(request, response, redirectUrl);
}
```

首先我们从这个方法的注释中就可以看出，这个方法是用来决定到底是要重定向还是要 forward，通过 Debug 追踪，我们发现默认情况下 useForward 的值为 false，所以请求走进了重定向。

那么我们解决问题的思路很简单，直接重写这个方法，在方法中返回 JSON 即可，不再做重定向操作，具体配置如下：

```java
.csrf().disable().exceptionHandling()
.authenticationEntryPoint((req, resp, authException) -> {
            resp.setContentType("application/json;charset=utf-8");
            PrintWriter out = resp.getWriter();
            out.write("尚未登录，请先登录");
            out.flush();
            out.close();
        }
);
```

在 Spring Security 的配置中加上自定义的 `AuthenticationEntryPoint` 处理方法，该方法中直接返回相应的 JSON 提示即可。这样，如果用户再去直接访问一个需要认证之后才可以访问的请求，就不会发生重定向操作了，服务端会直接给浏览器一个 JSON 提示，浏览器收到 JSON 之后，该干嘛干嘛。

#### 注销登录

最后我们再来看看注销登录的处理方案。

注销登录我们前面说过，按照前面的配置，注销登录之后，系统自动跳转到登录页面，这也是不合适的，如果是前后端分离项目，注销登录成功后返回 JSON 即可，配置如下：

```java
.and()
.logout()
.logoutUrl("/logout")
.logoutSuccessHandler((req, resp, authentication) -> {
    resp.setContentType("application/json;charset=utf-8");
    PrintWriter out = resp.getWriter();
    out.write("注销成功");
    out.flush();
    out.close();
})
.permitAll()
.and()
```

这样，注销成功之后，前端收到的也是 JSON 了：

## 5.多个 HttpSecurity

```java
@EnableWebSecurity
public class MultiHttpSecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    @Autowired
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().withUser("admin").password(passwordEncoder().encode("123")).roles("admin");
        auth.inMemoryAuthentication().withUser("user").password(passwordEncoder().encode("123")).roles("user");
    }

    @EnableWebSecurity
    @Order(1)
    public static class AdminSecurityConfig extends WebSecurityConfigurerAdapter {

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.antMatcher("/admin/**")
                    .authorizeRequests()
                    .anyRequest().hasAnyRole("admin");
        }
    }

    @EnableWebSecurity
    @Order(2)
    public static class OtherSecurityConfig extends WebSecurityConfigurerAdapter {

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.authorizeRequests()
                    .anyRequest()
                    .authenticated()
                    .and()
                    .formLogin()
                    .loginProcessingUrl("/doLogin")
                    .permitAll()
                    .and()
                    .csrf().disable();

        }
    }

}
```

用户发送请求，会先去 `AdminSecurityConfig`匹配，在这个类只是拦截 `/admin/**`的请求，如果匹配不到就会去`OtherSecurityConfig`类中进行配置，在这个类中会拦截所有的请求。

## 6.方法级别的安全

在配置类上方添加注解 `@EnableGlobalMethodSecurity(prePostEnabled = true,securedEnabled = true)`

```java
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true,securedEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {
```

创建 service 方法

```java
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
```









