title: Spring Boot + Spring Security 实现自动登录

---

# 实现自动登录功能

自动登录是我们在软件开发时一个非常常见的功能

很多网站我们在登录的时候都会看到类似的选项，毕竟总让用户输入用户名密码是一件很麻烦的事。

自动登录功能就是，用户在登录成功后，在某一段时间内，如果用户关闭了浏览器并重新打开，或者服务器重启了，都不需要用户重新登录了，用户依然可以直接访问接口数据。

## 实例代码

首先，要实现记住我这个功能，其实只需要其实只需要在 Spring Security 的配置中，添加如下代码即可：

```java
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .permitAll()
                .and()
                .rememberMe()
                .and()
                .csrf().disable();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("user").password(passwordEncoder().encode("123")).roles("user")
                ;
    }
```

大家看到，这里只需要添加一个 `.rememberMe()` 即可，自动登录功能就成功添加进来了。

接下来我们随意添加一个测试接口：

```java
@RestController
public class HelloController {
    @GetMapping("/hello")
    public String hello() {
        return "hello";
    }
}
```

重启项目，我们访问 hello 接口，此时会自动跳转到登录页面

这个时候大家发现，默认的登录页面多了一个选项，就是记住我。我们输入用户名密码，并且勾选上记住我这个框，然后点击登录按钮执行登录操作

可以看到，登录数据中，除了 username 和 password 之外，还有一个 remember-me，之所以给大家看这个，是想告诉大家，如果你你需要自定义登录页面，RememberMe 这个选项的 key 该怎么写。

登录成功之后，就会自动跳转到 hello 接口了。我们注意，系统访问 hello 接口的时候，携带的 cookie

接下来，我们关闭浏览器，再重新打开浏览器。正常情况下，浏览器关闭再重新打开，如果需要再次访问 hello 接口，就需要我们重新登录了。但是此时，我们再去访问 hello 接口，发现不用重新登录了，直接就能访问到，这就说明我们的 RememberMe 配置生效了（即下次自动登录功能生效了）

## 原理分析

按理说，浏览器关闭再重新打开，就要重新登录，现在竟然不用等了，那么这个功能到底是怎么实现的呢？

首先我们来分析一下 cookie 中多出来的这个 remember-me，这个值一看就是一个 Base64 转码后的字符串，我们可以使用网上的一些在线工具来解码，可以自己简单写两行代码来解码：

```java
@Test
void contextLoads() throws UnsupportedEncodingException {
    String s = new String(Base64.getDecoder().decode("amF2YWJveToxNTg5MTA0MDU1MzczOjI1NzhmZmJjMjY0ODVjNTM0YTJlZjkyOWFjMmVmYzQ3"), "UTF-8");
    System.out.println("s = " + s);
}
```

执行这段代码，输出结果如下：

```java
s = user:1589104055373:2578ffbc26485c534a2ef929ac2efc47
```

可以看到，这段 Base64 字符串实际上用 `:` 隔开，分成了三部分：

1. 第一段是用户名，这个无需质疑。
2. 第二段看起来是一个时间戳，我们通过在线工具或者 Java 代码解析后发现，这是一个两周后的数据。
3. 第三段,这是使用 MD5 散列函数算出来的值，他的明文格式是 `username + ":" + tokenExpiryTime + ":" + password + ":" + key`，最后的 key 是一个散列盐值，可以用来防治令牌被修改。

了解到 cookie 中 remember-me 的含义之后，那么我们对于记住我的登录流程也就很容易猜到了了。

在浏览器关闭后，并重新打开之后，用户再去访问 hello 接口，此时会携带着 cookie 中的 remember-me 到服务端，服务到拿到值之后，可以方便的计算出用户名和过期时间，再根据用户名查询到用户密码，然后通过 MD5 散列函数计算出散列值，再将计算出的散列值和浏览器传递来的散列值进行对比，就能确认这个令牌是否有效。

流程就是这么个流程，接下来我们通过分析源码来验证一下这个流程对不对。

## 源码分析

接下来，我们通过源码来验证一下我们上面说的对不对。

这里主要从两个方面来介绍，一个是 remember-me 这个令牌生成的过程，另一个则是它解析的过程。

### 生成

生成的核心处理方法在：`TokenBasedRememberMeServices#onLoginSuccess`：

```java
@Override
public void onLoginSuccess(HttpServletRequest request, HttpServletResponse response,
		Authentication successfulAuthentication) {
	String username = retrieveUserName(successfulAuthentication);
	String password = retrievePassword(successfulAuthentication);
	if (!StringUtils.hasLength(password)) {
		UserDetails user = getUserDetailsService().loadUserByUsername(username);
		password = user.getPassword();
	}
	int tokenLifetime = calculateLoginLifetime(request, successfulAuthentication);
	long expiryTime = System.currentTimeMillis();
	expiryTime += 1000L * (tokenLifetime < 0 ? TWO_WEEKS_S : tokenLifetime);
	String signatureValue = makeTokenSignature(expiryTime, username, password);
	setCookie(new String[] { username, Long.toString(expiryTime), signatureValue },
			tokenLifetime, request, response);
}
protected String makeTokenSignature(long tokenExpiryTime, String username,
		String password) {
	String data = username + ":" + tokenExpiryTime + ":" + password + ":" + getKey();
	MessageDigest digest;
	digest = MessageDigest.getInstance("MD5");
	return new String(Hex.encode(digest.digest(data.getBytes())));
}
```

这段方法的逻辑其实很好理解：

1. 首先从登录成功的 Authentication 中提取出用户名/密码。
2. 由于登录成功之后，密码可能被擦除了，所以，如果一开始没有拿到密码，就再从 UserDetailsService 中重新加载用户并重新获取密码。
3. 再接下来去获取令牌的有效期，令牌有效期默认就是两周。
4. 再接下来调用 makeTokenSignature 方法去计算散列值，实际上就是根据 username、令牌有效期以及 password、key 一起计算一个散列值。如果我们没有自己去设置这个 key，默认是在 RememberMeConfigurer#getKey 方法中进行设置的，它的值是一个 UUID 字符串。
5. 最后，将用户名、令牌有效期以及计算得到的散列值放入 Cookie 中。

由于我们自己没有设置 key，key 默认值是一个 UUID 字符串，这样会带来一个问题，就是如果服务端重启，这个 key 会变，这样就导致之前派发出去的所有 remember-me 自动登录令牌失效，所以，我们可以指定这个 key。指定方式如下：

```java
@Override
protected void configure(HttpSecurity http) throws Exception {
    http.authorizeRequests()
            .anyRequest().authenticated()
            .and()
            .formLogin()
            .and()
            .rememberMe()
            .key("javaboy")
            .and()
            .csrf().disable();
}
```

如果自己配置了 key，**即使服务端重启，即使浏览器打开再关闭**，也依然能够访问到 hello 接口。

这是 remember-me 令牌生成的过程。

> AbstractAuthenticationProcessingFilter#doFilter -> AbstractAuthenticationProcessingFilter#successfulAuthentication -> AbstractRememberMeServices#loginSuccess -> TokenBasedRememberMeServices#onLoginSuccess。

### 解析

那么当用户关掉并打开浏览器之后，重新访问 /hello 接口，此时的认证流程又是怎么样的呢？

我们之前说过，Spring Security 中的一系列功能都是通过一个过滤器链实现的，RememberMe 这个功能当然也不例外。

Spring Security 中提供了 RememberMeAuthenticationFilter 类专门用来做相关的事情，我们来看下 RememberMeAuthenticationFilter 的 doFilter 方法：

```java
public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
		throws IOException, ServletException {
	HttpServletRequest request = (HttpServletRequest) req;
	HttpServletResponse response = (HttpServletResponse) res;
	if (SecurityContextHolder.getContext().getAuthentication() == null) {
		Authentication rememberMeAuth = rememberMeServices.autoLogin(request,
				response);
		if (rememberMeAuth != null) {
				rememberMeAuth = authenticationManager.authenticate(rememberMeAuth);
				SecurityContextHolder.getContext().setAuthentication(rememberMeAuth);
				onSuccessfulAuthentication(request, response, rememberMeAuth);
				if (this.eventPublisher != null) {
					eventPublisher
							.publishEvent(new InteractiveAuthenticationSuccessEvent(
									SecurityContextHolder.getContext()
											.getAuthentication(), this.getClass()));
				}
				if (successHandler != null) {
					successHandler.onAuthenticationSuccess(request, response,
							rememberMeAuth);
					return;
				}
			}
		chain.doFilter(request, response);
	}
	else {
		chain.doFilter(request, response);
	}
}
```

可以看到，就是在这里实现的。

这个方法最关键的地方在于，如果从 SecurityContextHolder 中无法获取到当前登录用户实例，那么就调用 rememberMeServices.autoLogin 逻辑进行登录，我们来看下这个方法：

```java
public final Authentication autoLogin(HttpServletRequest request,
		HttpServletResponse response) {
	String rememberMeCookie = extractRememberMeCookie(request);
	if (rememberMeCookie == null) {
		return null;
	}
	logger.debug("Remember-me cookie detected");
	if (rememberMeCookie.length() == 0) {
		logger.debug("Cookie was empty");
		cancelCookie(request, response);
		return null;
	}
	UserDetails user = null;
	try {
		String[] cookieTokens = decodeCookie(rememberMeCookie);
		user = processAutoLoginCookie(cookieTokens, request, response);
		userDetailsChecker.check(user);
		logger.debug("Remember-me cookie accepted");
		return createSuccessfulAuthentication(request, user);
	}
	catch (CookieTheftException cte) {
		
		throw cte;
	}
	cancelCookie(request, response);
	return null;
}
```

可以看到，这里就是提取出 cookie 信息，并对 cookie 信息进行解码，解码之后，再调用 processAutoLoginCookie 方法去做校验，processAutoLoginCookie 方法的代码我就不贴了，核心流程就是首先获取用户名和过期时间，再根据用户名查询到用户密码，然后通过 MD5 散列函数计算出散列值，再将拿到的散列值和浏览器传递来的散列值进行对比，就能确认这个令牌是否有效，进而确认登录是否有效。

## 总结

看了上面的文章，大家可能已经发现，如果我们开启了 RememberMe 功能，最最核心的东西就是放在 cookie 中的令牌了，这个令牌突破了 session 的限制，即使服务器重启、即使浏览器关闭又重新打开，只要这个令牌没有过期，就能访问到数据。

一旦令牌丢失，别人就可以拿着这个令牌随意登录我们的系统了，这是一个非常危险的操作。

但是实际上这是一段悖论，为了提高用户体验（少登录），我们的系统不可避免的引出了一些安全问题，不过我们可以通过技术将安全风险降低到最小。

# RememberMe 持久化方案

在实际应用中，我们肯定要把这些安全风险降到最低。降低安全风险，主要有两个方面：

- 持久化方案
- 二次校验

## 持久化令牌

### 原理

要理解持久化令牌，一定要先搞明白自动登录的基本玩法

持久化令牌就是在基本的自动登录功能基础上，又增加了新的校验参数，来提高系统的安全性，这一些都是由开发者在后台完成的，对于用户来说，登录体验和普通的自动登录体验是一样的。

在持久化令牌中，新增了两个经过 MD5 散列函数计算的校验参数，一个是 series，另一个是 token。其中，series 只有当用户在使用用户名/密码登录时，才会生成或者更新，而 token 只要有新的会话，就会重新生成，这样就可以避免一个用户同时在多端登录，就像手机 QQ ，一个手机上登录了，就会踢掉另外一个手机的登录，这样用户就会很容易发现账户是否泄漏

持久化令牌的具体处理类在 PersistentTokenBasedRememberMeServices 中，自动化登录具体的处理类是在 TokenBasedRememberMeServices 中，它们有一个共同的父类

而用来保存令牌的处理类则是 PersistentRememberMeToken，该类的定义也很简洁命令：

```java
public class PersistentRememberMeToken {
	private final String username;
	private final String series;
	private final String tokenValue;
	private final Date date;
    //省略 getter
}
```

这里的 Date 表示上一次使用自动登录的时间。

### 代码实例

首先我们需要一张表来记录令牌信息，这张表我们可以完全自定义，也可以使用系统默认提供的 JDBC 来操作，如果使用默认的 JDBC，即 JdbcTokenRepositoryImpl，我们可以来分析一下该类的定义：

```java
public class JdbcTokenRepositoryImpl extends JdbcDaoSupport implements
		PersistentTokenRepository {
	public static final String CREATE_TABLE_SQL = "create table persistent_logins (username varchar(64) not null, series varchar(64) primary key, "
			+ "token varchar(64) not null, last_used timestamp not null)";
	public static final String DEF_TOKEN_BY_SERIES_SQL = "select username,series,token,last_used from persistent_logins where series = ?";
	public static final String DEF_INSERT_TOKEN_SQL = "insert into persistent_logins (username, series, token, last_used) values(?,?,?,?)";
	public static final String DEF_UPDATE_TOKEN_SQL = "update persistent_logins set token = ?, last_used = ? where series = ?";
	public static final String DEF_REMOVE_USER_TOKENS_SQL = "delete from persistent_logins where username = ?";
}
```

根据这段 SQL 定义，我们就可以分析出来表的结构

```sql
CREATE TABLE `persistent_logins` (
  `username` varchar(64) COLLATE utf8mb4_unicode_ci NOT NULL,
  `series` varchar(64) COLLATE utf8mb4_unicode_ci NOT NULL,
  `token` varchar(64) COLLATE utf8mb4_unicode_ci NOT NULL,
  `last_used` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`series`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
```

首先我们在数据库中准备好这张表。

既然要连接数据库，我们还需要准备 jdbc 和 mysql 依赖，如下：

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-jdbc</artifactId>
</dependency>
<dependency>
    <groupId>mysql</groupId>
    <artifactId>mysql-connector-java</artifactId>
</dependency>
```

然后修改 application.properties ，配置数据库连接信息：

```properties
spring.datasource.url=jdbc:mysql:///oauth2?useUnicode=true&characterEncoding=UTF-8&serverTimezone=Asia/Shanghai
spring.datasource.username=root
spring.datasource.password=123
```

接下来，我们修改 SecurityConfig，如下：

```java
@Autowired
DataSource dataSource;

@Bean
JdbcTokenRepositoryImpl jdbcTokenRepository() {
    JdbcTokenRepositoryImpl jdbcTokenRepository = new JdbcTokenRepositoryImpl();
    jdbcTokenRepository.setDataSource(dataSource);
    return jdbcTokenRepository;
}

@Override
protected void configure(HttpSecurity http) throws Exception {
    http.authorizeRequests()
            .anyRequest().authenticated()
            .and()
            .formLogin()
            .and()
            .rememberMe()
            .key("wenx")
            .tokenRepository(jdbcTokenRepository())
            .and()
            .csrf().disable();
}
```

提供一个 JdbcTokenRepositoryImpl 实例，并给其配置 DataSource 数据源，最后通过 tokenRepository 将 JdbcTokenRepositoryImpl 实例纳入配置中。

OK，做完这一切，我们就可以测试了。

### 测试

我们还是先去访问 `/hello` 接口，此时会自动跳转到登录页面，然后我们执行登录操作，记得勾选上“记住我”这个选项，登录成功后，我们可以重启服务器、然后关闭浏览器再打开，再去访问 /hello 接口，发现依然能够访问到，说明我们的持久化令牌配置已经生效。

令牌经过解析之后，格式如下：

```xml
emhqATk3ZDBdR8862WP4Ig%3D%3D:ZAEv6EIWqA7CkGbYewCh8g%3D%3D
```

这其中，%3D 表示 `=`，所以上面的字符实际上可以翻译成下面这样：

```
emhqATk3ZDBdR8862WP4Ig==:ZAEv6EIWqA7CkGbYewCh8g==
```

此时，查看数据库，我们发现之前的表中生成了一条记录

数据库中的记录和我们看到的 remember-me 令牌解析后是一致的。

### 源码分析

这次的实现类主要是：PersistentTokenBasedRememberMeServices，我们先来看里边几个和令牌生成相关的方法：

```java
protected void onLoginSuccess(HttpServletRequest request,
		HttpServletResponse response, Authentication successfulAuthentication) {
	String username = successfulAuthentication.getName();
	PersistentRememberMeToken persistentToken = new PersistentRememberMeToken(
			username, generateSeriesData(), generateTokenData(), new Date());
	tokenRepository.createNewToken(persistentToken);
	addCookie(persistentToken, request, response);
}
protected String generateSeriesData() {
	byte[] newSeries = new byte[seriesLength];
	random.nextBytes(newSeries);
	return new String(Base64.getEncoder().encode(newSeries));
}
protected String generateTokenData() {
	byte[] newToken = new byte[tokenLength];
	random.nextBytes(newToken);
	return new String(Base64.getEncoder().encode(newToken));
}
private void addCookie(PersistentRememberMeToken token, HttpServletRequest request,
		HttpServletResponse response) {
	setCookie(new String[] { token.getSeries(), token.getTokenValue() },
			getTokenValiditySeconds(), request, response);
}
```

可以看到：

1. 在登录成功后，首先还是获取到用户名，即 username。
2. 接下来构造一个 PersistentRememberMeToken 实例，generateSeriesData 和 generateTokenData 方法分别用来获取 series 和 token，具体的生成过程实际上就是调用 SecureRandom 生成随机数再进行 Base64 编码，不同于我们以前用的 Math.random 或者 java.util.Random 这种伪随机数，SecureRandom 则采用的是类似于密码学的随机数生成规则，其输出结果较难预测，适合在登录这样的场景下使用。
3. 调用 tokenRepository 实例中的 createNewToken 方法，tokenRepository 实际上就是我们一开始配置的 JdbcTokenRepositoryImpl，所以这行代码实际上就是将 PersistentRememberMeToken 存入数据库中。
4. 最后 addCookie，大家可以看到，就是添加了 series 和 token。

这是令牌生成的过程，还有令牌校验的过程，也在该类中，方法是：processAutoLoginCookie：

```java
protected UserDetails processAutoLoginCookie(String[] cookieTokens,
		HttpServletRequest request, HttpServletResponse response) {
	final String presentedSeries = cookieTokens[0];
	final String presentedToken = cookieTokens[1];
	PersistentRememberMeToken token = tokenRepository
			.getTokenForSeries(presentedSeries);
	if (!presentedToken.equals(token.getTokenValue())) {
		tokenRepository.removeUserTokens(token.getUsername());
		throw new CookieTheftException(
				messages.getMessage(
						"PersistentTokenBasedRememberMeServices.cookieStolen",
						"Invalid remember-me token (Series/token) mismatch. Implies previous cookie theft attack."));
	}
	if (token.getDate().getTime() + getTokenValiditySeconds() * 1000L < System
			.currentTimeMillis()) {
		throw new RememberMeAuthenticationException("Remember-me login has expired");
	}
	PersistentRememberMeToken newToken = new PersistentRememberMeToken(
			token.getUsername(), token.getSeries(), generateTokenData(), new Date());
	tokenRepository.updateToken(newToken.getSeries(), newToken.getTokenValue(),
				newToken.getDate());
	addCookie(newToken, request, response);
	return getUserDetailsService().loadUserByUsername(token.getUsername());
}
```

这段逻辑也比较简单：

1. 首先从前端传来的 cookie 中解析出 series 和 token。
2. 根据 series 从数据库中查询出一个 PersistentRememberMeToken 实例。
3. 如果查出来的 token 和前端传来的 token 不相同，说明账号可能被人盗用（别人用你的令牌登录之后，token 会变）。此时根据用户名移除相关的 token，相当于必须要重新输入用户名密码登录才能获取新的自动登录权限。
4. 接下来校验 token 是否过期。
5. 构造新的 PersistentRememberMeToken 对象，并且更新数据库中的 token（这就是我们文章开头说的，新的会话都会对应一个新的 token）。
6. 将新的令牌重新添加到 cookie 中返回。
7. 根据用户名查询用户信息，再走一波登录流程

## 二次校验

持久化令牌的方式其实已经安全很多了，但是依然存在用户身份被盗用的问题，这个问题实际上很难完美解决，我们能做的，只能是当发生用户身份被盗用这样的事情时，将损失降低到最小。

因此，我们来看下另一种方案，就是二次校验。

为了让用户使用方便，我们开通了自动登录功能，但是自动登录功能又带来了安全风险，一个规避的办法就是如果用户使用了自动登录功能，我们可以只让他做一些常规的不敏感操作，例如数据浏览、查看，但是不允许他做任何修改、删除操作，如果用户点击了修改、删除按钮，我们可以跳转回登录页面，让用户重新输入密码确认身份，然后再允许他执行敏感操作。

这个功能在 Shiro 中有一个比较方便的过滤器可以配置，Spring Security 当然也一样，例如我现在提供三个访问接口：

```java
@RestController
public class HelloController {
    @GetMapping("/hello")
    public String hello() {
        return "hello";
    }
    @GetMapping("/admin")
    public String admin() {
        return "admin";
    }
    @GetMapping("/rememberme")
    public String rememberme() {
        return "rememberme";
    }
}
```

1. 第一个 /hello 接口，只要认证后就可以访问，无论是通过用户名密码认证还是通过自动登录认证，只要认证了，就可以访问。
2. 第二个 /admin 接口，必须要用户名密码认证之后才能访问，如果用户是通过自动登录认证的，则必须重新输入用户名密码才能访问该接口。
3. 第三个 /rememberme 接口，必须是通过自动登录认证后才能访问，如果用户是通过用户名/密码认证的，则无法访问该接口。

```java
@Override
protected void configure(HttpSecurity http) throws Exception {
    http.authorizeRequests()
            .antMatchers("/rememberme").rememberMe()
            .antMatchers("/admin").fullyAuthenticated()
            .anyRequest().authenticated()
            .and()
            .formLogin()
            .and()
            .rememberMe()
            .key("wenx")
            .tokenRepository(jdbcTokenRepository())
            .and()
            .csrf().disable();
}
```

可以看到：

1. /rememberme 接口是需要 rememberMe 才能访问。
2. /admin 是需要 fullyAuthenticated，fullyAuthenticated 不同于 authenticated，fullyAuthenticated 不包含自动登录的形式，而 authenticated 包含自动登录的形式。
3. 最后剩余的接口（/hello）都是 authenticated 就能访问。

