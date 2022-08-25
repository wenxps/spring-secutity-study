## 1. Authentication

Authentication 接口用来保存我们的登录用户信息，实际上，它是对主体（java.security.Principal）做了进一步的封装。

我们来看下 Authentication 的一个定义：

```java
public interface Authentication extends Principal, Serializable {
	Collection<? extends GrantedAuthority> getAuthorities();
	Object getCredentials();
	Object getDetails();
	Object getPrincipal();
	boolean isAuthenticated();
	void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException;
}
```

接口的解释如下：

1. getAuthorities 方法用来获取用户的权限。
2. getCredentials 方法用来获取用户凭证，一般来说就是密码。
3. getDetails 方法用来获取用户携带的详细信息，可能是当前请求之类的东西。
4. getPrincipal 方法用来获取当前用户，可能是一个用户名，也可能是一个用户对象。
5. isAuthenticated 当前用户是否认证成功。

<!--more-->

这里有一个比较好玩的方法，叫做 getDetails。关于这个方法，源码的解释如下：

Stores additional details about the authentication request. These might be an IP address, certificate serial number etc.

从这段解释中，我们可以看出，该方法实际上就是用来存储有关身份认证的其他信息的，例如 IP 地址、证书信息等等。

实际上，在默认情况下，这里存储的就是用户登录的 IP 地址和 sessionId。我们从源码角度来看下。

## 2. 源码分析

松哥的 SpringSecurity 系列已经写到第 12 篇了，看了前面的文章，相信大家已经明白用户登录必经的一个过滤器就是 UsernamePasswordAuthenticationFilter，在该类的 attemptAuthentication 方法中，对请求参数做提取，在 attemptAuthentication 方法中，会调用到一个方法，就是 setDetails。

我们一起来看下 setDetails 方法：

```java
protected void setDetails(HttpServletRequest request,
		UsernamePasswordAuthenticationToken authRequest) {
	authRequest.setDetails(authenticationDetailsSource.buildDetails(request));
}
```

UsernamePasswordAuthenticationToken 是 Authentication 的具体实现，所以这里实际上就是在设置 details，至于 details 的值，则是通过 authenticationDetailsSource 来构建的，我们来看下：

```java
public class WebAuthenticationDetailsSource implements
		AuthenticationDetailsSource<HttpServletRequest, WebAuthenticationDetails> {
	public WebAuthenticationDetails buildDetails(HttpServletRequest context) {
		return new WebAuthenticationDetails(context);
	}
}
public class WebAuthenticationDetails implements Serializable {
	private final String remoteAddress;
	private final String sessionId;
	public WebAuthenticationDetails(HttpServletRequest request) {
		this.remoteAddress = request.getRemoteAddr();

		HttpSession session = request.getSession(false);
		this.sessionId = (session != null) ? session.getId() : null;
	}
    //省略其他方法
}
```

默认通过 WebAuthenticationDetailsSource 来构建 WebAuthenticationDetails，并将结果设置到 Authentication 的 details 属性中去。而 WebAuthenticationDetails 中定义的属性，大家看一下基本上就明白，这就是保存了用户登录地址和 sessionId。

那么看到这里，大家基本上就明白了，用户登录的 IP 地址实际上我们可以直接从 WebAuthenticationDetails 中获取到。

我举一个简单例子，例如我们登录成功后，可以通过如下方式随时随地拿到用户 IP：

```java
@Service
public class HelloService {
    public void hello() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        WebAuthenticationDetails details = (WebAuthenticationDetails) authentication.getDetails();
        System.out.println(details);
    }
}
```

这个获取过程之所以放在 service 来做，就是为了演示**随时随地**这个特性。然后我们在 controller 中调用该方法，当访问接口时，可以看到如下日志：

```java
WebAuthenticationDetails@fffc7f0c: RemoteIpAddress: 127.0.0.1; SessionId: 303C7F254DF8B86667A2B20AA0667160
```

可以看到，用户的 IP 地址和 SessionId 都给出来了。这两个属性在 WebAuthenticationDetails 中都有对应的 get 方法，也可以单独获取属性值。

## 3. 定制

当然，WebAuthenticationDetails 也可以自己定制，因为默认它只提供了 IP 和 sessionid 两个信息，如果我们想保存关于 Http 请求的更多信息，就可以通过自定义 WebAuthenticationDetails 来实现。

如果我们要定制 WebAuthenticationDetails，还要连同 WebAuthenticationDetailsSource 一起重新定义。

```java
public class MyAuthenticationProvider extends DaoAuthenticationProvider {

    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
        HttpServletRequest req = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest();
        String code = req.getParameter("code");
        String verify_code = (String) req.getSession().getAttribute("verify_code");
        if (code == null || verify_code == null || !code.equals(verify_code)) {
            throw new AuthenticationServiceException("验证码错误");
        }
        super.additionalAuthenticationChecks(userDetails, authentication);
    }
}
```

不过这个验证操作，我们也可以放在自定义的 WebAuthenticationDetails 中来做，我们定义如下两个类：

```java
public class MyWebAuthenticationDetails extends WebAuthenticationDetails {

    private boolean isPassed;

    public MyWebAuthenticationDetails(HttpServletRequest req) {
        super(req);
        String code = req.getParameter("code");
        String verify_code = (String) req.getSession().getAttribute("verify_code");
        if (code != null && verify_code != null && code.equals(verify_code)) {
            isPassed = true;
        }
    }

    public boolean isPassed() {
        return isPassed;
    }
}
@Component
public class MyWebAuthenticationDetailsSource implements AuthenticationDetailsSource<HttpServletRequest,MyWebAuthenticationDetails> {
    @Override
    public MyWebAuthenticationDetails buildDetails(HttpServletRequest context) {
        return new MyWebAuthenticationDetails(context);
    }
}
```

首先我们定义 MyWebAuthenticationDetails，由于它的构造方法中，刚好就提供了 HttpServletRequest 对象，所以我们可以直接利用该对象进行验证码判断，并将判断结果交给 isPassed 变量保存。**如果我们想扩展属性，只需要在 MyWebAuthenticationDetails 中再去定义更多属性，然后从 HttpServletRequest 中提取出来设置给对应的属性即可，这样，在登录成功后就可以随时随地获取这些属性了。**

最后在 MyWebAuthenticationDetailsSource 中构造 MyWebAuthenticationDetails 并返回。

定义完成后，接下来，我们就可以直接在 MyAuthenticationProvider 中进行调用了：

```java
public class MyAuthenticationProvider extends DaoAuthenticationProvider {

    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
        if (!((MyWebAuthenticationDetails) authentication.getDetails()).isPassed()) {
            throw new AuthenticationServiceException("验证码错误");
        }
        super.additionalAuthenticationChecks(userDetails, authentication);
    }
}
```

直接从 authentication 中获取到 details 并调用 isPassed 方法，有问题就抛出异常即可。

最后的问题就是如何用自定义的 MyWebAuthenticationDetailsSource 代替系统默认的 WebAuthenticationDetailsSource，很简单，我们只需要在 SecurityConfig 中稍作定义即可：

```java
@Autowired
MyWebAuthenticationDetailsSource myWebAuthenticationDetailsSource;
@Override
protected void configure(HttpSecurity http) throws Exception {
    http.authorizeRequests()
            ...
            .and()
            .formLogin()
            .authenticationDetailsSource(myWebAuthenticationDetailsSource)
            ...
}
```

将 MyWebAuthenticationDetailsSource 注入到 SecurityConfig 中，并在 formLogin 中配置 authenticationDetailsSource 即可成功使用我们自定义的 WebAuthenticationDetails。

这样自定义完成后，WebAuthenticationDetails 中原有的功能依然保留，也就是我们还可以利用老办法继续获取用户 IP 以及 sessionId 等信息，如下：

```java
@Service
public class HelloService {
    public void hello() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        MyWebAuthenticationDetails details = (MyWebAuthenticationDetails) authentication.getDetails();
        System.out.println(details);
    }
}
```

这里类型强转的时候，转为 MyWebAuthenticationDetails 即可。