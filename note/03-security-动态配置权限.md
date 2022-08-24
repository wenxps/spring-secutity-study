[TOC]

## RBAC权限设计思想

为了达成不同账号(员工，经理，BOSS)登录系统后能看到不同页面，执行不同的功能，RBAC(Role-Based-Access-Control)权限模型，就是根据角色的权限，分配可视页面。

### 三个关键点：

**用户**:使用系统的人
**角色**：使用系统的人是什么职位(员工，经理，BOSS)
**权限点**：职位可以做的事情(左侧菜单栏中的功能模块——>增删改查)

**测试流程**：
①在员工管理页新增员工这是三要素中的**用户**
②为新增的员工**分配角色**
③在公司设置里为角色**分配权限**

💢系统中的权限不能随意添加，必须是以开发出来的权限（左侧菜单栏里可实现的页面）
💢用户和角色之间是**一对多**的关系，一个人身兼数职。

### 数据库设计：

本案例数据库设计共涉及五张表：user role user_role menu menu_role

```sql
/*
 Navicat Premium Data Transfer

 Source Server         : 本地
 Source Server Type    : MySQL
 Source Server Version : 50734
 Source Host           : localhost:3306
 Source Schema         : security

 Target Server Type    : MySQL
 Target Server Version : 50734
 File Encoding         : 65001

 Date: 24/08/2022 15:36:45
*/

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ----------------------------
-- Table structure for menu
-- ----------------------------
DROP TABLE IF EXISTS `menu`;
CREATE TABLE `menu`  (
  `id` int(8) NOT NULL AUTO_INCREMENT,
  `pattern` varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
  PRIMARY KEY (`id`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 1 CHARACTER SET = utf8 COLLATE = utf8_general_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of menu
-- ----------------------------

-- ----------------------------
-- Table structure for menu_role
-- ----------------------------
DROP TABLE IF EXISTS `menu_role`;
CREATE TABLE `menu_role`  (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `mid` int(11) NOT NULL,
  `rid` int(11) NOT NULL,
  PRIMARY KEY (`id`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 4 CHARACTER SET = utf8 COLLATE = utf8_general_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of menu_role
-- ----------------------------
INSERT INTO `menu_role` VALUES (1, 1, 1);
INSERT INTO `menu_role` VALUES (2, 2, 2);
INSERT INTO `menu_role` VALUES (3, 3, 3);

-- ----------------------------
-- Table structure for role
-- ----------------------------
DROP TABLE IF EXISTS `role`;
CREATE TABLE `role`  (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(32) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
  `nameZh` varchar(32) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
  PRIMARY KEY (`id`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 4 CHARACTER SET = utf8 COLLATE = utf8_general_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of role
-- ----------------------------
INSERT INTO `role` VALUES (1, 'ROLE_dba', '数据库管理员');
INSERT INTO `role` VALUES (2, 'ROLE_admin', '系统管理员');
INSERT INTO `role` VALUES (3, 'ROLE_user', '用户');

-- ----------------------------
-- Table structure for user
-- ----------------------------
DROP TABLE IF EXISTS `user`;
CREATE TABLE `user`  (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `username` varchar(32) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
  `password` varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
  `enabled` tinyint(1) NULL DEFAULT NULL,
  `locked` tinyint(1) NULL DEFAULT NULL,
  PRIMARY KEY (`id`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 4 CHARACTER SET = utf8 COLLATE = utf8_general_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of user
-- ----------------------------
INSERT INTO `user` VALUES (1, 'root', '$2a$10$RMuFXGQ5AtH4wOvkUqyvuecpqUSeoxZYqilXzbz50dceRsga.WYiq', 1, 0);
INSERT INTO `user` VALUES (2, 'admin', '$2a$10$RMuFXGQ5AtH4wOvkUqyvuecpqUSeoxZYqilXzbz50dceRsga.WYiq', 1, 0);
INSERT INTO `user` VALUES (3, 'sang', '$2a$10$RMuFXGQ5AtH4wOvkUqyvuecpqUSeoxZYqilXzbz50dceRsga.WYiq', 1, 0);

-- ----------------------------
-- Table structure for user_role
-- ----------------------------
DROP TABLE IF EXISTS `user_role`;
CREATE TABLE `user_role`  (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `uid` int(11) NULL DEFAULT NULL,
  `rid` int(11) NULL DEFAULT NULL,
  PRIMARY KEY (`id`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 5 CHARACTER SET = utf8 COLLATE = utf8_general_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of user_role
-- ----------------------------
INSERT INTO `user_role` VALUES (1, 1, 1);
INSERT INTO `user_role` VALUES (2, 1, 2);
INSERT INTO `user_role` VALUES (3, 2, 2);
INSERT INTO `user_role` VALUES (4, 3, 3);

SET FOREIGN_KEY_CHECKS = 1;
```

## 项目创建

### 代码修改

相较于上一个项目添加了一个实体类相关代码

`Menu.java`

```java
@Data
@NoArgsConstructor
@AllArgsConstructor
@Accessors(chain = true)
@ToString(callSuper = true)
@TableName(value = "menu",resultMap = "menuWithRolesMap")
public class Menu {
    @TableId(type = IdType.AUTO)
    private Integer id;
    private String pattern;

    private List<Role> roles;
}
```

`MenuMapper`

```java
<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN" "http://mybatis.org/dtd/mybatis-3-mapper.dtd" >
<mapper namespace="com.wenx.security.dynamic.mapper.MenuMapper">
    <resultMap id="menuWithRolesMap" type="com.wenx.security.dynamic.bean.Menu">
        <id column="id" property="id"/>
        <result column="pattern" property="pattern"/>
        <collection property="roles" column="id" select="com.wenx.security.dynamic.mapper.RoleMapper.selectRolesByMid"/>
    </resultMap>
</mapper>
```

`修改RoleMapper.xml`

```xml
<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN" "http://mybatis.org/dtd/mybatis-3-mapper.dtd" >
<mapper namespace="com.wenx.security.dynamic.mapper.RoleMapper">

    <select id="selectRolesByUid" resultType="com.wenx.security.dynamic.bean.Role">
        select r.* from role r,user u,user_role ur where u.id=ur.uid and r.id=ur.rid and u.id = #{uid}
    </select>

    <select id="selectRolesByMid" resultType="com.wenx.security.dynamic.bean.Role">
        select r.* from role r,menu m,menu_role mr where m.id=mr.mid and r.id=mr.rid and m.id = #{mid}
    </select>
</mapper>
```

### 重写 FilterInvocationSecurityMetadataSource

`MyFiletr.java`

```java
/**
 * @author 温笙
 */
@Component
public class MyFilter implements FilterInvocationSecurityMetadataSource {

    // 路径规则匹配器
    AntPathMatcher antPathMatcher = new AntPathMatcher();

    @Autowired
    MenuMapper menuMapper;

    @Override
    public Collection<ConfigAttribute> getAttributes(Object object) throws IllegalArgumentException {
        String requestUrl = ((FilterInvocation) object).getRequestUrl();
        List<Menu> menus = menuMapper.selectList(null);
        for (Menu menu : menus) {
            if(antPathMatcher.match(menu.getPattern(),requestUrl)){
                List<Role> roles = menu.getRoles();
                String[] rolesStr = new String[roles.size()];
                for (int i = 0; i < roles.size(); i++) {
                    rolesStr[i]=roles.get(i).getName();
                }
                return SecurityConfig.createList(rolesStr);
            }
        }

        return SecurityConfig.createList("ROLE_login");
    }

    @Override
    public Collection<ConfigAttribute> getAllConfigAttributes() {
        return null;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return false;
    }
}
```

> 用户所有的请求都会进入getAttributes这个方法中，通过路径匹配器进行匹配，将对应的权限字符串进行返回，如果匹配不到就返回一个`ROLE_login`标志符，后续进行判断放行。

### 重写决策管理器AccessDecisionManager

```java
@Component
public class MyAccessDecisionManager implements AccessDecisionManager {

    @Override
    public void decide(Authentication authentication, Object object, Collection<ConfigAttribute> configAttributes) throws AccessDeniedException, InsufficientAuthenticationException {
        for (ConfigAttribute attribute : configAttributes) {
            if("ROLE_login".equals(attribute.getAttribute())){
                if(authentication instanceof AnonymousAuthenticationToken){
                    throw new AccessDeniedException("非法请求");
                }else{
                    return;
                }
            }

            Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
            for (GrantedAuthority authority : authorities) {
                if(authority.getAuthority().equals(attribute.getAttribute())){
                    return;
                }
            }

        }
        throw new AccessDeniedException("非法请求");
    }

    @Override
    public boolean supports(ConfigAttribute attribute) {
        return true;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return true;
    }
}
```

### 配置类

```java
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Resource
    UserService userService;

    @Autowired
    MyFilter myFilter;

    @Autowired
    MyAccessDecisionManager myAccessDecisionManager;

    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userService);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .withObjectPostProcessor(new ObjectPostProcessor<FilterSecurityInterceptor>() {
                    @Override
                    public <O extends FilterSecurityInterceptor> O postProcess(O object) {
                        object.setAccessDecisionManager(myAccessDecisionManager);
                        object.setSecurityMetadataSource(myFilter);
                        return object;
                    }
                })
                .and()
                .formLogin()
                .permitAll()
                .and()
                .csrf().disable();
    }
}
```



## 源码分析

首先在 Spring Security 中的权限控制有两种不同的方式：

1. 通过 URL 请求地址进行控制。
2. 通过方法进行控制。

如果通过 URL 请求地址进行控制，负责控制类配置的是 AbstractInterceptUrlConfigurer，我们来看下它的子类：

```markdown
# AbstractInterceptUrlConfigurer
## UrlAuthorizationConfigurer
## ExpressionUrlAuthorizationConfigurer
```

可以看到它有两个子类：

- ExpressionUrlAuthorizationConfigurer
- UrlAuthorizationConfigurer

两个都可以处理基于 URL 请求地址的权限控制。不同的是，第一个 ExpressionUrlAuthorizationConfigurer
支持权限表达式，第二个不支持。

UrlAuthorizationConfigurer 不支持权限表达式，是因为它使用的投票器是 RoleVoter 和 AuthenticatedVoter，这两者可以用来处理角色或者权限，但是没法处理权限表达式。

上面说的都是默认行为，我们也可以通过修改配置，让 UrlAuthorizationConfigurer 支持权限表达式，不过一般来说没必要这样做，如果需要支持权限表达式，直接用 ExpressionUrlAuthorizationConfigurer 即可。

当我们调用如下这行代码时：

```java
http.authorizeRequests()
```

实际上就是通过 ExpressionUrlAuthorizationConfigurer 去配置基于 URL 请求地址的权限控制，所以它是支持权限表达式的。例如下面这段大家再熟悉不过的代码：

```java
http.authorizeRequests()
        .antMatchers("/admin/**").hasRole("ADMIN")
        .antMatchers("/user/**").access("hasRole('USER')")

```

在 ExpressionUrlAuthorizationConfigurer 中创建 SecurityMetadataSource 时，就会检查映射关系，如果 requestMap 为空就会抛出异常：

```java
@Override
ExpressionBasedFilterInvocationSecurityMetadataSource createMetadataSource(
		H http) {
	LinkedHashMap<RequestMatcher, Collection<ConfigAttribute>> requestMap = REGISTRY
			.createRequestMap();
	if (requestMap.isEmpty()) {
		throw new IllegalStateException(
				"At least one mapping is required (i.e. authorizeRequests().anyRequest().authenticated())");
	}
	return new ExpressionBasedFilterInvocationSecurityMetadataSource(requestMap,
			getExpressionHandler(http));
}
```

UrlAuthorizationConfigurer 中也有 createMetadataSource 方法，但是却是另外一套实现方案：

```java
@Override
FilterInvocationSecurityMetadataSource createMetadataSource(H http) {
	return new DefaultFilterInvocationSecurityMetadataSource(
			REGISTRY.createRequestMap());
}
```

UrlAuthorizationConfigurer 并不会检查 requestMap 是否为空，但是它会在 createRequestMap 方法中检查一下映射关系是否完整，例如下面这样：

```java
.antMatchers("/admin/**").access("ROLE_ADMIN")
.mvcMatchers("/user/**").access("ROLE_USER")
.antMatchers("/getinfo");
```

最后的 /getinfo 没有指定需要的权限，这种就是不完整，就会抛出异常。

ExpressionUrlAuthorizationConfigurer 会要求至少配置一个映射关系，UrlAuthorizationConfigurer 则无此要求。





