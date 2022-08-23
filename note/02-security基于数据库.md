## 授权

所谓的授权，就是用户如果要访问某一个资源，我们要去检查用户是否具备这样的权限，如果具备就允许访问，如果不具备，则不允许访问。

### 准备数据库脚本

```sql
/*
Navicat MySQL Data Transfer
Source Server         : localhost
Source Server Version : 50717
Source Host           : localhost:3306
Source Database       : security
Target Server Type    : MYSQL
Target Server Version : 50717
File Encoding         : 65001
Date: 2018-07-28 15:26:51
*/

SET FOREIGN_KEY_CHECKS=0;

-- ----------------------------
-- Table structure for role
-- ----------------------------
DROP TABLE IF EXISTS `role`;
CREATE TABLE `role` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(32) DEFAULT NULL,
  `nameZh` varchar(32) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8;

-- ----------------------------
-- Records of role
-- ----------------------------
INSERT INTO `role` VALUES ('1', 'dba', '数据库管理员');
INSERT INTO `role` VALUES ('2', 'admin', '系统管理员');
INSERT INTO `role` VALUES ('3', 'user', '用户');

-- ----------------------------
-- Table structure for user
-- ----------------------------
DROP TABLE IF EXISTS `user`;
CREATE TABLE `user` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `username` varchar(32) DEFAULT NULL,
  `password` varchar(255) DEFAULT NULL,
  `enabled` tinyint(1) DEFAULT NULL,
  `locked` tinyint(1) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8;

-- ----------------------------
-- Records of user
-- ----------------------------
INSERT INTO `user` VALUES ('1', 'root', '$2a$10$RMuFXGQ5AtH4wOvkUqyvuecpqUSeoxZYqilXzbz50dceRsga.WYiq', '1', '0');
INSERT INTO `user` VALUES ('2', 'admin', '$2a$10$RMuFXGQ5AtH4wOvkUqyvuecpqUSeoxZYqilXzbz50dceRsga.WYiq', '1', '0');
INSERT INTO `user` VALUES ('3', 'sang', '$2a$10$RMuFXGQ5AtH4wOvkUqyvuecpqUSeoxZYqilXzbz50dceRsga.WYiq', '1', '0');

-- ----------------------------
-- Table structure for user_role
-- ----------------------------
DROP TABLE IF EXISTS `user_role`;
CREATE TABLE `user_role` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `uid` int(11) DEFAULT NULL,
  `rid` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8;

-- ----------------------------
-- Records of user_role
-- ----------------------------
INSERT INTO `user_role` VALUES ('1', '1', '1');
INSERT INTO `user_role` VALUES ('2', '1', '2');
INSERT INTO `user_role` VALUES ('3', '2', '2');
INSERT INTO `user_role` VALUES ('4', '3', '3');
SET FOREIGN_KEY_CHECKS=1;
```

### 实体类

1. User 类 实现 UserDetail 接口中的方法

   ```java
   @Data
   @NoArgsConstructor
   @AllArgsConstructor
   @Accessors(chain = true)
   @ToString(callSuper = true)
   @TableName(value = "user",resultMap = "userWithRolesMap")
   public class User implements UserDetails {
       @TableId(type = IdType.AUTO)
       private Integer id;
       private String username;
       private String password;
       private Boolean enabled;
       private Boolean locked;
   
       private List<Role> roles;
   
       @Override
       public Collection<? extends GrantedAuthority> getAuthorities() {
           List<SimpleGrantedAuthority> authorities = new ArrayList<>();
           roles.forEach(r->{
               authorities.add(new SimpleGrantedAuthority("ROLE_"+r.getName()));
           });
           return authorities;
       }
   
       @Override
       public boolean isAccountNonExpired() {
           return true;
       }
   
       @Override
       public boolean isAccountNonLocked() {
           return !locked;
       }
   
       @Override
       public boolean isCredentialsNonExpired() {
           return true;
       }
   
       @Override
       public boolean isEnabled() {
           return enabled;
       }
   }
   ```

2. Role 类

   ```java
   @Data
   @TableName("role")
   public class Role {
       private Integer id;
       private String name;
       private String nameZh;
   }
   ```

3. UserService 类实现 UserDetailService 类

   ```java
   @Service
   public class UserServiceImpl implements UserService , UserDetailsService {
   
       @Autowired
       UserMapper userMapper;
   
       /**
        * 根据用户名查询用户
        * @param username the username identifying the user whose data is required.
        * @return UserDetails
        * @throws UsernameNotFoundException
        */
       @Override
       public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
           User user = userMapper.selectOne(
                   new LambdaQueryWrapper<User>().eq(User::getUsername, username)
           );
           if(user==null){
               throw new UsernameNotFoundException("用户不存在");
           }
   
           return user;
       }
   }
   ```

4. UserMapper 接口

   ```java
   @Mapper
   public interface UserMapper extends BaseMapper<User> {
   }
   ```

5. UserMapper.xml

   ```xml
   <mapper namespace="com.wenx.security.security.mapper.UserMapper">
       <resultMap id="userWithRolesMap" type="com.wenx.security.security.bean.User">
           <id column="id" property="id"/>
           <result column="username" property="username"/>
           <result column="password" property="password"/>
           <result column="enabled" property="enabled"/>
           <result column="locked" property="locked"/>
           <collection property="roles" column="id" select="com.wenx.security.security.mapper.RoleMapper.selectRolesByUid"/>
       </resultMap>
   </mapper>
   ```

6. RoleMapper.xml

   ```xml
   <mapper namespace="com.wenx.security.security.mapper.RoleMapper">
       <select id="selectRolesByUid" resultType="com.wenx.security.security.bean.Role">
           select r.* from role r,user u,user_role ur where u.id=ur.uid and r.id=ur.rid and u.id = #{uid}
       </select>
   </mapper>
   ```

### 配置类

```java
package com.wenx.security.security.config;

import com.wenx.security.security.service.UserService;
import com.wenx.security.security.service.impl.UserServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.annotation.Resource;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Resource
    UserServiceImpl userService;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userService);
    }

    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/dba/**").hasRole("dba")
                .antMatchers("/user/**").hasRole("user")
                .antMatchers("/admin/**").hasRole("admin")
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .permitAll()
                .and()
                .csrf().disable();
    }
}
```

### 准备接口

```java
    @GetMapping("/hello")
    String hello(){
        return "hello";
    }

    @GetMapping("/dba/hello")
    String dbaHello(){
        return "DBA hello";
    }

    @GetMapping("/admin/hello")
    String adminHello(){
        return "admin hello";
    }

    @GetMapping("/user/hello")
    String userHello(){
        return "user hello";
    }

```

当我们使用 root 用户进行登录，`/dba/hello` `/admin/hello`是可以进行访问的 `/user/hello`没有权限访问

## 角色继承

角色继承实际上是一个很常见的需求，因为大部分公司治理可能都是金字塔形的，上司可能具备下属的部分甚至所有权限，这一现实场景，反映到我们的代码中，就是角色继承了。 Spring Security 中为开发者提供了相关的角色继承解决方案，但是这一解决方案在最近的 Spring Security 版本变迁中，使用方法有所变化。

pringSecurity 在角色继承上有两种不同的写法，在 Spring Boot2.0.8（对应 Spring Security 也是 5.0.11）上面是一种写法，从 Spring Boot2.1.0（对应 Spring Security5.1.1）又是另外一种写法

### 以前的写法

这里说的以前写法，就是指 SpringBoot2.0.8（含）之前的写法，在之前的写法中，角色继承只需要开发者提供一个 RoleHierarchy 接口的实例即可，例如下面这样：

```java
@Bean
RoleHierarchy roleHierarchy() {
    RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
    String hierarchy = "ROLE_dba > ROLE_admin ROLE_admin > ROLE_user";
    roleHierarchy.setHierarchy(hierarchy);
    return roleHierarchy;
}
```

在这里我们提供了一个 RoleHierarchy 接口的实例，使用字符串来描述了角色之间的继承关系， `ROLE_dba` 具备 `ROLE_admin` 的所有权限，而 `ROLE_admin` 则具备 `ROLE_user` 的所有权限，继承与继承之间用一个空格隔开。提供了这个 Bean 之后，以后所有具备 `ROLE_user` 角色才能访问的资源， `ROLE_dba` 和 `ROLE_admin` 也都能访问，具备 `ROLE_amdin` 角色才能访问的资源， `ROLE_dba` 也能访问。

### 现在的写法

但是上面这种写法仅限于 Spring Boot2.0.8（含）之前的版本，在之后的版本中，这种写法则不被支持，新版的写法是下面这样：

```java
@Bean
RoleHierarchy roleHierarchy() {
    RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
    String hierarchy = "ROLE_dba > ROLE_admin \n ROLE_admin > ROLE_user";
    roleHierarchy.setHierarchy(hierarchy);
    return roleHierarchy;
}
```

变化主要就是分隔符，将原来用空格隔开的地方，现在用换行符了。这里表达式的含义依然和上面一样，不再赘述。

上面两种不同写法都是配置角色的继承关系，配置完成后，接下来指定角色和资源的对应关系即可，如下：

```java
@Override
protected void configure(HttpSecurity http) throws Exception {
    http.authorizeRequests().antMatchers("/admin/**")
            .hasRole("admin")
            .antMatchers("/db/**")
            .hasRole("dba")
            .antMatchers("/user/**")
            .hasRole("user")
            .and()
            .formLogin()
            .loginProcessingUrl("/doLogin")
            .permitAll()
            .and()
            .csrf().disable();
}
```

这个表示 `/db/**` 格式的路径需要具备 dba 角色才能访问， `/admin/**` 格式的路径则需要具备 admin 角色才能访问， `/user/**` 格式的路径，则需要具备 user 角色才能访问，此时提供相关接口，会发现，dba 除了访问 `/db/**` ，也能访问 `/admin/**` 和 `/user/**` ，admin 角色除了访问 `/admin/**` ，也能访问 `/user/**` ，user 角色则只能访问 `/user/**` 。

### 源码分析

这样两种不同的写法，其实也对应了两种不同的解析策略，角色继承关系的解析在 RoleHierarchyImpl 类的 buildRolesReachableInOneStepMap 方法中，Spring Boot2.0.8（含）之前该方法的源码如下：

```java
private void buildRolesReachableInOneStepMap() {
	Pattern pattern = Pattern.compile("(\\s*([^\\s>]+)\\s*>\\s*([^\\s>]+))");
	Matcher roleHierarchyMatcher = pattern
			.matcher(this.roleHierarchyStringRepresentation);
	this.rolesReachableInOneStepMap = new HashMap<GrantedAuthority, Set<GrantedAuthority>>();
	while (roleHierarchyMatcher.find()) {
		GrantedAuthority higherRole = new SimpleGrantedAuthority(
				roleHierarchyMatcher.group(2));
		GrantedAuthority lowerRole = new SimpleGrantedAuthority(
				roleHierarchyMatcher.group(3));
		Set<GrantedAuthority> rolesReachableInOneStepSet;
		if (!this.rolesReachableInOneStepMap.containsKey(higherRole)) {
			rolesReachableInOneStepSet = new HashSet<>();
			this.rolesReachableInOneStepMap.put(higherRole,
					rolesReachableInOneStepSet);
		}
		else {
			rolesReachableInOneStepSet = this.rolesReachableInOneStepMap
					.get(higherRole);
		}
		addReachableRoles(rolesReachableInOneStepSet, lowerRole);
		logger.debug("buildRolesReachableInOneStepMap() - From role " + higherRole
				+ " one can reach role " + lowerRole + " in one step.");
	}
}
```

从这段源码中我们可以看到，角色的继承关系是通过正则表达式进行解析，通过空格进行切分，然后构建相应的 map 出来。

Spring Boot2.1.0（含）之后该方法的源码如下：

```java
private void buildRolesReachableInOneStepMap() {
	this.rolesReachableInOneStepMap = new HashMap<GrantedAuthority, Set<GrantedAuthority>>();
	try (BufferedReader bufferedReader = new BufferedReader(
			new StringReader(this.roleHierarchyStringRepresentation))) {
		for (String readLine; (readLine = bufferedReader.readLine()) != null;) {
			String[] roles = readLine.split(" > ");
			for (int i = 1; i < roles.length; i++) {
				GrantedAuthority higherRole = new SimpleGrantedAuthority(
						roles[i - 1].replaceAll("^\\s+|\\s+$", ""));
				GrantedAuthority lowerRole = new SimpleGrantedAuthority(roles[i].replaceAll("^\\s+|\\s+$
				Set<GrantedAuthority> rolesReachableInOneStepSet;
				if (!this.rolesReachableInOneStepMap.containsKey(higherRole)) {
					rolesReachableInOneStepSet = new HashSet<GrantedAuthority>();
					this.rolesReachableInOneStepMap.put(higherRole, rolesReachableInOneStepSet);
				} else {
					rolesReachableInOneStepSet = this.rolesReachableInOneStepMap.get(higherRole);
				}
				addReachableRoles(rolesReachableInOneStepSet, lowerRole);
				if (logger.isDebugEnabled()) {
					logger.debug("buildRolesReachableInOneStepMap() - From role " + higherRole
							+ " one can reach role " + lowerRole + " in one step.");
				}
			}
		}
	} catch (IOException e) {
		throw new IllegalStateException(e);
	}
}
```

从这里我们可以看到，这里并没有一上来就是用正则表达式，而是先将角色继承字符串转为一个 BufferedReader ，然后一行一行的读出来，再进行解析，最后再构建相应的 map。从这里我们可以看出为什么前后版本对此有不同的写法。