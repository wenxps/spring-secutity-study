package com.wenx.security.dynamic.config;

import com.wenx.security.dynamic.bean.Menu;
import com.wenx.security.dynamic.bean.Role;
import com.wenx.security.dynamic.mapper.MenuMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

import javax.crypto.MacSpi;
import java.util.Collection;
import java.util.List;

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