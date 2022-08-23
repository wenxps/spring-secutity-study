package com.wenx.security.security.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.wenx.security.security.bean.Role;
import org.apache.catalina.LifecycleState;
import org.apache.catalina.mbeans.BaseCatalinaMBean;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;

@Mapper
public interface RoleMapper extends BaseMapper<Role> {

    List<Role> selectRolesByUid(Integer uid);
}