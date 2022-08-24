package com.wenx.security.dynamic.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.wenx.security.dynamic.bean.Role;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;

@Mapper
public interface RoleMapper extends BaseMapper<Role> {

    List<Role> selectRolesByUid(Integer uid);

    List<Role> selectRolesByMid(Integer mid);
}