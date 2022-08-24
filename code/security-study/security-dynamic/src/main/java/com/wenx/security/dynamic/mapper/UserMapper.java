package com.wenx.security.dynamic.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.wenx.security.dynamic.bean.User;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface UserMapper extends BaseMapper<User> {
}