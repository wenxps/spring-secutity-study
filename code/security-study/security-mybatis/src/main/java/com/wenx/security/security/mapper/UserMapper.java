package com.wenx.security.security.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.wenx.security.security.bean.User;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface UserMapper extends BaseMapper<User> {
}