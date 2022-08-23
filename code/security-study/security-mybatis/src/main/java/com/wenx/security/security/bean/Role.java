package com.wenx.security.security.bean;

import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;

@Data
@TableName("role")
public class Role {
    private Integer id;
    private String name;
    private String nameZh;
}