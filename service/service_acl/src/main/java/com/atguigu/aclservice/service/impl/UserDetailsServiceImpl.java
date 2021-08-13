package com.atguigu.aclservice.service.impl;

import com.atguigu.aclservice.entity.User;
import com.atguigu.aclservice.service.PermissionService;
import com.atguigu.aclservice.service.UserService;
import com.atguigu.security.entity.SecurityUser;
import org.springframework.beans.BeanUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.List;

@Service("userDetailsService")
public class UserDetailsServiceImpl implements UserDetailsService {
    @Resource
    private UserService userService;
    @Resource
    private PermissionService permissionService;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        //根据用户名查信息
        User user = userService.selectByUsername(username);
        //判断
        if (user == null){
            throw new UsernameNotFoundException("用户不存在");
        }
        //有两个user 区分
        com.atguigu.security.entity.User secUser = new com.atguigu.security.entity.User();
        //复制
        BeanUtils.copyProperties(user,secUser);
        //根据用户查询权限
        List<String> permissionValueList = permissionService.selectPermissionValueByUserId(user.getId());
        //放到securityUser里面 把权限
        SecurityUser securityUser = new SecurityUser();
        securityUser.setPermissionValueList(permissionValueList);

        return securityUser;
    }
}
