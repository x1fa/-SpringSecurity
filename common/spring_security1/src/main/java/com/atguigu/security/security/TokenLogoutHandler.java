package com.atguigu.security.security;

import com.atguigu.utils.utils.R;
import com.atguigu.utils.utils.ResponseUtil;
import org.springframework.core.annotation.Order;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class TokenLogoutHandler implements LogoutHandler {
    private TokenManager tokenManager;
    private RedisTemplate redisTemplate;
    public TokenLogoutHandler(TokenManager tokenManager,RedisTemplate redisTemplate){
        this.tokenManager = tokenManager;
        this.redisTemplate = redisTemplate;
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        String token = request.getHeader("token");
        //移除 token
        if (token !=null ){
        tokenManager.removeToken(token);
        //redis 中 移除
        //根据token获取用户
        String username = tokenManager.getUserInfoFormToken(token);
        redisTemplate.delete("username");
        }
        ResponseUtil.out(response, R.ok());
    }
}
