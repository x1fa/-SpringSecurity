package com.atguigu.security.filter;

import com.atguigu.security.security.TokenManager;
import org.springframework.data.redis.core.ReactiveSetOperations;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class TokenAuthenticationFilter extends BasicAuthenticationFilter {

    private TokenManager tokenManager;
    private RedisTemplate redisTemplate;
    //有参构造
    public TokenAuthenticationFilter(AuthenticationManager authenticationManager,TokenManager tokenManager,RedisTemplate redisTemplate) {
        super(authenticationManager);
        this.tokenManager = tokenManager;
        this.redisTemplate = redisTemplate;
    }
    //从写doFilterInternal
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        //获取用户权限信息
        UsernamePasswordAuthenticationToken authRequest = getAuthentication(request);
        //判断 权限信息是否为空
        if (authRequest != null){
            //不为空 放到权限上下文中
            SecurityContextHolder.getContext().setAuthentication(authRequest);
        }
        chain.doFilter(request, response);
    }

    private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request) {
        //先从 request 中的header 获取token
        String token = request.getHeader("token");
        //判断 token 是否为空
        if (token != null){
            //根据token获取用户名
            String username = tokenManager.getUserInfoFormToken(token);
            //根据用户名 在redis中获取 权限列表
            List<String> pvList = (List<String>) redisTemplate.opsForValue().get(username);
            //由于UsernamePasswordAuthenticationToken返回的第三个参数的数组类型 需要遍历转换
            Collection<GrantedAuthority> authority = new ArrayList<>();
            for (String s : pvList) {
                SimpleGrantedAuthority auth = new SimpleGrantedAuthority(s);
                authority.add(auth);
            }
            return new UsernamePasswordAuthenticationToken(username,token,authority);
        }
        return null;
    }

}
