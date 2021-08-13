package com.atguigu.security.config;

import com.atguigu.security.filter.TokenAuthenticationFilter;
import com.atguigu.security.filter.TokenLoginFilter;
import com.atguigu.security.security.DefaultPasswordEncoder;
import com.atguigu.security.security.TokenLogoutHandler;
import com.atguigu.security.security.TokenManager;
import com.atguigu.security.security.UnauthEntryPoint;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class TokenWebSecurityConfig extends WebSecurityConfigurerAdapter {
    //token 管理工具类
    private TokenManager tokenManager;
    //密码 管理工具类
    private DefaultPasswordEncoder defaultPasswordEncoder;
    //redis 操作工具类
    private RedisTemplate redisTemplate;
    //自定义查询数据库 用户名 密码 权限信息
    private UserDetailsService userDetailsService;

    @Autowired
    public TokenWebSecurityConfig(TokenManager tokenManager,
            DefaultPasswordEncoder defaultPasswordEncoder,
            RedisTemplate redisTemplate,
            UserDetailsService userDetailsService){
        this.tokenManager = tokenManager;
        this.defaultPasswordEncoder = defaultPasswordEncoder;
        this.redisTemplate = redisTemplate;
        this.userDetailsService = userDetailsService;
    }
    //密码处理
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(defaultPasswordEncoder);
    }
    //配置设置
    @Override
    protected void configure(HttpSecurity http) throws Exception {
                //异常
        http.exceptionHandling()
                //没有权限访问 就跳转到 自定义
                .authenticationEntryPoint(new UnauthEntryPoint())
                //管理 csrf
                .and().csrf().disable()
                //权限
                .authorizeRequests()
                .anyRequest().authenticated()
                //退出登录
                .and().logout().logoutUrl("/admin/acl/index/logout")
                //退出登录 操作token和redis
                .addLogoutHandler(new TokenLogoutHandler(tokenManager,redisTemplate))
                .and()
                //添加登录过滤器
                .addFilter(new TokenLoginFilter(tokenManager,redisTemplate,authenticationManager()))
                //权限过滤器
                .addFilter(new TokenAuthenticationFilter(authenticationManager(),tokenManager,redisTemplate)).httpBasic();
    }
    //配置哪些不拦截
    @Override
    public void configure(WebSecurity web) throws Exception {
       web.ignoring().antMatchers("/api/**","swagger-ui.html/**");
    }
}
