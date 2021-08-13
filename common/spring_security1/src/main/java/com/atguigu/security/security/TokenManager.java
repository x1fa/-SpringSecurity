package com.atguigu.security.security;

import io.jsonwebtoken.CompressionCodecs;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class TokenManager {
    //token 有效时长
    private int tokenEcpiration = 24*60*60*1000;
    //编码密钥
    private String tokenSignKey = "123456";
    //根据用户名生成token
    public String createToke(String username){
        String token = Jwts.builder() //创建
                .setSubject(username) //因为根据用户名创建token 所以设置用户名
                //根据创建token的当前时间 用new Date 加上 有效时长 是失效时间
                .setExpiration(new Date(System.currentTimeMillis() + tokenEcpiration))
                //设置 密钥。首先放入 签名算法  然后再把密钥放进去
                .signWith(SignatureAlgorithm.ES512, tokenSignKey)
                //以GZIP方式 压缩编码
                .compressWith(CompressionCodecs.GZIP)
                .compact();
        return token;
    }
    //根据token字符串 获取 用户名
    public String getUserInfoFormToken(String token){
        //设置密钥 解析token 获取body 获取subject
        String userInfo = Jwts.parser().setSigningKey(tokenSignKey).parseClaimsJws(token).getBody().getSubject();
        return userInfo;
    }
    //删除token 前端不携带token就可以
    public void removeToken(String token){}
}
