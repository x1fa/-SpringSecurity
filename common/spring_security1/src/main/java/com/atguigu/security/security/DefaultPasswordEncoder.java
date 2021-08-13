package com.atguigu.security.security;

import com.atguigu.utils.utils.MD5;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import sun.security.util.Password;

@Component
public class DefaultPasswordEncoder implements PasswordEncoder {
    public DefaultPasswordEncoder(){
        this(-1);
    }
    public DefaultPasswordEncoder(int strenth){
    }
//MD5加密
    @Override
    public String encode(CharSequence charSequence) {
        return MD5.encrypt(charSequence.toString());
    }
//进行密码比对
    @Override
    public boolean matches(CharSequence charSequence, String s) {
        return s.equals(MD5.encrypt(charSequence.toString()));
    }
}
