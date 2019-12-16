package com.example.demoshiro;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.annotation.RequiresAuthentication;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.subject.Subject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class TestController {

    @RequiresRoles("admin")
    @RequestMapping(value = "/test1")
    @ResponseBody
    public String test1(){
        return "test1";
    }

    @Autowired
    @Qualifier("ManagerA")
    DefaultSecurityManager customRealmSecurityManager;

    @RequestMapping(value = "/logn")
    @ResponseBody
    public String login(@RequestParam("username")String username,
                        @RequestParam("password")String password){

        SecurityUtils.setSecurityManager(customRealmSecurityManager);
        Subject subject = SecurityUtils.getSubject();
        UsernamePasswordToken token = new UsernamePasswordToken("mark","123456");
        subject.login(token);

        System.out.println(subject.isAuthenticated());


        return "login success";
    }

}
