package com.example.demoshiro;

import com.alibaba.druid.pool.DruidDataSource;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.realm.SimpleAccountRealm;
import org.apache.shiro.realm.jdbc.JdbcRealm;
import org.apache.shiro.realm.text.IniRealm;
import org.apache.shiro.subject.Subject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.event.annotation.BeforeTestMethod;

//@SpringBootTest
class DemoshiroApplicationTests {

    @Test
    void contextLoads() {
    }

    private SimpleAccountRealm simpleAccountRealm = new SimpleAccountRealm();


    public void addUser(String username,String password){
        simpleAccountRealm.addAccount(username,password);
    }
    public void addUser(String username,String password,String role){
        simpleAccountRealm.addAccount(username,password,role);
    }

    @Test
    public void testAuthentication(){

        addUser("mark","123456");

        //1. build SecurityManager enviorment
        DefaultSecurityManager defaultSecurityManager = new DefaultSecurityManager();
        defaultSecurityManager.setRealm(simpleAccountRealm);

        //2.Subject submits certification
        SecurityUtils.setSecurityManager(defaultSecurityManager);
        Subject subject = SecurityUtils.getSubject();

        UsernamePasswordToken token = new UsernamePasswordToken("mark","123456");
        subject.login(token);

        System.out.println("isAuthenticate:"+subject.isAuthenticated());
        subject.logout();
    }
    @Test public void testAuthorizer(){
        addUser("mark","123456","admin");

        //1. build securityManager enviorment
        DefaultSecurityManager defaultSecurityManager = new DefaultSecurityManager();
        defaultSecurityManager.setRealm(simpleAccountRealm);

        //2.subject submit certification
        SecurityUtils.setSecurityManager(defaultSecurityManager);
        Subject subject = SecurityUtils.getSubject();

        UsernamePasswordToken token = new UsernamePasswordToken("mark","123456");
        subject.login(token);

        System.out.println(subject.isAuthenticated());

        subject.checkRole("admin");

        subject.logout();
    }

    @Test
    public void testIniRealm(){
        IniRealm iniRealm = new IniRealm("classpath:user.ini");

        //1. build securityManager enviorment
        DefaultSecurityManager defaultSecurityManager = new DefaultSecurityManager();
        defaultSecurityManager.setRealm(iniRealm);

        //2.subject submit certification
        SecurityUtils.setSecurityManager(defaultSecurityManager);
        Subject subject = SecurityUtils.getSubject();

        UsernamePasswordToken token = new UsernamePasswordToken("mark","123456");
        subject.login(token);

        System.out.println(subject.isAuthenticated());

        subject.checkRole("admin");
        subject.checkPermission("user:delete");

        subject.logout();
    }

    private DruidDataSource druidDataSource = new DruidDataSource();

    {
        druidDataSource.setUrl("jdbc:mysql://localhost:3306/test");
        druidDataSource.setUsername("root");
        druidDataSource.setPassword("123456");
    }

    @Test
    public void testJdbcRealm(){
        JdbcRealm jdbcRealm = new JdbcRealm();
        jdbcRealm.setDataSource(druidDataSource);
        jdbcRealm.setPermissionsLookupEnabled(true);
        String sql = "select user_info.password from user_password left join user_info on user_password.user_id=user_info.id where user_info.username = ?";
        jdbcRealm.setAuthenticationQuery(sql);

        //1. build securityManager enviorment
        DefaultSecurityManager defaultSecurityManager = new DefaultSecurityManager();
        defaultSecurityManager.setRealm(jdbcRealm);

        //2.subject submit certification
        SecurityUtils.setSecurityManager(defaultSecurityManager);
        Subject subject = SecurityUtils.getSubject();

        UsernamePasswordToken token = new UsernamePasswordToken("mark","123456");
        subject.login(token);

        System.out.println(subject.isAuthenticated());

        subject.logout();
    }

    @Test
    public void testCustomRealm(){

        CustomRealm customRealm = new CustomRealm();

        HashedCredentialsMatcher hashedCredentialsMatcher = new HashedCredentialsMatcher();
        hashedCredentialsMatcher.setHashAlgorithmName("md5");
        hashedCredentialsMatcher.setHashIterations(1);

        customRealm.setCredentialsMatcher(hashedCredentialsMatcher);

        //1. build securityManager enviorment
        DefaultSecurityManager defaultSecurityManager = new DefaultSecurityManager();
        defaultSecurityManager.setRealm(customRealm);

        //2.subject submit certification
        SecurityUtils.setSecurityManager(defaultSecurityManager);
        Subject subject = SecurityUtils.getSubject();

        UsernamePasswordToken token = new UsernamePasswordToken("mark","123456");
        subject.login(token);

        System.out.println(subject.isAuthenticated());

        subject.checkRole("admin");
        subject.checkPermission("user:delete");

        subject.logout();
    }
}
