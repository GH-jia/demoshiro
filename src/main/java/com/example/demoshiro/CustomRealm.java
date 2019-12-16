package com.example.demoshiro;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.crypto.hash.Md5Hash;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

@Component
public class CustomRealm extends AuthorizingRealm {

    private Map<String,String> map = new HashMap<>();

    {
        map.put("mark","73bea81c6c06bacab41a995495239545");
        super.setName("CustomRealm");
    }

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {

        String username = (String) principalCollection.getPrimaryPrincipal();
        Set<String> roles = getRolesByUsername(username);
        Set<String> permissions = getPermissionsByUsername(username);

        SimpleAuthorizationInfo simpleAuthorizationInfo = new SimpleAuthorizationInfo();
        simpleAuthorizationInfo.addRoles(roles);
        simpleAuthorizationInfo.addStringPermissions(permissions);

        return simpleAuthorizationInfo;
    }

    private Set<String> getPermissionsByUsername(String username) {
        Set<String> permissions = new HashSet<>();
        permissions.add("user:delete");
        return permissions;
    }

    private Set<String> getRolesByUsername(String username) {
        Set<String> roles = new HashSet<>();
        roles.add("admin");
        return roles;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {

        String username = (String) authenticationToken.getPrincipal();
        String password = getPasswordByUsername(username);
        if (password == null){
            return null;
        }
        SimpleAuthenticationInfo simpleAuthenticationInfo = new SimpleAuthenticationInfo(username,password,"CustomRealm");
        simpleAuthenticationInfo.setCredentialsSalt(ByteSource.Util.bytes("mark"));

        return simpleAuthenticationInfo;
    }

    private String getPasswordByUsername(String username) {
        String password = map.get(username);
        return password;
    }

//    public static void main(String[] args) {
//        Md5Hash md5Hash = new Md5Hash("123456","mark");
//        System.out.println(md5Hash.toString());
//    }
}
