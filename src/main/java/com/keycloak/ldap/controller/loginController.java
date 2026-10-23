package com.keycloak.ldap.controller;

import com.keycloak.ldap.dto.UserLogin;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(path = "/api/keycloak")
public class loginController {

    public void login(@RequestBody UserLogin userLogin) {

    }

}
