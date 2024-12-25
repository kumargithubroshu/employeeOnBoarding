package com.employee.onboarding.userAuthentication.serviceImpl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Service;

import com.employee.onboarding.userAuthentication.configuration.JwtUtils;
import com.employee.onboarding.userAuthentication.pojoRequest.LoginRequest;
import com.employee.onboarding.userAuthentication.pojoResponse.LoginResponse;
import com.employee.onboarding.userAuthentication.service.UserService;

@Service
public class UserServiceImpl implements UserService{

	@Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Override
    public LoginResponse login(LoginRequest request) {
        UsernamePasswordAuthenticationToken authInputToken =
                new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword());

        authenticationManager.authenticate(authInputToken);
        String token = jwtUtils.generateToken(request.getEmail());

        return new LoginResponse(token, "Login Successful !");
    }
}
