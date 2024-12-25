package com.employee.onboarding.userAuthentication.service;

import com.employee.onboarding.userAuthentication.entity.User;
import com.employee.onboarding.userAuthentication.pojoRequest.LoginRequest;
import com.employee.onboarding.userAuthentication.pojoRequest.UserRequest;
import com.employee.onboarding.userAuthentication.pojoResponse.LoginResponse;

public interface UserService {
	
	public LoginResponse login(LoginRequest request);
	
	public User rgisterNewUser(UserRequest request) throws Exception;
	
	public void verifyOtp(Long userId, String otp);
	
	public void sendPasswordByEmail(String email) throws Exception;
}
