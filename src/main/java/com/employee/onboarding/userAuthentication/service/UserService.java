package com.employee.onboarding.userAuthentication.service;

import com.employee.onboarding.userAuthentication.pojoRequest.LoginRequest;
import com.employee.onboarding.userAuthentication.pojoResponse.LoginResponse;

public interface UserService {
	
	public LoginResponse login(LoginRequest request);
}
