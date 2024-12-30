package com.employee.onboarding.userAuthentication.service;

import com.employee.onboarding.userAuthentication.entity.User;
import com.employee.onboarding.userAuthentication.enummeration.Role;
import com.employee.onboarding.userAuthentication.pojoRequest.ChangePasswordRequest;
import com.employee.onboarding.userAuthentication.pojoRequest.LoginRequest;
import com.employee.onboarding.userAuthentication.pojoRequest.UserRequest;
import com.employee.onboarding.userAuthentication.pojoRequest.UserUpdateRequest;
import com.employee.onboarding.userAuthentication.pojoResponse.LoginResponse;

public interface UserService {
	
	public LoginResponse login(LoginRequest request);
	
	public User rgisterNewUser(UserRequest request) throws Exception;
	
	public void verifyOtp(Long userId, String otp);
	
	public void resendOtp(String email) throws Exception;
	
	public void assignRoleToUser(String email, Role role) throws Exception;
	
	public void sendPasswordByEmail(String email) throws Exception;
	
	public void changePassword(ChangePasswordRequest request) throws Exception;
	
	public void updateUserDetailsByEmail(String emailId, UserUpdateRequest updateRequest);
	
}
