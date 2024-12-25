package com.employee.onboarding.userAuthentication.pojoRequest;

import com.employee.onboarding.userAuthentication.enummeration.Role;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserRequest {
	
	private String userName;
	private String password;
	private String email;
	private Role role;
	private String phoneNumber;
	private String description;
}
