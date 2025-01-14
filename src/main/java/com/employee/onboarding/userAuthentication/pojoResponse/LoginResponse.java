package com.employee.onboarding.userAuthentication.pojoResponse;

import com.fasterxml.jackson.annotation.JsonInclude;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class LoginResponse {

	private String token;
	private String message;
	public LoginResponse(String message) {
		super();
		this.message = message;
	}
}
