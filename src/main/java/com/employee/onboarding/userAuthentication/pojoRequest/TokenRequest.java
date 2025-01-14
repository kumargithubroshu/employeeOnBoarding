package com.employee.onboarding.userAuthentication.pojoRequest;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class TokenRequest {
	
	@Schema(defaultValue = "randstad")
	private String username;

}
