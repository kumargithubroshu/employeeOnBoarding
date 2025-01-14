package com.employee.onboarding.userAuthentication.pojoRequest;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ChangePasswordRequest {
	
	private String email;
	private String temporaryPassword;
    private String newPassword;
    private String confirmPassword;
}
