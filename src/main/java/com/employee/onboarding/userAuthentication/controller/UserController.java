package com.employee.onboarding.userAuthentication.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.employee.onboarding.userAuthentication.configuration.JwtUtils;
import com.employee.onboarding.userAuthentication.exception.UsernameMismatchException;
import com.employee.onboarding.userAuthentication.pojoRequest.TokenRequest;

@RestController
@RequestMapping("/api/users")
public class UserController {
	
	@Autowired
    private JwtUtils jwtUtils;

	@PostMapping("/generate-token")
    public ResponseEntity<String> generateToken(@RequestBody TokenRequest tokenRequest) {
		try {
        if (tokenRequest.getUsername() == null || tokenRequest.getUsername().isBlank()) {
            throw new IllegalArgumentException("Username cannot be empty or null");
        }
        if(!"randstad".equals(tokenRequest.getUsername()))
        {
        	throw new UsernameMismatchException("User not found: " + tokenRequest.getUsername());
        }
        String token = jwtUtils.generateToken(tokenRequest.getUsername());
        return ResponseEntity.ok(token);
		}catch (Exception e) {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("An unexpected error occurred");
		}
    }
}