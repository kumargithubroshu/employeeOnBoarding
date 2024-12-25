package com.employee.onboarding.userAuthentication.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.employee.onboarding.userAuthentication.configuration.JwtUtils;
import com.employee.onboarding.userAuthentication.exception.EmailAlreadyInUseException;
import com.employee.onboarding.userAuthentication.exception.InvalidOtpException;
import com.employee.onboarding.userAuthentication.exception.UsernameMismatchException;
import com.employee.onboarding.userAuthentication.pojoRequest.LoginRequest;
import com.employee.onboarding.userAuthentication.pojoRequest.TokenRequest;
import com.employee.onboarding.userAuthentication.pojoRequest.UserRequest;
import com.employee.onboarding.userAuthentication.pojoResponse.LoginResponse;
import com.employee.onboarding.userAuthentication.pojoResponse.Message;
import com.employee.onboarding.userAuthentication.service.UserService;

import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/users")
public class UserController {

	@Autowired
	private JwtUtils jwtUtils;

	@Autowired
	private UserService userService;

	@PostMapping("/generate-token")
	public ResponseEntity<Message> generateToken(@RequestBody TokenRequest tokenRequest) {
		try {
			if (tokenRequest.getUsername() == null || tokenRequest.getUsername().isBlank()) {
				throw new IllegalArgumentException("Username cannot be empty or null");
			}
			if (!"randstad".equals(tokenRequest.getUsername())) {
				throw new UsernameMismatchException("User not found: " + tokenRequest.getUsername());
			}
			String token = jwtUtils.generateToken(tokenRequest.getUsername());
			return ResponseEntity.ok(new Message(token));
		} catch (Exception e) {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
					.body(new Message("An unexpected error occurred"));
		}
	}

	@PostMapping("/register")
	public ResponseEntity<Message> registerNewUser(@RequestBody UserRequest request) {
		try {
			userService.rgisterNewUser(request);
			return ResponseEntity.ok(new Message("User registered successfully. Check your email for OTP."));
		} catch (EmailAlreadyInUseException e) {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST)
					.body(new Message("This email is already in use. Please try again"));
		} catch (Exception e) {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
					.body(new Message("Registration failed. Please try again."));
		}
	}
	
	@PostMapping("/verify-otp")
    public ResponseEntity<Message> verifyOtp(@RequestParam Long userId, @RequestParam String otp) {
        try {
            userService.verifyOtp(userId, otp);
            return ResponseEntity.ok(new Message("User verified successfully and status set to ACTIVE."));
        } catch (InvalidOtpException e) {
            return ResponseEntity.badRequest().body(new Message(e.getMessage()));
        }
    }

	@PostMapping("/login")
	public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest request) {
		try {
			LoginResponse response = userService.login(request);
			return ResponseEntity.ok(response);
		} catch (Exception e) {
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(null);
		}
	}
}