package com.employee.onboarding.userAuthentication.controller;

import java.util.Collections;
import java.util.List;

import org.springdoc.core.annotations.ParameterObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.employee.onboarding.userAuthentication.configuration.JwtUtils;
import com.employee.onboarding.userAuthentication.enummeration.Role;
import com.employee.onboarding.userAuthentication.exception.EmailAlreadyInUseException;
import com.employee.onboarding.userAuthentication.exception.InvalidOtpException;
import com.employee.onboarding.userAuthentication.exception.UserNotFoundException;
import com.employee.onboarding.userAuthentication.exception.UsernameMismatchException;
import com.employee.onboarding.userAuthentication.pojoRequest.ChangePasswordRequest;
import com.employee.onboarding.userAuthentication.pojoRequest.LoginRequest;
import com.employee.onboarding.userAuthentication.pojoRequest.SearchAndListUserRequest;
import com.employee.onboarding.userAuthentication.pojoRequest.TokenRequest;
import com.employee.onboarding.userAuthentication.pojoRequest.UserRequest;
import com.employee.onboarding.userAuthentication.pojoRequest.UserUpdateRequest;
import com.employee.onboarding.userAuthentication.pojoResponse.LoginResponse;
import com.employee.onboarding.userAuthentication.pojoResponse.Message;
import com.employee.onboarding.userAuthentication.pojoResponse.UserResponse;
import com.employee.onboarding.userAuthentication.service.UserService;

import io.swagger.v3.oas.annotations.Operation;

@RestController
@RequestMapping("/api/users")
public class UserController {

	@Autowired
	private JwtUtils jwtUtils;

	@Autowired
	private UserService userService;

	@Operation(summary = "Generate a JWT token")
	@PostMapping("/generate-token")
	public ResponseEntity<Message> generateToken(@ParameterObject TokenRequest tokenRequest) {
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

	@Operation(summary = "Register a new user")
	@PostMapping("/register")
	public ResponseEntity<Message> registerNewUser(@ParameterObject UserRequest request) {
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

	@Operation(summary = "Verify OTP")
	@PostMapping("/verify-otp")
	public ResponseEntity<Message> verifyOtp(@RequestParam Long userId, @RequestParam String otp) {
		try {
			userService.verifyOtp(userId, otp);
			return ResponseEntity.ok(new Message("User verified successfully !"));
		} catch (InvalidOtpException e) {
			return ResponseEntity.badRequest().body(new Message(e.getMessage()));
		}
	}

	@Operation(summary = "Resend OTP")
	@PostMapping("/resend-otp")
	public ResponseEntity<Message> resendOtp(@RequestParam String email) {
		try {
			userService.resendOtp(email);
			return ResponseEntity.ok(new Message("OTP has been resent successfully to your registered email."));
		} catch (UserNotFoundException e) {
			return ResponseEntity.status(HttpStatus.NOT_FOUND)
					.body(new Message("No user found with the provided email."));
		} catch (Exception e) {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
					.body(new Message("Failed to resend OTP. Please try again later."));
		}
	}

	@Operation(summary = "Assign a role to a user")
	@PutMapping("/assign-role")
	public ResponseEntity<Message> assignRoleToUser(@RequestParam String email, @RequestParam Role role) {
		try {
			userService.assignRoleToUser(email, role);
			return ResponseEntity.ok(new Message("Role assigned successfully."));
		} catch (UserNotFoundException e) {
			return ResponseEntity.status(HttpStatus.NOT_FOUND)
					.body(new Message("User not found with the provided email."));
		} catch (Exception e) {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
					.body(new Message("Failed to assign role. Please try again later."));
		}
	}

	@Operation(summary = "User Login")
	@PostMapping("/login")
	public ResponseEntity<LoginResponse> login(@ParameterObject LoginRequest request) {
		try {
			LoginResponse response = userService.login(request);
			return ResponseEntity.ok(response);
		} catch (BadCredentialsException e) {
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new LoginResponse("Invalid email or password!"));
		} catch (IllegalStateException e) {
			return ResponseEntity.status(HttpStatus.FORBIDDEN).body(new LoginResponse(e.getMessage()));
		} catch (Exception e) {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
					.body(new LoginResponse("Unexpected error occurred!"));
		}
	}

	@Operation(summary = "Request a temporary password")
	@PostMapping("/forgot-password")
	public ResponseEntity<Message> forgotPassword(@RequestParam String email) {
		try {
			userService.sendPasswordByEmail(email);
			return ResponseEntity.ok(new Message("Your temporary password has been sent to your registered email."));
		} catch (UserNotFoundException e) {
			return ResponseEntity.status(HttpStatus.NOT_FOUND)
					.body(new Message("No user found with the provided email address."));
		} catch (Exception e) {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
					.body(new Message("Failed to retrieve password. Please try again later."));
		}
	}

	@Operation(summary = "Change password")
	@PostMapping("/change-password")
	public ResponseEntity<Message> changePassword(@ParameterObject ChangePasswordRequest request) {
		try {
			userService.changePassword(request);
			return ResponseEntity.ok(new Message("Password updated successfully."));
		} catch (Exception e) {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
					.body(new Message("Failed to update password. Please try again later."));
		}
	}

	@Operation(summary = "Update user details based on email")
	@PutMapping("/update")
	public ResponseEntity<Message> updateUserDetails(@RequestParam String emailId,
			@ParameterObject UserUpdateRequest updateRequest) {
		try {
			userService.updateUserDetailsByEmail(emailId, updateRequest);
			return ResponseEntity.ok(new Message("User details updated successfully."));
		} catch (UserNotFoundException e) {
			return ResponseEntity.status(HttpStatus.NOT_FOUND)
					.body(new Message("User not found with the provided email ID."));
		} catch (Exception e) {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
					.body(new Message("Failed to update user details. Please try again later."));
		}
	}

	@Operation(summary = "Get user details by email ID")
	@GetMapping("/by-email")
	public ResponseEntity<UserResponse> getUserByEmail(@RequestParam String email) {
		try {
			UserResponse user = userService.getUserByEmail(email);
			return ResponseEntity.ok(user);
		} catch (UserNotFoundException e) {
			return ResponseEntity.status(HttpStatus.NOT_FOUND)
					.body(new UserResponse("User not found with email: " + email));
		}
	}

	@Operation(summary = "Get user details by userId")
	@GetMapping("/{userId}")
	public ResponseEntity<UserResponse> getUserById(@PathVariable Long userId) {
		try {
			UserResponse userResponse = userService.getUserById(userId);
			return ResponseEntity.ok(userResponse);
		} catch (UserNotFoundException e) {
			return ResponseEntity.status(HttpStatus.NOT_FOUND)
					.body(new UserResponse("User not found with ID: " + userId));
		}
	}

	@Operation(summary = "Get all users details by their attributes")
	@GetMapping("/byAttributes")
	public ResponseEntity<List<UserResponse>> getUsersByAttributes(@ParameterObject SearchAndListUserRequest request) {
		try {
			List<UserResponse> users = userService.getUsersByAttribute(request);
			if (users.size() == 1 && users.get(0).getMessage() != null) {
				return ResponseEntity.status(HttpStatus.NOT_FOUND).body(users);
			}
			return ResponseEntity.ok(users);
		} catch (Exception e) {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
					.body(Collections.singletonList(new UserResponse("Failed to fetch user details.")));
		}
	}

	@Operation(summary = "Get all users")
	@GetMapping("/all")
	public ResponseEntity<List<UserResponse>> getAllUsers() {
		try {
			List<UserResponse> users = userService.getAllUsers();
			return ResponseEntity.ok(users);
		} catch (Exception e) {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
					.body(Collections.singletonList(new UserResponse("Failed to fetch user details.")));
		}
	}

	@Operation(summary = "Delete a user by userId")
	@DeleteMapping("/{userId}")
	public ResponseEntity<Message> deleteUserById(@PathVariable Long userId) {
		try {
			userService.deleteUserById(userId);
			return ResponseEntity.ok(new Message("User deleted successfully."));
		} catch (UserNotFoundException e) {
			return ResponseEntity.status(HttpStatus.NOT_FOUND).body(new Message("User not found with ID: " + userId));
		} catch (Exception e) {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
					.body(new Message("Failed to delete user. Please try again later."));
		}
	}

	@Operation(summary = "Delete a user by email")
	@DeleteMapping("/by-email")
	public ResponseEntity<Message> deleteUserByEmail(@RequestParam String email) {
	    try {
	        userService.deleteUserByEmail(email);
	        return ResponseEntity.ok(new Message("User deleted successfully."));
	    } catch (UserNotFoundException e) {
	        return ResponseEntity.status(HttpStatus.NOT_FOUND)
	                .body(new Message("User not found with email: " + email));
	    } catch (Exception e) {
	        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
	                .body(new Message("Failed to delete user. Please try again later."));
	    }
	}
}