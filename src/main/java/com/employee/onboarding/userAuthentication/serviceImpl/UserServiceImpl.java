package com.employee.onboarding.userAuthentication.serviceImpl;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.employee.onboarding.userAuthentication.configuration.EmailService;
import com.employee.onboarding.userAuthentication.configuration.JwtUtils;
import com.employee.onboarding.userAuthentication.configuration.OtpService;
import com.employee.onboarding.userAuthentication.entity.User;
import com.employee.onboarding.userAuthentication.enummeration.Role;
import com.employee.onboarding.userAuthentication.enummeration.Status;
import com.employee.onboarding.userAuthentication.exception.EmailAlreadyInUseException;
import com.employee.onboarding.userAuthentication.exception.InvalidOtpException;
import com.employee.onboarding.userAuthentication.exception.InvalidPasswordException;
import com.employee.onboarding.userAuthentication.exception.UserNotFoundException;
import com.employee.onboarding.userAuthentication.pojoRequest.ChangePasswordRequest;
import com.employee.onboarding.userAuthentication.pojoRequest.LoginRequest;
import com.employee.onboarding.userAuthentication.pojoRequest.SearchAndListUserRequest;
import com.employee.onboarding.userAuthentication.pojoRequest.UserRequest;
import com.employee.onboarding.userAuthentication.pojoRequest.UserUpdateRequest;
import com.employee.onboarding.userAuthentication.pojoResponse.LoginResponse;
import com.employee.onboarding.userAuthentication.pojoResponse.UserResponse;
import com.employee.onboarding.userAuthentication.repository.UserRepo;
import com.employee.onboarding.userAuthentication.service.UserService;

import jakarta.persistence.criteria.Predicate;

@Service
public class UserServiceImpl implements UserService {

	@Autowired
	private JwtUtils jwtUtils;

	@Autowired
	private UserRepo userRepo;

	@Autowired
	private OtpService otpService;

	@Autowired
	private EmailService emailService;

	@Autowired
	private PasswordEncoder passwordEncoder;

	@Autowired
	private AuthenticationManager authenticationManager;

	@Override
	public User rgisterNewUser(UserRequest request) throws Exception {
		User byEmail = userRepo.findByEmail(request.getEmail());
		if (byEmail != null) {
			throw new EmailAlreadyInUseException("Email already in use." + request.getEmail());
		}
		User user = new User();
		user.setUserName(request.getUserName());
		user.setPassword(passwordEncoder.encode(request.getPassword()));
		user.setEmail(request.getEmail());
		user.setPhoneNumber(request.getPhoneNumber());
		user.setCreatedAt(LocalDateTime.now());
		user.setStatus(Status.INACTIVE.toString());
		user.setDescription(request.getDescription());

		User savedUser = userRepo.save(user);

		String otp = generateOtp();
		otpService.saveOtpForUser(savedUser.getUserId(), otp);

		emailService.sendEmail(savedUser.getEmail(), "OTP Verification",
				"Your OTP is: " + otp + " and user id is: " + savedUser.getUserId());
		return savedUser;
	}

	private String generateOtp() {
		return String.valueOf((int) ((Math.random() * 900000) + 100000)); // 6-digit OTP
	}

	@Override
	public void verifyOtp(Long userId, String otp) {

		String savedOtp = otpService.getOtpForUser(userId);
		if (!otp.equals(savedOtp)) {
			throw new InvalidOtpException("Invalid OTP provided.");
		}
		User user = userRepo.findById(userId)
				.orElseThrow(() -> new IllegalArgumentException("User not found with ID: " + userId));

		user.setStatus(Status.ACTIVE.toString());
		user.setUpdatedAt(LocalDateTime.now());
		userRepo.save(user);

		otpService.removeOtpForUser(userId);
	}

	@Override
	public void resendOtp(String email) throws Exception {
		User user = userRepo.findByEmail(email);
		if (user == null) {
			throw new UserNotFoundException("No user found with the provided email.");
		}
		if (!Status.INACTIVE.toString().equals(user.getStatus())) {
			throw new IllegalStateException("User is already verified and active.");
		}

		String otp = generateOtp();
		otpService.saveOtpForUser(user.getUserId(), otp);

		emailService.sendEmail(user.getEmail(), "Resend OTP Verification", "Your new OTP is: " + otp
				+ " and userId is: " + user.getUserId() + ".  Please verify within 5 minutes.");
	}

	@Override
	public void assignRoleToUser(String email, Role role) throws Exception {
		User user = userRepo.findByEmail(email);
		if (user == null) {
			throw new UserNotFoundException("User not found with the provided email: " + email);
		}

		user.setRole(role.toString());
		user.setUpdatedAt(LocalDateTime.now());
		userRepo.save(user);
	}

	@Override
	public LoginResponse login(LoginRequest request) {
		User user = userRepo.findByEmail(request.getEmail());

		if (user == null) {
			return new LoginResponse("User not found with the provided email!");
		}

		if (!"ACTIVE".equalsIgnoreCase(user.getStatus())) {
			return new LoginResponse("Login not allowed. User status is not active!");
		}

		try {
			UsernamePasswordAuthenticationToken authInputToken = new UsernamePasswordAuthenticationToken(
					request.getEmail(), request.getPassword());

			authenticationManager.authenticate(authInputToken);

			String token = jwtUtils.generateToken(request.getEmail());
			return new LoginResponse(token, "Login Successful!");
		} catch (BadCredentialsException e) {
			return new LoginResponse("Incorrect password!");
		}
	}

	@Override
	public void sendPasswordByEmail(String email) throws Exception {
		User user = userRepo.findByEmail(email);
		if (user == null) {
			throw new UserNotFoundException("No user found with the provided email.");
		}
		String temporaryPassword = generateTemporaryPassword();
		user.setPassword(temporaryPassword);
		userRepo.save(user);
		emailService.sendEmail(user.getEmail(), "Temporary Password",
				"Your temporary password is: " + temporaryPassword);
	}

	private String generateTemporaryPassword() {
		return UUID.randomUUID().toString().substring(0, 8); // 8-character random password
	}

	@Override
	public void changePassword(ChangePasswordRequest request) throws Exception {
		if (!request.getNewPassword().equals(request.getConfirmPassword())) {
			throw new InvalidPasswordException("New password and confirm password do not match.");
		}
		User user = userRepo.findByEmail(request.getEmail());
		if (user == null) {
			throw new UserNotFoundException("User not found");
		}
		if (!user.getPassword().equals(request.getCurrentPassword())) {
			throw new InvalidPasswordException("Temporary password is incorrect.");
		}
		user.setPassword(passwordEncoder.encode(request.getNewPassword()));
		userRepo.save(user);
	}

	@Override
	public void updateUserDetailsByEmail(String emailId, UserUpdateRequest updateRequest) {
		User user = userRepo.findByEmail(emailId);
		if (user == null) {
			throw new UserNotFoundException("User not found");
		}

		if (updateRequest.getName() != null) {
			user.setUserName(updateRequest.getName());
		}
		if (updateRequest.getRole() != null) {
			user.setRole(updateRequest.getRole().toString());
		}
		if (updateRequest.getPhoneNumber() != null) {
			user.setPhoneNumber(updateRequest.getPhoneNumber());
		}
		if (updateRequest.getDescription() != null) {
			user.setDescription(updateRequest.getDescription());
		}

		userRepo.save(user);
	}

	@Override
	public UserResponse getUserByEmail(String email) throws UserNotFoundException {
		User user = userRepo.findByEmail(email);
		if (user == null) {
			throw new UserNotFoundException("User not found with email: " + email);
		}
		return new UserResponse(user.getUserId(), user.getUserName(), user.getEmail(), user.getPhoneNumber(),
				user.getRole(), user.getStatus());
	}

	@Override
	public UserResponse getUserById(Long userId) throws UserNotFoundException {
		Optional<User> byId = userRepo.findById(userId);
		if (!byId.isPresent()) {
			throw new UserNotFoundException("User not found with ID: " + userId);
		}
		User user = byId.get();
		return new UserResponse(user.getUserId(), user.getUserName(), user.getEmail(), user.getPhoneNumber(),
				user.getRole(), user.getStatus());
	}

	@Override
	public List<UserResponse> getUsersByAttribute(SearchAndListUserRequest request) {
		Specification<User> roleSpec = filterAttributes(request);
		List<User> users = userRepo.findAll(roleSpec);

		return users.stream().map(user -> new UserResponse(user.getUserId(), user.getUserName(), user.getEmail(),
				user.getPhoneNumber(), user.getRole(), user.getStatus())).toList();
	}

	public static Specification<User> filterAttributes(SearchAndListUserRequest request) {
		return (root, query, criteriaBuilder) -> {
			List<Predicate> predicates = new ArrayList<>();

			if (request != null && request.getFilterRole() != null) {
				predicates.add(criteriaBuilder.equal(root.get("role"), request.getFilterRole().name()));
			}

			if (request != null && request.getFilterUserName() != null && !request.getFilterUserName().isEmpty()) {
				predicates.add(criteriaBuilder.like(criteriaBuilder.lower(root.get("userName")),
						"%" + request.getFilterUserName().toLowerCase() + "%"));
			}

			if (request != null && request.getFilterPhoneNumber() != null
					&& !request.getFilterPhoneNumber().isEmpty()) {
				predicates.add(criteriaBuilder.equal(root.get("phoneNumber"), request.getFilterPhoneNumber()));
			}

			if (request != null && request.getFilterStatus() != null) {
				predicates.add(criteriaBuilder.equal(root.get("status"), request.getFilterStatus().name()));
			}

			return criteriaBuilder.and(predicates.toArray(new Predicate[0]));
		};
	}

	@Override
	public List<UserResponse> getAllUsers() {
		List<User> users = userRepo.findAll();
		return users.stream().map(user -> new UserResponse(user.getUserId(), user.getUserName(), user.getEmail(),
				user.getPhoneNumber(), user.getRole(), user.getStatus())).toList();
	}
}