package com.employee.onboarding.userAuthentication.serviceImpl;

import java.time.LocalDateTime;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.employee.onboarding.userAuthentication.configuration.EmailService;
import com.employee.onboarding.userAuthentication.configuration.JwtUtils;
import com.employee.onboarding.userAuthentication.configuration.OtpService;
import com.employee.onboarding.userAuthentication.entity.User;
import com.employee.onboarding.userAuthentication.enummeration.Status;
import com.employee.onboarding.userAuthentication.exception.EmailAlreadyInUseException;
import com.employee.onboarding.userAuthentication.exception.InvalidOtpException;
import com.employee.onboarding.userAuthentication.exception.UserNotFoundException;
import com.employee.onboarding.userAuthentication.pojoRequest.LoginRequest;
import com.employee.onboarding.userAuthentication.pojoRequest.UserRequest;
import com.employee.onboarding.userAuthentication.pojoResponse.LoginResponse;
import com.employee.onboarding.userAuthentication.repository.UserRepo;
import com.employee.onboarding.userAuthentication.service.UserService;

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

//	@Autowired
//	private PasswordEncoder passwordEncoder;

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
		user.setPassword(request.getPassword());
		user.setEmail(request.getEmail());
		user.setRole(request.getRole().toString());
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
	public LoginResponse login(LoginRequest request) {
		UsernamePasswordAuthenticationToken authInputToken = new UsernamePasswordAuthenticationToken(request.getEmail(),
				request.getPassword());

		authenticationManager.authenticate(authInputToken);
		String token = jwtUtils.generateToken(request.getEmail());

		return new LoginResponse(token, "Login Successful !");
	}

	@Override
	public void sendPasswordByEmail(String email) throws Exception {
		User user = userRepo.findByEmail(email);
		if (user == null) {
			throw new UserNotFoundException("No user found with the provided email.");
		}
		emailService.sendEmail(user.getEmail(), "Your Password", "Your password is: " + user.getPassword());
	}
}