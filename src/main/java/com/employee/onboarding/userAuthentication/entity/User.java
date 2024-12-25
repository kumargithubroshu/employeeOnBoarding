package com.employee.onboarding.userAuthentication.entity;

import java.time.LocalDateTime;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "user")
@Data
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class User {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "id")
	private long userId;

	@Column(name = "name")
	@NotBlank
	private String userName;

	@Column(name = "password")
	@NotBlank
	private String password;

	@Column(name = "email")
//	@Email(regexp = "^[a-zA-Z0-9._%+-]+@gmail\\.com$", message = "Email must be a valid Gmail address")
	@Email
	@NotBlank
	private String email;

	@Column(name = "role")
	private String role;

	@Column(name = "created_at")
	private LocalDateTime createdAt;

	@Column(name = "updated_at")
	private LocalDateTime updatedAt;

	@Column(name = "phone_number")
	@NotBlank
	private String phoneNumber;

	@Column(name = "status")
	private String status;

	@Column(name = "role_description")
	private String description;

}