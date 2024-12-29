package com.employee.onboarding.userAuthentication;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.info.Info;

@SpringBootApplication
@OpenAPIDefinition(
	    info = @Info(
	        title = "User Management API",
	        version = "1.0.0",
	        description = "This API handles user registration, authentication, and related operations for the onboarding process."
	    )
	)
public class UserAuthenticationApplication {

	public static void main(String[] args) {
		SpringApplication.run(UserAuthenticationApplication.class, args);
	}
}

//http://localhost:8080/swagger-ui/index.html