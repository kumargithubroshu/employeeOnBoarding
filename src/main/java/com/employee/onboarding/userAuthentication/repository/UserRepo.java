package com.employee.onboarding.userAuthentication.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;

import com.employee.onboarding.userAuthentication.entity.User;

public interface UserRepo extends JpaRepository<User, Long>, JpaSpecificationExecutor<User>{
	
	@Query("SELECT u FROM User u WHERE u.email = :email")
    User findByEmail(String email);
}
