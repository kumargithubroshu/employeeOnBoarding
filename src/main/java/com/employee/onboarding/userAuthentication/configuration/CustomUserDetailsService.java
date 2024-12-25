package com.employee.onboarding.userAuthentication.configuration;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.employee.onboarding.userAuthentication.entity.User;
import com.employee.onboarding.userAuthentication.repository.UserRepo;

@Service
public class CustomUserDetailsService implements UserDetailsService{
	
	@Autowired
	private UserRepo userRepo;
	
	@Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        User user = userRepo.findByEmail(email);
        
        if (user == null) {
            throw new UsernameNotFoundException("User not found with email: " + email);
        }

        return new org.springframework.security.core.userdetails.User(user.getEmail(), user.getPassword(),
                Arrays.asList(new SimpleGrantedAuthority(user.getRole().toString())));
    }
}