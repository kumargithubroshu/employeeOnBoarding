package com.employee.onboarding.userAuthentication.exception;

public class UsernameMismatchException extends RuntimeException{

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	
	public UsernameMismatchException(String message) {
        super(message);
    }
}
