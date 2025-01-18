package com.employee.onboarding.userAuthentication.exception;

public class InactiveUserException extends RuntimeException{
	
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public InactiveUserException(String message)
	{
		super(message);
	}

}
