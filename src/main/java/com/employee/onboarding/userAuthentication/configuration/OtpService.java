package com.employee.onboarding.userAuthentication.configuration;

import java.util.concurrent.ConcurrentHashMap;

import org.springframework.stereotype.Service;

import com.employee.onboarding.userAuthentication.exception.InvalidOtpException;
import com.employee.onboarding.userAuthentication.pojoResponse.OtpEntry;

@Service
public class OtpService {
	
	private final ConcurrentHashMap<String, OtpEntry> storMailOtp = new ConcurrentHashMap<>();
	private final ConcurrentHashMap<Long, OtpEntry> storeOtp = new ConcurrentHashMap<>();
    private final long otpExpiryMillis = 5 * 60 * 1000;
	
//	for email Id
    public void saveOtpForEmail(String email, String otp) {
    	storMailOtp.put(email, new OtpEntry(otp, System.currentTimeMillis()));
    }
    
    public String getOtpForEmail(String email) {
        OtpEntry otpEntry = storMailOtp.get(email);

        if (otpEntry == null || isOtpExpired(otpEntry)) {
        	storMailOtp.remove(email);
            throw new InvalidOtpException("OTP has expired or does not exist.");
        }
        return otpEntry.getOtp();
    }
    
    public void removeOtpForEmail(String email) {
    	storMailOtp.remove(email);
    }
	
//	for user Id
    public void saveOtpForUser(Long userId, String otp) {
        storeOtp.put(userId, new OtpEntry(otp, System.currentTimeMillis()));
    }

    public String getOtpForUser(Long userId) {
        OtpEntry otpEntry = storeOtp.get(userId);

        if (otpEntry == null || isOtpExpired(otpEntry)) {
            storeOtp.remove(userId);
            throw new InvalidOtpException("OTP has expired or does not exist.");
        }
        return otpEntry.getOtp();
    }

    public void removeOtpForUser(Long userId) {
        storeOtp.remove(userId);
    }

    private boolean isOtpExpired(OtpEntry otpEntry) {
        return System.currentTimeMillis() > (otpEntry.getTimestamp() + otpExpiryMillis);
    }
}