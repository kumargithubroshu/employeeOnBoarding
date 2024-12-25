package com.employee.onboarding.userAuthentication.configuration;

import java.util.concurrent.ConcurrentHashMap;

import org.springframework.stereotype.Service;

import com.employee.onboarding.userAuthentication.exception.InvalidOtpException;
import com.employee.onboarding.userAuthentication.pojoResponse.OtpEntry;

@Service
public class OtpService {
	
	private final ConcurrentHashMap<Long, OtpEntry> storeOtp = new ConcurrentHashMap<>();
    private final long otpExpiryMillis = 5 * 60 * 1000;

    public void saveOtpForUser(Long userId, String otp) {
        storeOtp.put(userId, new OtpEntry(otp, System.currentTimeMillis()));
    }

    public String getOtpForUser(Long userId) {
        OtpEntry otpEntry = storeOtp.get(userId);

        if (otpEntry == null || isOtpExpired(otpEntry)) {
            storeOtp.remove(userId); // Remove expired OTP
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