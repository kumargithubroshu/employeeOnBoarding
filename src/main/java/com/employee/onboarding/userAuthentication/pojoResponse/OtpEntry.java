package com.employee.onboarding.userAuthentication.pojoResponse;

import lombok.Data;
import lombok.Getter;
import lombok.Setter;

@Data
@Getter
@Setter
public class OtpEntry {

	private final String otp;
    private final long timestamp;
}
