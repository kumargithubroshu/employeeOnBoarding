package com.employee.onboarding.userAuthentication.pojoResponse;

import com.fasterxml.jackson.annotation.JsonInclude;

import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class UserResponse {

	private Long userId;
    private String userName;
    private String email;
    private String phoneNumber;
    private String role;
    private String status;
    
//    @JsonIgnore
    private String message;

    public UserResponse(String message) {
        this.message = message;
    }
    
    public UserResponse(Long userId, String userName, String email, String phoneNumber, String role, String status) {
        this.userId = userId;
        this.userName = userName;
        this.email = email;
        this.phoneNumber = phoneNumber;
        this.role = role;
        this.status = status;
    }
}
