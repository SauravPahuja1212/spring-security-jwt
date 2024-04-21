package com.swr.security.dto;

import com.swr.security.constant.RoleConstant;
import com.swr.security.entity.RoleEntity;
import com.swr.security.entity.UserEntity;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserRegistrationDTO {

    private String username;
    private String password;
    private String email;
    private String firstName;
    private String lastName;
    private String role;

    public UserEntity convertToEntity() {
        var userRoles = new ArrayList<RoleEntity>(3);

        var userEntity = UserEntity.builder()
                .email(email)
                .firstName(firstName)
                .lastName(lastName)
                .username(username)
                .password(password)
                .userRoles(userRoles)
                .build();

        if(role.equals(RoleConstant.ROLE_NAME_USER)) {
            userRoles.add(RoleEntity.builder()
                    .roleName(RoleConstant.ROLE_NAME_USER)
                    .roleType(RoleConstant.ROLE_TYPE_USER)
                    .user(userEntity)
                    .build());
        }

        if(role.equals(RoleConstant.ROLE_NAME_MANAGER)) {
            userRoles.add(RoleEntity.builder()
                    .roleName(RoleConstant.ROLE_NAME_USER)
                    .roleType(RoleConstant.ROLE_TYPE_USER)
                    .user(userEntity)
                    .build());

            userRoles.add(RoleEntity.builder()
                    .roleName(RoleConstant.ROLE_NAME_MANAGER)
                    .roleType(RoleConstant.ROLE_TYPE_MANAGER)
                    .user(userEntity)
                    .build());
        }

        if(role.equals(RoleConstant.ROLE_NAME_ADMIN)) {
            userRoles.add(RoleEntity.builder()
                    .roleName(RoleConstant.ROLE_NAME_USER)
                    .roleType(RoleConstant.ROLE_TYPE_USER)
                    .user(userEntity)
                    .build());

            userRoles.add(RoleEntity.builder()
                    .roleName(RoleConstant.ROLE_NAME_ADMIN)
                    .roleType(RoleConstant.ROLE_TYPE_ADMIN)
                    .user(userEntity)
                    .build());
        }

        userEntity.setUserRoles(userRoles);
        return userEntity;
    }
}
