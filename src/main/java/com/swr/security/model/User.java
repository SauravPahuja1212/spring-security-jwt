package com.swr.security.model;

import com.swr.security.entity.RoleEntity;
import com.swr.security.entity.UserEntity;
import lombok.*;

import java.util.List;
import java.util.UUID;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class User {

    private UUID userId;
    private String firstName;
    private String lastName;
    private String email;
    private String username;
    private String password;
    private List<Role> userRoles;

    public UserEntity convertToEntity() {
        UserEntity userEntity = new UserEntity();

        userEntity.setFirstName(getFirstName());
        userEntity.setLastName(getLastName());
        userEntity.setEmail(getEmail());
        userEntity.setUsername(getUsername());
        userEntity.setPassword(getPassword());
        userEntity.setUserRoles(getUserRoles().stream().map(role -> role.convertToEntity(userEntity)).toList());

        return userEntity;
    }
}
