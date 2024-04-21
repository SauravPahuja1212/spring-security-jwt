package com.swr.security.model;

import com.swr.security.entity.RoleEntity;
import com.swr.security.entity.UserEntity;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.UUID;

@Data
@NoArgsConstructor
@AllArgsConstructor

public class Role {

    private UUID roleId;
    private String roleName;
    private Integer roleType;

    public RoleEntity convertToEntity(UserEntity user) {
        RoleEntity roleEntity = new RoleEntity();

        roleEntity.setRoleName(getRoleName());
        roleEntity.setRoleType(getRoleType());
        roleEntity.setUser(user);

        return roleEntity;
    }
}
