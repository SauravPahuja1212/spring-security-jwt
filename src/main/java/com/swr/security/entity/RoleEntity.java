package com.swr.security.entity;

import com.swr.security.constant.DatabaseConstant;
import com.swr.security.model.Role;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.UUID;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity(name = DatabaseConstant.Role.TABLE_NAME)
public class RoleEntity {

    @Id
    @Column(name = DatabaseConstant.Role.COLUMN_ROLE_ID)
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID roleId;

    @Column(name = DatabaseConstant.Role.COLUMN_ROLE_NAME)
    private String roleName;

    @Column(name = DatabaseConstant.Role.COLUMN_ROLE_TYPE)
    private Integer roleType;

    @JoinColumn(name = DatabaseConstant.User.COLUMN_USER_ID, referencedColumnName = DatabaseConstant.User.COLUMN_USER_ID
            , foreignKey = @ForeignKey(name = "FK_USER_INFO_USER_ID"))
    @ManyToOne(fetch = FetchType.EAGER)
    private UserEntity user;

    public Role convertToModel() {
        Role role = new Role();

        role.setRoleId(getRoleId());
        role.setRoleName(getRoleName());
        role.setRoleType(getRoleType());

        return role;
    }
}
