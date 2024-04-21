package com.swr.security.entity;

import com.swr.security.constant.DatabaseConstant;
import com.swr.security.model.User;
import jakarta.persistence.*;
import lombok.*;

import java.util.List;
import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity(name = DatabaseConstant.User.TABLE_NAME)
public class UserEntity {

    @Id
    @Column(name = DatabaseConstant.User.COLUMN_USER_ID)
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID userId;

    @Column(name = DatabaseConstant.User.COLUMN_FIRST_NAME, nullable = false)
    private String firstName;

    @Column(name = DatabaseConstant.User.COLUMN_LAST_NAME)
    private String lastName;

    @Column(name = DatabaseConstant.User.COLUMN_EMAIL, nullable = false, unique = true)
    private String email;

    @Column(name = DatabaseConstant.User.COLUMN_USERNAME, nullable = false, unique = true)
    private String username;

    @Column(name = DatabaseConstant.User.COLUMN_PASSWORD, nullable = false)
    private String password;

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, fetch = FetchType.EAGER)
    private List<RoleEntity> userRoles;

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private List<RefreshTokenEntity> refreshTokenEntities;

    public User convertToModel() {
        User user = new User();

        user.setUserId(getUserId());
        user.setFirstName(getFirstName());
        user.setLastName(getLastName());
        user.setEmail(getEmail());
        user.setUsername(getUsername());
        user.setPassword(getPassword());
        user.setUserRoles(getUserRoles().stream().map(RoleEntity::convertToModel).toList());

        return user;
    }
}
