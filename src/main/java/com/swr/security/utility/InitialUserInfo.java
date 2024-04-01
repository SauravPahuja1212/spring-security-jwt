package com.swr.security.utility;

import com.swr.security.constant.RoleConstant;
import com.swr.security.model.Role;
import com.swr.security.model.User;
import com.swr.security.repository.UserInfoJpaRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Component
@RequiredArgsConstructor
@Transactional
public class InitialUserInfo implements CommandLineRunner {

    private final UserInfoJpaRepository userInfoJpaRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) {

        var user = userInfoJpaRepository.findByUsernameOrEmail("User", "user@swr.com");
        if(user.isEmpty()) {
            createUser();
        }

        var admin = userInfoJpaRepository.findByUsernameOrEmail("Admin", "admin@swr.com");
        if(admin.isEmpty()) {
            createAdmin();
        }

        var manager = userInfoJpaRepository.findByUsernameOrEmail("Manager", "manager@swr.com");
        if(manager.isEmpty()) {
            createManager();
        }
    }

    private void createUser() {
        User user = new User();
        user.setFirstName("User");
        user.setLastName("Pahuja");
        user.setUsername("User");
        user.setPassword(passwordEncoder.encode("user"));
        user.setEmail("user@swr.com");

        Role role = new Role();
        role.setRoleName("ROLE_USER");
        role.setRoleType(RoleConstant.ROLE_USER);

        user.setUserRoles(List.of(role));
        userInfoJpaRepository.save(user.convertToEntity());
    }

    private void createAdmin() {
        User user = new User();
        user.setFirstName("Admin");
        user.setLastName("Pahuja");
        user.setUsername("Admin");
        user.setPassword(passwordEncoder.encode("admin"));
        user.setEmail("admin@swr.com");

        Role roleAdmin = new Role();
        roleAdmin.setRoleName("ROLE_ADMIN");
        roleAdmin.setRoleType(RoleConstant.ROLE_ADMIN);

        Role roleUser = new Role();
        roleUser.setRoleName("ROLE_USER");
        roleUser.setRoleType(RoleConstant.ROLE_USER);

        user.setUserRoles(List.of(roleAdmin, roleUser));
        userInfoJpaRepository.save(user.convertToEntity());
    }

    private void createManager() {
        User user = new User();
        user.setFirstName("Manager");
        user.setLastName("Pahuja");
        user.setUsername("Manager");
        user.setPassword(passwordEncoder.encode("manager"));
        user.setEmail("manager@swr.com");

        Role roleManager = new Role();
        roleManager.setRoleName("ROLE_MANAGER");
        roleManager.setRoleType(RoleConstant.ROLE_MANAGER);

        Role roleUser = new Role();
        roleUser.setRoleName("ROLE_USER");
        roleUser.setRoleType(RoleConstant.ROLE_USER);

        user.setUserRoles(List.of(roleManager, roleUser));
        userInfoJpaRepository.save(user.convertToEntity());
    }
}
