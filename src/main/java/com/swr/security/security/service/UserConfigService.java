package com.swr.security.security.service;

import com.swr.security.entity.UserEntity;
import com.swr.security.repository.UserInfoJpaRepository;
import com.swr.security.security.model.UserSecurityInfo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserConfigService implements UserDetailsService {

    private final UserInfoJpaRepository userInfoJpaRepository;

    @Autowired
    public UserConfigService(UserInfoJpaRepository userInfoJpaRepository) {
        this.userInfoJpaRepository = userInfoJpaRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return this.userInfoJpaRepository.findByUsernameOrEmail(username, username).map(userEntity ->
                new UserSecurityInfo(userEntity.convertToModel()))
                .orElseThrow(() -> new UsernameNotFoundException("User not found with username or email - " + username));
    }
}
