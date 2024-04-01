package com.swr.security.repository;

import com.swr.security.entity.RoleEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface UserRoleJpaRepository extends JpaRepository<RoleEntity, UUID> {
}
