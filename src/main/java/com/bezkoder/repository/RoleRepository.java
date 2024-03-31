package com.bezkoder.repository;

import java.util.Optional;

import com.bezkoder.models.ERole;
import com.bezkoder.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
  Optional<Role> findByName(ERole name);
}
