package com.securevault.repository;

import com.securevault.entity.User;
import com.securevault.entity.VaultItem;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface VaultItemRepository extends JpaRepository<VaultItem, Long> {
    List<VaultItem> findByOwner(User owner);
    Optional<VaultItem> findByIdAndOwner(Long id, User owner);
}
