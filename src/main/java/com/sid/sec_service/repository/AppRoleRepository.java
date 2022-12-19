
package com.sid.sec_service.repository;

import com.sid.sec_service.modeles.AppRole;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 *
 * @author CTC
 */
public interface AppRoleRepository extends JpaRepository<AppRole, Long> {
    AppRole findByroleName(String name);
}
