
package com.sid.sec_service.repository;

import com.sid.sec_service.modeles.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 *
 * @author CTC
 */
public interface AppUserRepository extends JpaRepository<AppUser, Long> {
   public AppUser findByusername(String username);
}
