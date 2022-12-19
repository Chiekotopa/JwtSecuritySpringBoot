package com.sid.sec_service.services;

import com.sid.sec_service.modeles.AppRole;
import com.sid.sec_service.modeles.AppUser;
import com.sid.sec_service.repository.AppRoleRepository;
import com.sid.sec_service.repository.AppUserRepository;
import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
public class AccountServiceImpl implements AccountService {

    @Autowired
    AppUserRepository appUserRepository;

    @Autowired
    AppRoleRepository appRoleRepository;
    
    @Autowired
    PasswordEncoder passwordEncoder;

    @Override
    public AppUser addNewUser(AppUser appUser) {
        appUser.setPassword(passwordEncoder.encode(appUser.getPassword()));
        return appUserRepository.save(appUser);
    }

    @Override
    public AppRole addNewRole(AppRole appRole) {
        return appRoleRepository.save(appRole);
    }

    @Override
    public void addRoleToUser(String username, String roleName) {
        AppUser appUser = appUserRepository.findByusername(username);
        AppRole appRole = appRoleRepository.findByroleName(roleName);
        appUser.getAppRole().add(appRole);
    }

    @Override
    public AppUser loadUserByUserName(String username) {
        return appUserRepository.findByusername(username);
    }

    @Override
    public List<AppUser> listuser() {
        return appUserRepository.findAll();
    }

}
