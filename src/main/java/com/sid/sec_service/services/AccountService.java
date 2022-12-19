/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Interface.java to edit this template
 */
package com.sid.sec_service.services;

import com.sid.sec_service.modeles.AppRole;
import com.sid.sec_service.modeles.AppUser;
import java.util.List;

/**
 *
 * @author CTC
 */
public interface AccountService {
   public AppUser addNewUser(AppUser appUser);
   public AppRole addNewRole(AppRole appRole);
   public void addRoleToUser(String username, String roleName);
   public AppUser loadUserByUserName(String username);
   public List<AppUser>listuser();
           
}
