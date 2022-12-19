package com.sid.sec_service.controler;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sid.sec_service.filters.JwtUtils;
import com.sid.sec_service.modeles.AppRole;
import com.sid.sec_service.modeles.AppUser;
import com.sid.sec_service.services.AccountService;
import java.io.IOException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.Data;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 *
 * @author CTC
 */
@RestController
public class AccountRestController {

    @Autowired
    AccountService accountService;

    @GetMapping(path = "/getListUsers")
    public ResponseEntity listAppUsers() {

        return new ResponseEntity(accountService.listuser(), HttpStatus.OK);
    }

    @PostMapping(path = "/addUser")
    public ResponseEntity addUser(@RequestBody AppUser appUser) {
        return new ResponseEntity(accountService.addNewUser(appUser), HttpStatus.CREATED);
    }

    @PostMapping(path = "/addRole")
    public ResponseEntity addRole(@RequestBody AppRole appRole) {
        return new ResponseEntity(accountService.addNewRole(appRole), HttpStatus.CREATED);
    }

    @PostMapping(path = "/addRoleToUser")
    public ResponseEntity addRoleToUser(@RequestBody RoleUserForm roleUserForm) {
        accountService.addRoleToUser(roleUserForm.getUsername(), roleUserForm.getRoleName());
        return new ResponseEntity("{Success}", HttpStatus.CREATED);
    }

    @GetMapping(path = "loadUserByUserName/{username}")
    public ResponseEntity loadUserByUserName(@PathVariable(value = "username") String username) {
        return new ResponseEntity(accountService.loadUserByUserName(username), HttpStatus.CREATED);
    }

    @GetMapping(path = "/refreshToken")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String authorizationToken = request.getHeader(JwtUtils.AUT_HEADER);
        if (authorizationToken != null && authorizationToken.startsWith(JwtUtils.PREFIX)) {
            //si le token est expire lors de la verification alors on gerere une exception  
            try {
                String jwt = authorizationToken.substring(JwtUtils.PREFIX.length());
                Algorithm algorithm = Algorithm.HMAC256(JwtUtils.SECRET);
                JWTVerifier jWTVerifier = JWT.require(algorithm).build();
                DecodedJWT decodedJWT = jWTVerifier.verify(jwt);
                AppUser appUser = accountService.loadUserByUserName(decodedJWT.getSubject());
                String jwtAccessToken = JWT.create().withSubject(appUser.getUsername())
                        .withExpiresAt(new Date(System.currentTimeMillis() + JwtUtils.EXPIRE_REFRESH_TOKEN))
                        .withIssuer(request.getRequestURL().toString())
                        .withClaim("roles", appUser.getAppRole().stream().map(r -> r.getRoleName()).collect(Collectors.toList()))
                        .sign(algorithm);
                Map idtkent = new HashMap();
                idtkent.put("refresh-token", jwtAccessToken);
                idtkent.put("expireAt", new Date(System.currentTimeMillis() + JwtUtils.EXPIRE_REFRESH_TOKEN));

                new ObjectMapper().writeValue(response.getOutputStream(), idtkent);

            } catch (Exception e) {
                response.setHeader("error-message", e.getMessage());
                response.sendError(HttpServletResponse.SC_FORBIDDEN);
            }

        } else {

            throw new RuntimeException("Refresh Token Required");
        }
    }

    //recupere le user connecte
    @GetMapping(path = "/profile")
    public ResponseEntity profile(Principal principal) {
        return new ResponseEntity(accountService.loadUserByUserName(principal.getName()), HttpStatus.OK);

    }

}

@Data
class RoleUserForm {

    private String username, roleName;
}
