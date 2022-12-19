package com.sid.sec_service.filters;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 *
 * @author CTC
 */
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private AuthenticationManager authenticationManager;

    public JwtAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        UsernamePasswordAuthenticationToken passwordAuthenticationToken = new UsernamePasswordAuthenticationToken(request.getParameter("username"), request.getParameter("password"));
        return authenticationManager.authenticate(passwordAuthenticationToken);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        User user = (User) authResult.getPrincipal();
        Algorithm algo1 = Algorithm.HMAC256(JwtUtils.SECRET);
        String jwtAccessToken = JWT.create().withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + JwtUtils.EXPIRE_ACCESS_TOKEN))
                .withIssuer(request.getRequestURL().toString())
                .withClaim("roles", user.getAuthorities().stream().map(r -> r.getAuthority()).collect(Collectors.toList()))
                .sign(algo1);
        response.setHeader(JwtUtils.AUT_HEADER, jwtAccessToken);

        String jwtRefreshToken = JWT.create().withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + JwtUtils.EXPIRE_REFRESH_TOKEN))
                .withIssuer(request.getRequestURL().toString())
                .withClaim("roles", user.getAuthorities().stream().map(r -> r.getAuthority()).collect(Collectors.toList()))
                .sign(algo1);
        response.setContentType("application/json");
        Map idtkent = new HashMap();
        idtkent.put("access-token", jwtAccessToken);
        idtkent.put("expireAt", new Date(System.currentTimeMillis() + JwtUtils.EXPIRE_ACCESS_TOKEN));
        idtkent.put("refresh-token", jwtRefreshToken);
        idtkent.put("expireAt", new Date(System.currentTimeMillis() + JwtUtils.EXPIRE_REFRESH_TOKEN));

        new ObjectMapper().writeValue(response.getOutputStream(), idtkent);

    }

}
