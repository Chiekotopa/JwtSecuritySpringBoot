package com.sid.sec_service.filters;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 *
 * @author CTC
 */
public class JwtAuthorizationFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (request.getServletPath().equals("/refreshToken")) {
            filterChain.doFilter(request, response);

        } else {
            String authorizationToken = request.getHeader(JwtUtils.AUT_HEADER);
            if (authorizationToken != null && authorizationToken.startsWith(JwtUtils.PREFIX)) {
                //si le token est expire lors de la verification alors on gerere une exception  
                try {
                    String jwt = authorizationToken.substring(JwtUtils.PREFIX.length());
                    Algorithm algorithm = Algorithm.HMAC256(JwtUtils.SECRET);
                    JWTVerifier jWTVerifier = JWT.require(algorithm).build();
                    DecodedJWT decodedJWT = jWTVerifier.verify(jwt);
                    String[] roles = decodedJWT.getClaim("roles").asArray(String.class);
                    Collection<GrantedAuthority> grantedAuthoritys = new ArrayList<>();
                    for (String r : roles) {
                        grantedAuthoritys.add(new SimpleGrantedAuthority(r));
                    }
                    UsernamePasswordAuthenticationToken authenticationToken
                            = new UsernamePasswordAuthenticationToken(decodedJWT.getSubject(), null, grantedAuthoritys);
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                    filterChain.doFilter(request, response);
                } catch (Exception e) {
                    response.setHeader("error-message", e.getMessage());
                    response.sendError(HttpServletResponse.SC_FORBIDDEN);
                }

            } else {
                filterChain.doFilter(request, response);
            }
        }

    }

}
