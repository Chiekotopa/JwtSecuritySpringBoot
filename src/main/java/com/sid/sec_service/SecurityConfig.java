package com.sid.sec_service;

import com.sid.sec_service.filters.JwtAuthenticationFilter;
import com.sid.sec_service.filters.JwtAuthorizationFilter;
import com.sid.sec_service.modeles.AppUser;
import com.sid.sec_service.services.AccountService;
import java.util.ArrayList;
import java.util.Collection;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 *
 * @author CTC
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    AccountService accountService;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(new UserDetailsService() {
            @Override
            public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
                AppUser appUser = accountService.loadUserByUserName(username);
                Collection<GrantedAuthority> authoritys = new ArrayList<>();
                appUser.getAppRole().forEach(r -> {
                    authoritys.add(new SimpleGrantedAuthority(r.getRoleName()));
                });
                return new User(appUser.getUsername(), appUser.getPassword(), authoritys);
            }
        });
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();
        //pour preciser a Spring security que on utilise Authentification STATELESS
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        http.headers().frameOptions().disable();
        //http.formLogin();
        http.authorizeRequests().antMatchers("/h2-console/**", "/login/**","/refreshToken/**").permitAll();
//        http.authorizeHttpRequests().antMatchers(HttpMethod.POST, "/getListUsers/**").hasAuthority("ADMIN");
//        http.authorizeHttpRequests().antMatchers(HttpMethod.GET, "/getListUsers/**").hasAuthority("USER");
        http.authorizeRequests().anyRequest().authenticated();
        http.addFilter(new JwtAuthenticationFilter(authenticationManagerBean()));
        http.addFilterBefore(new JwtAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class);
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

}
