package com.ferendia.discoveryserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity
@Order(1)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(final AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("admin").password(passwordEncoder().encode("adminPassword")).roles("ADMIN")
                .and()
                .withUser("system").password(passwordEncoder().encode("systemPassword")).roles("SYSTEM");

    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(final HttpSecurity http) throws Exception {
        http.sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.ALWAYS).and()
                .requestMatchers().antMatchers("/eureka/**").and()
                .authorizeRequests()
                .antMatchers("/eureka/**").hasAnyRole("SYSTEM", "ADMIN")
                .and().sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.ALWAYS).and().requestMatchers().antMatchers("/")
                .and().authorizeRequests().antMatchers("/").hasAnyRole("ADMIN")
                .anyRequest().authenticated().and()
                .httpBasic().and().csrf().disable();
    }
}
