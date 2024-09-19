package com.vrt.sp.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(authorizeRequests -> authorizeRequests
                .anyRequest().authenticated()  // Secures all endpoints
            )
            .formLogin(formLogin -> formLogin
                .loginPage("/login")  // Specify custom or default login page
            )
            .saml2Login(saml2Login -> saml2Login
                .relyingPartyRegistrationRepository(relyingPartyRegistrationRepository())  // Configure SAML2 login
            )
            .saml2Logout(saml2Logout -> saml2Logout
                .logoutUrl("/saml2/logout")  // Handles SAML2 logout
            );

        return http.build();
    }

    // Define the RelyingPartyRegistrationRepository bean for SAML2 configurations
    @Bean
    public RelyingPartyRegistrationRepository relyingPartyRegistrationRepository() {
        // Define the service provider (SP) registration
        RelyingPartyRegistration relyingPartyRegistration = RelyingPartyRegistration
            .withRegistrationId("sp")  // Registration ID for the Service Provider
            .entityId("http://localhost:8081/saml2/service-provider-metadata")  // SP entity ID
            .assertionConsumerServiceLocation("http://localhost:8081/login/saml2/sso/sp")  // ACS URL for receiving SAML responses

            // Identity Provider (IdP) configuration
            .assertingPartyDetails(party -> party
                .entityId("http://localhost:8080/idp/entityId")  // IdP entity ID (from IdP metadata)
                .singleSignOnServiceLocation("http://localhost:8080/saml2/idp/SSO")  // IdP SSO URL
                .singleLogoutServiceLocation("http://localhost:8080/saml2/idp/SLO")  // IdP SLO URL
            )
            .build();
        
        return new InMemoryRelyingPartyRegistrationRepository(relyingPartyRegistration);
    }

    // Define the UserDetailsService with in-memory users and encoded passwords
    @Bean
    public UserDetailsService userDetailsService(PasswordEncoder passwordEncoder) {
        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
        manager.createUser(User.withUsername("user1")
            .password(passwordEncoder.encode("password"))  // Encode password using BCrypt
            .roles("USER")
            .build());
        manager.createUser(User.withUsername("admin")
            .password(passwordEncoder.encode("password"))  // Encode password using BCrypt
            .roles("ADMIN")
            .build());
        return manager;
    }

    // Define the PasswordEncoder bean to be used for password encoding
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();  // Use BCryptPasswordEncoder for secure password storage
    }
}
