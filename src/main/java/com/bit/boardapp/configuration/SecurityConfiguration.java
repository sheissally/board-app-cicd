package com.bit.boardapp.configuration;

import com.bit.boardapp.jwt.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {
    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    @Bean
    public static PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                    .cors(httpSecurityCorsConfigurer -> {})
                    .csrf(AbstractHttpConfigurer::disable)
                    .httpBasic(httpSecurityHttpBasicConfigurer -> {
                        httpSecurityHttpBasicConfigurer.disable();
                    })
                    .sessionManagement(httpSecuritySessionManagementConfigurer -> {
                        httpSecuritySessionManagementConfigurer.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
                    })
                    .authorizeHttpRequests(authorizationManagerRequestMatcherRegistry -> {
                        authorizationManagerRequestMatcherRegistry.requestMatchers("/").permitAll();
                        authorizationManagerRequestMatcherRegistry.requestMatchers("/favicon.ico").permitAll();
                        authorizationManagerRequestMatcherRegistry.requestMatchers("/manifest.json").permitAll();
                        authorizationManagerRequestMatcherRegistry.requestMatchers("/asset-manifest.json").permitAll();
                        authorizationManagerRequestMatcherRegistry.requestMatchers("/robots.txt").permitAll();
                        authorizationManagerRequestMatcherRegistry.requestMatchers("/index.html").permitAll();
                        authorizationManagerRequestMatcherRegistry.requestMatchers("/static/**").permitAll();
                        authorizationManagerRequestMatcherRegistry.requestMatchers("/images/**").permitAll();
                        authorizationManagerRequestMatcherRegistry.requestMatchers("/board/**").hasAnyRole("ADMIN", "USER");
                        authorizationManagerRequestMatcherRegistry.requestMatchers("/admin/**").hasRole("ADMIN");
                        authorizationManagerRequestMatcherRegistry.requestMatchers("/user/login").permitAll();
                        authorizationManagerRequestMatcherRegistry.requestMatchers("/user/join").permitAll();
                        authorizationManagerRequestMatcherRegistry.requestMatchers("/user/id-check").permitAll();
                        //리액트 라우터 기능(페이지 이동하는 기능)들은 모두 permitAll
                        authorizationManagerRequestMatcherRegistry.requestMatchers("/app/**").permitAll();
                        authorizationManagerRequestMatcherRegistry.anyRequest().authenticated();
                    })
                    .addFilterAfter(jwtAuthenticationFilter, CorsFilter.class)
                    .build();
    }
}
