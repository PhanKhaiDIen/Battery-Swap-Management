package com.ev.batteryswap.security;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity // Bật module bảo mật Spring Security
public class SecurityConfig {

    private final JwtAuthFilter jwtAuthFilter;

    public SecurityConfig(JwtAuthFilter jwtAuthFilter) {
        this.jwtAuthFilter = jwtAuthFilter;
    }
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(sess -> sess.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/","/my","/login", "/register","/packages","/admin/login","/staff/login","/api/**").permitAll() // API công khai
                        .requestMatchers("/css/**", "/js/**", "/images/**", "/img/**").permitAll() // hiệu ứng
                        .requestMatchers("/packages/**", "/pricing/**").permitAll()
                        .requestMatchers("/my/**").hasAnyAuthority("ADMIN", "STAFF", "DRIVER")
                        .requestMatchers("/datlich/**", "/pricing/**").hasAnyAuthority("DRIVER")
                        .requestMatchers("/admin/**").hasAnyAuthority("ADMIN")
                        .requestMatchers("/staff/**").hasAnyAuthority("STAFF")
                        .requestMatchers("/admin/login", "/staff/login").permitAll()
                        .anyRequest().authenticated()
                )
                .formLogin(AbstractHttpConfigurer::disable) // vô hiệu hóa form login mặc định của Spring Security
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

}
