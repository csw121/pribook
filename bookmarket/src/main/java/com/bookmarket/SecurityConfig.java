package com.bookmarket;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests((authorizeHttpRequests) -> authorizeHttpRequests
                        // [CTO 수정] '도서 상세' 페이지 주소("/book/detail/**")를 '허용 목록'에 추가합니다.
                        // (/**: '/detail/' 뒤에 1이 오든 2가 오든 '모두' 허용한다는 뜻)
                        .requestMatchers("/", "/member/login", "/member/signup", "/book/search", "/book/detail/**","**").permitAll()
                        .requestMatchers("/**.css", "/**.js").permitAll()

                        // '그리고' 그 외 모든 요청을 '마지막'에 막습니다.
                        .anyRequest().authenticated()
                )
                .csrf((csrf) -> csrf.disable())

                .formLogin((formLogin) -> formLogin
                        .loginPage("/member/login")
                        .defaultSuccessUrl("/")
                        .permitAll()
                )

                .logout((logout) -> logout
                        .logoutUrl("/member/logout")
                        .logoutSuccessUrl("/")
                        .invalidateHttpSession(true)
                )
        ;
        return http.build();
    }

    // '암호화 기계' (부팅에 필수)
    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}