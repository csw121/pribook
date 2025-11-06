package com.bookmarket;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
// [CTO 수정] 'JPA 스위치'의 '부품 수입(import)'을 '정확하게' 합니다.
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

// [CTO 수정] 'JPA 스위치'를 '올바르게' 켭니다.
@EnableJpaRepositories(basePackages = "com.bookmarket")
@SpringBootApplication
public class BookmarketApplication {

    public static void main(String[] args) {
        SpringApplication.run(BookmarketApplication.class, args);
    }

}