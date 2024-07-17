package com.security.login.config

import com.security.login.jwt.JwtAccessDeniedHandler
import com.security.login.jwt.JwtAuthenticationEntryPoint
import com.security.login.jwt.JwtFilter
import com.security.login.jwt.JwtTokenProvider
import com.security.login.service.RedisService
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter

@Configuration
@EnableWebSecurity
class SecurityConfig(
    private val jwtAccessDeniedHandler: JwtAccessDeniedHandler,
    private val jwtAuthenticationEntryPoint: JwtAuthenticationEntryPoint,
    private val jwtTokenProvider: JwtTokenProvider,
    private val redisService: RedisService,
    @Value("\${jwt.access}")
    private val accessTokenName : String,
    @Value("\${jwt.refresh}")
    private val refreshTokenName : String
){

    @Bean
    fun passwordEncoder() : PasswordEncoder{ //빈 등록해서 비밀번호 암호화에는 BCryptPasswordEncoder를 사용하도록함
        return BCryptPasswordEncoder()
    }

    @Bean
    fun configure (http : HttpSecurity) : SecurityFilterChain{
        http
            .csrf { csrf -> csrf.disable() }
            .httpBasic { httpBasic -> httpBasic.disable() }
            .formLogin { formLogin -> formLogin.disable() }
            .sessionManagement { sessionManagement ->
                sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            }
            // enable h2-console
            .headers { headers ->
                headers.frameOptions { frameOptions -> frameOptions.sameOrigin() }
            }

            .exceptionHandling { exceptionHandling ->
                exceptionHandling.authenticationEntryPoint(jwtAuthenticationEntryPoint)
                exceptionHandling.accessDeniedHandler(jwtAccessDeniedHandler)
            }

            .authorizeHttpRequests { authorizeRequests ->
                authorizeRequests.requestMatchers("/auth/**", "/h2-console/**").permitAll()
                authorizeRequests.anyRequest().authenticated()
            }

            .addFilterBefore(
                JwtFilter(jwtTokenProvider, redisService, accessTokenName, refreshTokenName),
                UsernamePasswordAuthenticationFilter::class.java
            )

        return http.build()
    }


}