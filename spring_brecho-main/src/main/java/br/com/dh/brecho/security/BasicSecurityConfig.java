package br.com.dh.brecho.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration //espera uma requisicao
@EnableWebSecurity //indica q a classe vai ser utilizada para seguranca da app
@EnableGlobalMethodSecurity(prePostEnabled = true) //habilita de forma global a seguranca a aplicacao
public class BasicSecurityConfig {

    @Bean//pode ser chamado em qlq classe dentro da app(autoriwed so na classe)
    AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration)
            throws Exception {
        return authenticationConfiguration.getAuthenticationManager();//procura um autenticador(classe UserDetails)
    }
  
    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and().csrf().disable()
                .cors();//faz o front funcionar c outros servidores

        http
                .authorizeHttpRequests((auth) -> auth
                        .antMatchers("/usuarios/logar").permitAll()
                        .antMatchers("/usuarios/cadastrar").permitAll()
                        .antMatchers(HttpMethod.OPTIONS).permitAll()
                        .anyRequest().authenticated())
                .httpBasic();//tela de login do navegador

        return http.build();

    }

}