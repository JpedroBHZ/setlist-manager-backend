package br.com.jpedrobhz.music_api.config;

import br.com.jpedrobhz.music_api.config.security.SecurityFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer; // IMPORTANTE ADICIONAR
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration; // IMPORTANTE ADICIONAR
import org.springframework.web.cors.CorsConfigurationSource; // IMPORTANTE ADICIONAR
import org.springframework.web.cors.UrlBasedCorsConfigurationSource; // IMPORTANTE ADICIONAR

import java.util.Arrays;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final SecurityFilter securityFilter;

    public SecurityConfig(SecurityFilter securityFilter) {
        this.securityFilter = securityFilter;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                // 👇 LINHA NOVA: Ativa a configuração de CORS que definimos lá embaixo
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                // Desabilita a proteção contra CSRF porque nossa API é Stateless (usa Tokens)
                .csrf(csrf -> csrf.disable())
                // Define que a aplicação não salvará sessões no servidor (padrão REST JWT)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                // Configuração das regras de acesso às rotas
                .authorizeHttpRequests(authorize -> authorize
                        // Libera os endpoints do OpenAPI/Swagger publicamente
                        .requestMatchers("/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html").permitAll()

                        .requestMatchers(HttpMethod.POST, "/auth/login").permitAll()    // Qualquer um tenta logar
                        .requestMatchers(HttpMethod.POST, "/auth/register").permitAll() // Qualquer um se cadastra
                        .requestMatchers(HttpMethod.GET, "/api/**").permitAll()        // Qualquer um lê músicas/eventos/setlists
                        .anyRequest().authenticated()                                  // Criar, deletar ou editar exige login!
                )
                // Agora a variável securityFilter vai funcionar perfeitamente aqui:
                .addFilterBefore(securityFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }

    // 👇 BEAN NOVO: Configura quais origens e métodos o Spring Security aceitará
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        // Autoriza expressamente o seu front-end em Angular
        configuration.setAllowedOrigins(Arrays.asList("http://localhost:4200"));
        // Autoriza os métodos HTTP padrão que o front vai usar
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        // Autoriza cabeçalhos comuns (inclusive o Header de Authorization que mandará o Token depois)
        configuration.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type", "Accept"));
        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration); // Aplica para todas as rotas
        return source;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}