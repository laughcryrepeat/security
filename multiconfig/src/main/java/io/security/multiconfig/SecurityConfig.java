package io.security.multiconfig;

import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
@Order(0)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

  protected void configure(HttpSecurity http) throws Exception {
    http
        .antMatcher("/admin/**")
        .authorizeRequests()
        .anyRequest().authenticated()
        .and()
        .httpBasic();
  }

}

/**
 * FilterChainProxy에 두개의 각기 다른 설정클래스에 따른 Filter들이 filterChains 배열에 등록됨.
 * 사용자 요청에 따라 거기에 맞틑 FilterChain 을 가져옴.
 *
 * Order 순서가 중요함.
 * 모든 요청에 대해 인증없이 접근이 가능한 설정, 넓은 범위의 보안 설정은 나중 순서로 설정해야 함.
 * 그렇지 않으면 스프링 시큐리티가 구체적인 보안 기능 처리 전에 먼저 처리하여 좁은 범위의 보안이 제대로 동작하지 않음.
 * 구체적인 보안 설정을 우선순위로 두어야 함.
 *
 */
@Configuration
@Order(1)
class SecurityConfig2 extends WebSecurityConfigurerAdapter {

  protected void configure(HttpSecurity http) throws Exception {
    http
        .authorizeRequests()
        .anyRequest().permitAll()
        .and()
        .formLogin();
  }
}
