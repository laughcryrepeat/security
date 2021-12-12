package io.security;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http  // 인가
        .authorizeRequests()
        .anyRequest().authenticated();
    http  // 인증
        .formLogin()
        //.loginPage("/loginPage")  // 사용자 정의 로그인 페이지
        .defaultSuccessUrl("/") // 로그인 성공 후 이동 페이지
        .failureUrl("/login") // 로그인 실패 후 이동 페이지
        .usernameParameter("userId")  // 아이디 파라미터명 설정
        .passwordParameter("passwd")  // 패스워드 파라미터명 설정
        .loginProcessingUrl("/login_proc")  // 로그인 Form Action Url
        .successHandler(new AuthenticationSuccessHandler() {  // 로그인 성공 후 핸들러
          @Override
          public void onAuthenticationSuccess(HttpServletRequest request,
              HttpServletResponse response, Authentication authentication)
              throws IOException, ServletException {
            System.out.printf("authentication"+authentication.getName());
            response.sendRedirect("/");
          }
        })
        .failureHandler(new AuthenticationFailureHandler() {  // 로그인 실패 후 핸들러
          @Override
          public void onAuthenticationFailure(HttpServletRequest request,
              HttpServletResponse response, AuthenticationException exception)
              throws IOException, ServletException {
            System.out.println("exception"+exception.getMessage());
          }
        })
        .permitAll()
    ;
  }
}
