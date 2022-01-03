package io.security.demo;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

  @Autowired
  UserDetailsService userDerailsService;

  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth.inMemoryAuthentication().withUser("user").password("{noop}1111").roles("USER");
    auth.inMemoryAuthentication().withUser("sys").password("{noop}1111").roles("SYS","USER");
    auth.inMemoryAuthentication().withUser("admin").password("{noop}1111").roles("ADMIN","SYS","USER");
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http  // 인가
        .authorizeRequests()
        .antMatchers("/login").permitAll()
        .antMatchers("/user").hasRole("USER")
        .antMatchers("/admin/pay").hasRole("ADMIN")
        .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
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
            RequestCache requestCache = new HttpSessionRequestCache();
            SavedRequest savedRequest = requestCache.getRequest(request, response);
            String redirectUrl = savedRequest.getRedirectUrl();
            response.sendRedirect(redirectUrl);  // 인증 성공 후 세션에 담아둔 이전 요청 정보로 이동.
          }
        })
        .failureHandler(new AuthenticationFailureHandler() {  // 로그인 실패 후 핸들러
          @Override
          public void onAuthenticationFailure(HttpServletRequest request,
              HttpServletResponse response, AuthenticationException exception)
              throws IOException, ServletException {
            System.out.println("exception" + exception.getMessage());
          }
        })
        .permitAll();
    http
        .logout()
        .logoutUrl("/logout")
        .logoutSuccessUrl("/login")
        .addLogoutHandler(new LogoutHandler() {
          @Override
          public void logout(HttpServletRequest request, HttpServletResponse response,
              Authentication authentication) {
            HttpSession session = request.getSession();
            session.invalidate();
            // SecurityContextLogoutHandler 에서 seeeon 무효화 해주기 때문에 위 로직은 필요없음.
          }
        })
        .logoutSuccessHandler(new LogoutSuccessHandler() {  // logout 성공한 후 로직
          @Override
          public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response,
              Authentication authentication) throws IOException, ServletException {
            response.sendRedirect("/login");
          }
        })
        .deleteCookies("remember-me");
    http
        .rememberMe() // 관련 필터 :
        .rememberMeParameter("remember")  // 기본 파라미터명은 remember-me
        .tokenValiditySeconds(3600) // Default는 14일
        //.alwaysRemember(true) // 리멤버미 기능이 활성화되지 않아도 항상 실행. 대체로 설정x
        .userDetailsService(userDerailsService);
    http
        .sessionManagement()  // 세션 관리 기능. 관련 필터 : SessionManagementFilter, ConcurrentSessionFilter
        .sessionCreationPolicy(SessionCreationPolicy.ALWAYS)  // Always: 항상 생성, If_Required: 필요시 생성(default), Never: 생성하지 않으나 존재하면 사용, Stateless: 사용안함. jwt 사용할 경우 선택
        .sessionFixation().changeSessionId()  // servelet 3.x 이상 changeSessionId: 기본값, none : 세션 새로설정 안함, servelet 3.x 미만 migrateSession: 세션 새로 생성함, newSession : 이전 세션에서 설정한 속성을 사용하지 못함
        .maximumSessions(1) // 최대허용 가능 세션 수 , -1: 무제한 로그인 세션 허용
        .maxSessionsPreventsLogin(true) // true: 동시 로그인 차단함. false:기존 세션 만료(default)
        .expiredUrl("/expired"); // 세션이 만료된 경우 이동 할 페이지
    http
        .exceptionHandling()  // 인증 실패시 예외 처리. 관련 필터: ExceptionTranslationFilter
        .authenticationEntryPoint(new AuthenticationEntryPoint() {
          @Override
          public void commence(HttpServletRequest request, HttpServletResponse response,
              AuthenticationException authException) throws IOException, ServletException {
            response.sendRedirect("/login");
          }
        })
        .accessDeniedHandler(new AccessDeniedHandler() {
          @Override
          public void handle(HttpServletRequest request, HttpServletResponse response,
              AccessDeniedException accessDeniedException) throws IOException, ServletException {
            response.sendRedirect("/denied");
          }
        });
  }
}
