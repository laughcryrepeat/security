package io.security.demo;

import javax.servlet.http.HttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SecurityController {


  @GetMapping("/")
  public String index(HttpSession session) {

    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    SecurityContext context = (SecurityContext)session.getAttribute(
        HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
    Authentication authentication1 = context.getAuthentication();
    // Session에 저장된 Authentication와 SecurityContextHolder에서 가져온 authentication 객체는 동일함.

    return "home";
  }

  @GetMapping("/thread")
  public String thread() {

    new Thread(
        new Runnable() {
          @Override
          public void run() {
            // SecurityContext 저장 정책에 의해 자식 스레드에서도 Authentication 객체 참조가 가능한지 확인 가능.
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
          }
        }
    ).start();

    return "thread";
  }

  @GetMapping("/loginPage")
  public String loginPage() {
    return "loginPage";
  }

  @GetMapping("/user")
  public String user() {
    return "user";
  }

  @GetMapping("/admin")
  public String admin() {
    return "admin";
  }

  @GetMapping("/admin/pay")
  public String adminPay() {
    return "admin/pay";
  }

  @GetMapping("/login")
  public String login() {
    return "login";
  }
  @GetMapping("/denied")
  public String denied() {
    return "denied";
  }
}
