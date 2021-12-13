package io.security;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SecurityController {


  @GetMapping("/")
  public String index() {
    return "home";
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
