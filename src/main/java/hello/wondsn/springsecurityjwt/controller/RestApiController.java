package hello.wondsn.springsecurityjwt.controller;

import hello.wondsn.springsecurityjwt.model.User;
import hello.wondsn.springsecurityjwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@CrossOrigin
@RestController
@RequiredArgsConstructor
public class RestApiController {

    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;

    @GetMapping("/home")
    public String home() {
        return "<h1>Home</h1>";
    }

    @PostMapping("/token")
    public String token() {
        return "<h1>Token</h1>";
    }

    @PostMapping("/join")
    public String join(@RequestBody User user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        user.setRoles("ROLE_USER");
        userRepository.save(user);
        return "회원가입완료";
    }

    @GetMapping("/api/v1/user")
    @ResponseBody
    public String user() {
        return "user";
    }

    @GetMapping("/api/v1/admin")
    @ResponseBody
    public String admin() {
        return "admin";
    }

    @GetMapping("/api/v1/manager")
    @ResponseBody
    public String manager() {
        return "manager";
    }
}
