package hello.wondsn.springsecurityjwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import hello.wondsn.springsecurityjwt.config.auth.PrincipalDetails;
import hello.wondsn.springsecurityjwt.model.User;
import hello.wondsn.springsecurityjwt.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

// 시큐리티가 filter 가지고 있는데 그 필터 중 BasicAuthenticationFilter라는 것이 있음
// 권한이나 인증이 필요한 특정 주소를 요청 시, 이 필터를 무조건 거치게 됨
// 만약 권한, 인증이 필요한 주소가 아니라면, 이 필터를 거치지 않음.
@Slf4j
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private final UserRepository userRepository;

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
        super(authenticationManager);
        this.userRepository = userRepository;
    }

    // 인증이나 권한이 필요한 주소요청이 있을 때, 해당 필터를 거치게 됨
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        String jwtHeader = request.getHeader("Authorization");

        // header가 있는지 확인
        if (jwtHeader == null || !jwtHeader.startsWith("Bearer ")) {
            chain.doFilter(request, response);
            return;
        }

        // JWT 토큰을 검증해서 정상적인 사용자인지 확인
        String token = jwtHeader.replace("Bearer ", "");
        String username = JWT.require(Algorithm.HMAC512("cos"))
                .build()
                .verify(token)
                .getClaim("username").asString();
        // 서명이 정상적으로 됨
        if (username != null) {
            User user = userRepository.findByUsername(username).orElseThrow(() -> new UsernameNotFoundException("존재하지 않는 유저입니다."));
            PrincipalDetails principal = new PrincipalDetails(user);
            // JWT 토큰 서명을 통해서 서명이 정상이면 Authentication 객체를 만들어줌
            // 원래 AuthenticationManager를 통해서 만들 수 있지만, UserDetailsService::loadUserByUsername 메소드가 호출됨. 이는 이미 로그인과정에서 지나옴
            // 그래서 UsernamePasswordAuthenticationToken 객체를 생성함으로써 강제로 만들 수 있음
            Authentication authentication = new UsernamePasswordAuthenticationToken(principal, null, principal.getAuthorities());
            // 강제로 시큐리티의 세션에 접근하여 Authentication 객체를 저장
            SecurityContextHolder.getContext().setAuthentication(authentication);
            chain.doFilter(request, response);
        }
    }
}
