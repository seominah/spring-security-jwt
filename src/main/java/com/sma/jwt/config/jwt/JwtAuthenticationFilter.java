package com.sma.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sma.jwt.config.auth.PrincipalDetails;
import com.sma.jwt.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;

// Spring Security에서 아래의 필터가 있음
// /login 요청해서 username, password 전송하면 (post)
// 아래의 필터가 동작함.
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;

    // /login 요청을 하면 로그인 시도를 위해서 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("로그인 시도중");

        // 1. username과 password 방아서
        // request.getIntHeader()에 usrname과 password가 담겨있다.
        try {
//            BufferedReader br = request.getReader();
//            String input = null;
//            while ((input = br.readLine()) != null) {
//                System.out.println(input);
//            }
            ObjectMapper om = new ObjectMapper();
            User user = om.readValue(request.getInputStream(), User.class);
            System.out.println(user);

            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            // PrincipalDetailsService의 loadUserByUsername()함수가 실행된 후 정상이라면 authentication이 return됨
            // DB에 있는 username과 paasword가 일치한다.
            Authentication authentication = authenticationManager.authenticate(authenticationToken);

            // 로그인이 정상적으로 되면 아래에 프린트문이 잘 실행됨
            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            System.out.println(principalDetails.getUser().getUsername());

            // 권한처리를 위해서는 session에 넣어준다.
            return authentication;
        } catch (IOException e) {
            e.printStackTrace();
        }
        // 2. 정상인지 로그인 시도를 해본다. authenticationManager로 로그인을 시도하면
        //  PrincipalDetailsService가 호출되어 loadUserByUsername() 함수가 실행된다.
        // 3. PrincipalDetails를 세션에 담아 (권한 관리를 위해)
        // 4. JWT토큰을 만들어서 응답해주면 됨
        return null;
    }

    // attemtAuthentication실행 후 인증이 정상적으로 되었으면 successfulAuthentication 함수가 실행됨
    // JWT 토큰을 만들어서 request 요청한 사용자에게 JWT토큰을 response 해주면 됨
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        // JWT 생성
        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        // Hash 암호방식
        String jwtToken = JWT.create()
                .withSubject(principalDetails.getUsername()) // 토큰 이름
                .withExpiresAt(new Date(System.currentTimeMillis() + JwtProperties.EXPIRATION_TIME)) // 토큰 만료 시간
                .withClaim("id", principalDetails.getUser().getId()) // private
                .withClaim("username", principalDetails.getUser().getUsername())
                .sign(Algorithm.HMAC512(JwtProperties.SECRET)); // sign
        response.addHeader(JwtProperties.HEADER_STRING, JwtProperties.TOKEN_PREFIX+jwtToken);
    }
}
