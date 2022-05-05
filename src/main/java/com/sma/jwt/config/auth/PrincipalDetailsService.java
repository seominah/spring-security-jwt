package com.sma.jwt.config.auth;

import com.sma.jwt.model.User;
import com.sma.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

// http://localhost:8080/login 요청이 올때 동작을 한다.
@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("principaldtaisservice 실행됨!");
        User userEntity = userRepository.findByUsername(username);
        System.out.println("userEntity : " + userEntity);
        return new PrincipalDetails(userEntity);
    }
}
