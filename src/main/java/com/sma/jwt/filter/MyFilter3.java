package com.sma.jwt.filter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

public class MyFilter3 implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        // Token 인증
        // id, pw가 들어와 로그인이 완료되면 토큰을 만들어주고 그걸 응답을 해준다.
        //        // 요청할 때 마다 header에 Authorization에 value 값으로 토근을 가지고 온다.
        // 그때 토큰이 넘어오면 이 토킨이 내가 만든 토킨이 맞는지 검증만 하면됨 (RSA, HS256)
        if (req.getMethod().equals("POST")) {
            String headerAuth = req.getHeader("Authorization");
            System.out.println(headerAuth);

            if (headerAuth.equals("cos")) {
                chain.doFilter(req, res);
            } else {
                PrintWriter out = res.getWriter();
                out.println("인증 안됨");
            }
        }
    }
}
