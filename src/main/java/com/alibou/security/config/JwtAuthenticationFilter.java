package com.alibou.security.config;

import com.alibou.security.token.TokenRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.beans.Transient;
import java.io.IOException;
import java.security.Security;

import jakarta.transaction.TransactionScoped;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

  private final JwtService jwtService;
  private final UserDetailsService userDetailsService;
  private final TokenRepository tokenRepository;

  @Override
  protected void doFilterInternal(
      @NonNull HttpServletRequest request,
      @NonNull HttpServletResponse response,
      @NonNull FilterChain filterChain
  ) throws ServletException, IOException {

    //https://developer-ping9.tistory.com/237

    /*
    filterChain.doFilter() 메서드는 Spring Security 필터 체인에서 현재 필터의 처리를 완료하고 다음 필터로 제어를 전달하는 역할을 합니다.

Spring Security는 보안 관련 작업을 수행하기 위해 다양한 필터들로 구성된 필터 체인을 사용합니다. 이러한 필터 체인은 요청이 들어올 때 필터들을 순차적으로 실행하여 인증, 권한 부여, 보안 검사 등의 작업을 수행하며, 필터들 간에는 연결고리가 필요합니다.

filterChain.doFilter() 메서드는 현재 필터의 처리가 완료되었음을 알리고, 제어를 다음 필터로 전달합니다. 이 메서드를 호출하면 다음 필터로 제어가 이동하며, 다음 필터에서는 동일한 메서드를 호출하여 체인 상의 다음 필터로 계속 진행합니다. 이렇게 필터 체인을 따라가면서 모든 필터가 처리되면 최종적으로 요청이 서블릿이나 컨트롤러로 전달됩니다.

예를 들어, Spring Security 필터 체인에서 인증 필터가 실행된 후에 filterChain.doFilter()를 호출하면, 권한 부여 필터가 실행되고 그 다음에는 보안 검사 필터가 실행됩니다. 이런 식으로 필터 체인의 각 필터들이 차례대로 실행되고, 요청이 최종적으로 처리되는 것입니다.

filterChain.doFilter() 메서드는 필터 체인을 통해 제어를 다음 필터로 전달하는 역할을 하므로, 이 메서드를 호출하지 않으면 필터 체인의 다음 단계로 진행되지 않고 처리가 중단됩니다.
     */

    if (request.getServletPath().contains("/api/v1/auth")) {

      filterChain.doFilter(request, response);

      return;
    }

    final String authHeader = request.getHeader("Authorization");
    final String jwt;
    final String userEmail;
    if (authHeader == null ||!authHeader.startsWith("Bearer ")) {
      filterChain.doFilter(request, response);
      return;
    }
    jwt = authHeader.substring(7);
    userEmail = jwtService.extractUsername(jwt);
    if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
      UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
      var isTokenValid = tokenRepository.findByToken(jwt)
          .map(t -> !t.isExpired() && !t.isRevoked())
          .orElse(false);
      if (jwtService.isTokenValid(jwt, userDetails) && isTokenValid) {
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
            userDetails,
            null,
            userDetails.getAuthorities()
        );
        authToken.setDetails(
            new WebAuthenticationDetailsSource().buildDetails(request)
        );
        SecurityContextHolder.getContext().setAuthentication(authToken);
      }
    }
    filterChain.doFilter(request, response);
  }
}
