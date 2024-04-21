package com.swr.security.security.filter;

import com.swr.security.dto.TokenType;
import com.swr.security.security.config.RSAKeyRecord;
import com.swr.security.security.service.UserConfigService;
import com.swr.security.utility.JwtTokenUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.util.Objects;

@Slf4j
@RequiredArgsConstructor
public class JwtAccessTokenFilter extends OncePerRequestFilter {

    private final RSAKeyRecord rsaKeyRecord;
    private final JwtTokenUtils jwtTokenUtils;
    private final UserConfigService userConfigService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response
            , FilterChain filterChain) throws ServletException, IOException {
        try {
            log.info("JwtAccessTokenFilter :: Started");

            final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

            if (Objects.isNull(authHeader) || authHeader.isBlank()) {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Authorization header is invalid !");
            }

            if (!authHeader.startsWith(TokenType.Bearer.name())) {
                filterChain.doFilter(request, response);
                return;
            }

            JwtDecoder jwtDecoder = NimbusJwtDecoder.withPublicKey(rsaKeyRecord.rsaPublicKey()).build();
            final String authHeaderVal = authHeader.substring(7);
            final Jwt jwtToken = jwtDecoder.decode(authHeaderVal);

            final String username = jwtTokenUtils.getUsername(jwtToken);

            if (Objects.nonNull(username) && !username.isBlank() && Objects.isNull(SecurityContextHolder.getContext().getAuthentication())) {
                UserDetails userDetails = userConfigService.loadUserByUsername(username);

                if (jwtTokenUtils.isTokenValid(jwtToken, userDetails)) {
                    SecurityContext securityContext = SecurityContextHolder.createEmptyContext();

                    UsernamePasswordAuthenticationToken createdToken = new UsernamePasswordAuthenticationToken(
                            userDetails, null, userDetails.getAuthorities());

                    createdToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    securityContext.setAuthentication(createdToken);
                    SecurityContextHolder.setContext(securityContext);
                }
            }

            log.info("[JwtAccessTokenFilter:doFilterInternal] Completed");
            filterChain.doFilter(request, response);
        } catch (Exception exception) {
            log.error("[JwtAccessTokenFilter:doFilterInternal] Exception due to :{}", exception.getMessage());
            throw new ResponseStatusException(HttpStatus.NOT_ACCEPTABLE, exception.getMessage());
        }
    }
}
