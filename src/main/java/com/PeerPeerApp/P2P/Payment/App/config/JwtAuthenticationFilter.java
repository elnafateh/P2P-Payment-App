package com.PeerPeerApp.P2P.Payment.App.config;

import com.PeerPeerApp.P2P.Payment.App.user.User;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;
    @Override
    protected void doFilterInternal(
                                   @NonNull HttpServletRequest request,
                                   @NonNull HttpServletResponse response,
                                   @NonNull FilterChain filterChain)
            throws ServletException, IOException {
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String authPrefix;
        final String userEmail;
        //jwt token check
        if (authHeader == null || !authHeader.startsWith("Bearer ") ){
            filterChain.doFilter(request,response);
            return;
        }
        //extraction of Jwt from authHeader
        jwt=authHeader.substring(7);
        //extracting useEmail from JWT token
        userEmail= jwtService.extractUserEmail(jwt);
        //check if the userEmail is present but not already Authenticated
        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null){
            //getting UserDetails from th dataBase
            UserDetails userDetails=this.userDetailsService.loadUserByUsername(userEmail);
            //check if the token & userDetails is valid
            if (jwtService.isTokenValid(jwt,userDetails)){
                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );
                authenticationToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            }
        }
        filterChain.doFilter(request,response);

    }
}
