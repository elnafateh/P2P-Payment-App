package com.PeerPeerApp.P2P.Payment.App.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {
    private static final String  Secret_Keys="576E5A7234753778214125442A462D4A614E645267556B58703273357638792F423F4528482B4B6250655368566D597133743677397A24432646294A404E6351";

    public String extractUserEmail(String jwt_token) {
        return extractClaim(jwt_token,Claims::getSubject);
    }
    public String generateToken(UserDetails userDetails){
        return generateToken(new HashMap<>(),userDetails);
    }
    public String generateToken(
            Map<String,Object> extraClaims,
            //in case there's a need to store/pass data/authoraties to the token
            UserDetails userDetails
    ){
    return Jwts
            .builder()
            .setClaims(extraClaims)
            .setSubject(userDetails.getUsername())
            .setIssuedAt(new Date(System.currentTimeMillis()))
            .setExpiration(new Date(System.currentTimeMillis()+ 1000*60*24))
            .signWith(getSigningKey(), SignatureAlgorithm.HS512)
            .compact();
    }
    public boolean isTokenValid(String jwt_token,UserDetails userDetails){
        final String userEmail = extractUserEmail(jwt_token);
        return (userEmail.equals(userDetails.getUsername())) && !isTokenExpired(jwt_token);
    }

    private boolean isTokenExpired(String jwtToken) {
        return extractExpiration(jwtToken).before(new Date());
    }

    private Date extractExpiration(String jwtToken) {
        return extractClaim(jwtToken,Claims::getExpiration);
    }

    public <T> T extractClaim(String jwt_token, Function<Claims,T> claimsTFunction){
        final Claims claims=extractAllClaims(jwt_token);
        return claimsTFunction.apply(claims);
    }
    private Claims extractAllClaims(String jwt_token){
        return Jwts
                .parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(jwt_token)
                .getBody();
    }

    private Key getSigningKey() {
        byte[] keyBytes= Decoders.BASE64.decode(Secret_Keys);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
