package com.storozhuk.decoder;

import java.time.Instant;
import java.util.List;

public record UserInfo(String subject, List<String> roles, List<String> permissions, Instant issuedAt,
                       Instant expirationTime) {

}
