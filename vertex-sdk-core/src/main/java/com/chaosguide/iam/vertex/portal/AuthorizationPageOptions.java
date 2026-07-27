package com.chaosguide.iam.vertex.portal;
public record AuthorizationPageOptions(Integer page, Integer size) { public static AuthorizationPageOptions defaults() { return new AuthorizationPageOptions(0, 20); } }
