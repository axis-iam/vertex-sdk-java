package com.example.demo.security;

import com.chaosguide.iam.vertex.authz.PermissionDefinition;
import com.chaosguide.iam.vertex.authz.PermissionKey;

public enum MyAppPermissions implements PermissionDefinition {

    POSTS_READ("posts", "read"),
    POSTS_WRITE("posts", "write");

    private final PermissionKey key;

    MyAppPermissions(String resource, String action) {
        this.key = new PermissionKey(resource, action);
    }

    @Override
    public PermissionKey key() {
        return key;
    }
}
