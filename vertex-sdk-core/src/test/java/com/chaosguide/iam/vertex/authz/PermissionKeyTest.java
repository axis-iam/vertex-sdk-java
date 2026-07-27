package com.chaosguide.iam.vertex.authz;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PermissionKeyTest {

    @Test
    void toAuthorityJoinsResourceAndAction() {
        assertThat(new PermissionKey("posts", "read").toAuthority()).isEqualTo("posts:read");
    }

    @Test
    void parseRoundTrips() {
        PermissionKey k = PermissionKey.parse("posts:read");
        assertThat(k.resource()).isEqualTo("posts");
        assertThat(k.action()).isEqualTo("read");
    }

    @Test
    void parseRejectsInvalid() {
        assertThatThrownBy(() -> PermissionKey.parse("no-colon"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> PermissionKey.parse(":trailing"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> PermissionKey.parse("leading:"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void blankResourceOrActionRejected() {
        assertThatThrownBy(() -> new PermissionKey("", "read"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new PermissionKey("posts", ""))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
