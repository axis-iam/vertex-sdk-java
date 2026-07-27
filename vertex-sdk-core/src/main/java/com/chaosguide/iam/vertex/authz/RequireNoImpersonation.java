package com.chaosguide.iam.vertex.authz;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Denies access when the current IAM token contains an {@code act.sub} impersonation actor.
 *
 * <pre>
 * &#64;RequireNoImpersonation
 * public void rotateApiKey(...) { ... }
 * </pre>
 */
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD, ElementType.TYPE})
public @interface RequireNoImpersonation {
}
