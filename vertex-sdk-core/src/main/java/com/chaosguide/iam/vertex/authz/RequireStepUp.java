package com.chaosguide.iam.vertex.authz;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Requires the current IAM access token to carry the requested authentication context class.
 *
 * <pre>
 * &#64;RequireStepUp(acr = "urn:iam:acr:mfa")
 * public TransferResult approveTransfer(...) { ... }
 * </pre>
 */
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD, ElementType.TYPE})
public @interface RequireStepUp {

    /** Required JWT {@code acr} claim value. Defaults to the IAM MFA ACR. */
    String acr() default "urn:iam:acr:mfa";
}
