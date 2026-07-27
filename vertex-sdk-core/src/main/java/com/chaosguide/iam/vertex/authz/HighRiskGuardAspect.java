package com.chaosguide.iam.vertex.authz;

import com.chaosguide.iam.vertex.context.IamContext;
import com.chaosguide.iam.vertex.context.IamCurrentUser;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.springframework.security.access.AccessDeniedException;

/** Enforces high-risk IAM guards such as step-up and no-impersonation checks. */
@Aspect
public class HighRiskGuardAspect {

    @Before("@annotation(require)")
    public void checkStepUpMethod(RequireStepUp require) {
        checkStepUp(require);
    }

    @Before("@within(require)")
    public void checkStepUpClass(RequireStepUp require) {
        checkStepUp(require);
    }

    @Before("@annotation(require)")
    public void checkNoImpersonationMethod(RequireNoImpersonation require) {
        checkNoImpersonation();
    }

    @Before("@within(require)")
    public void checkNoImpersonationClass(RequireNoImpersonation require) {
        checkNoImpersonation();
    }

    private void checkStepUp(RequireStepUp require) {
        IamCurrentUser user = requireUser("@RequireStepUp");
        String requiredAcr = require.acr();
        if (requiredAcr == null || requiredAcr.isBlank()) {
            throw new AccessDeniedException("@RequireStepUp acr must not be blank");
        }
        if (!requiredAcr.equals(user.authenticationContextClass())) {
            throw new AccessDeniedException("Step-up authentication required: " + requiredAcr);
        }
    }

    private void checkNoImpersonation() {
        IamCurrentUser user = requireUser("@RequireNoImpersonation");
        if (user.isImpersonating()) {
            throw new AccessDeniedException("Impersonated sessions are not allowed");
        }
    }

    private IamCurrentUser requireUser(String guard) {
        return IamContext.currentUserOptional()
                .orElseThrow(() -> new AccessDeniedException("Authentication required for " + guard));
    }
}
