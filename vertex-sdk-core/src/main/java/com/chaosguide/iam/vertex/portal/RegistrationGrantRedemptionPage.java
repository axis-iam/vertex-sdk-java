package com.chaosguide.iam.vertex.portal;

import java.util.List;

/** Spring PagedModel response for safe masked redemption history. */
public record RegistrationGrantRedemptionPage(
        List<RegistrationGrantRedemption> content, RegistrationGrantPageMetadata page) {}
