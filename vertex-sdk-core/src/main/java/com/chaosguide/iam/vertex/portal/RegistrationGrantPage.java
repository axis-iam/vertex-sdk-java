package com.chaosguide.iam.vertex.portal;

import java.util.List;

/** Spring PagedModel response for safe registration-grant results. */
public record RegistrationGrantPage(List<RegistrationGrant> content, RegistrationGrantPageMetadata page) {}
