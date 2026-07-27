package com.chaosguide.iam.vertex.portal;
import java.util.List;
public record OpenRolePage(List<OpenRole> content, AuthorizationPageMetadata page) {}
