package com.chaosguide.iam.vertex.portal;
import java.util.List;
public record OpenPermissionPage(List<OpenPermission> content, AuthorizationPageMetadata page) {}
