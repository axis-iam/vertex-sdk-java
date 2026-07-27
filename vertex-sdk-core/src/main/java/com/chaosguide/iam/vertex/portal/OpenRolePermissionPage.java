package com.chaosguide.iam.vertex.portal;
import java.util.List;
public record OpenRolePermissionPage(List<OpenRolePermissionBinding> content, AuthorizationPageMetadata page, String etag) { public OpenRolePermissionPage withEtag(String value) { return new OpenRolePermissionPage(content,page,value); } }
