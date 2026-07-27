package com.chaosguide.iam.vertex.portal;
import java.util.List;
public record OpenRolePermissionSet(String roleId, List<String> permissionIds, long version, String etag) { public OpenRolePermissionSet withEtag(String value) { return new OpenRolePermissionSet(roleId,permissionIds,version,value); } }
