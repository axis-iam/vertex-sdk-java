package com.chaosguide.iam.vertex.portal;
public record OpenPermission(String id, String resource, String action, String key, String name, String description, String source, long version, String createdAt, String updatedAt, String etag) { public OpenPermission withEtag(String value) { return new OpenPermission(id,resource,action,key,name,description,source,version,createdAt,updatedAt,value); } }
