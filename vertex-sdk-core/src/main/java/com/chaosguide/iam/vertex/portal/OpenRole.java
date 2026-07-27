package com.chaosguide.iam.vertex.portal;
public record OpenRole(String id, String key, String name, String description, boolean system, long version, String createdAt, String updatedAt, String etag) { public OpenRole withEtag(String value) { return new OpenRole(id,key,name,description,system,version,createdAt,updatedAt,value); } }
