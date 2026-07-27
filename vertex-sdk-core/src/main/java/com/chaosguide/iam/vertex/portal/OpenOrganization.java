package com.chaosguide.iam.vertex.portal;

/** Application-bound Organization detail. ETag is populated for create/get/update responses. */
public record OpenOrganization(
        String id,
        String name,
        String slug,
        long version,
        String createdAt,
        String updatedAt,
        String etag) {

    OpenOrganization withEtag(String value) {
        return new OpenOrganization(id, name, slug, version, createdAt, updatedAt, value);
    }
}
