package com.chaosguide.iam.vertex.portal;

import com.chaosguide.iam.vertex.exception.IamSdkException;

/** Invalid server-side Portal Open API client configuration. */
public class PortalOpenApiConfigException extends IamSdkException {

    public PortalOpenApiConfigException(String message) {
        super(message);
    }
}
