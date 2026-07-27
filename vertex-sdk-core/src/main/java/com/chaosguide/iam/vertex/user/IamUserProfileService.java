package com.chaosguide.iam.vertex.user;

import com.chaosguide.iam.vertex.IamSecurityProperties;
import com.chaosguide.iam.vertex.client.IamClient;
import com.chaosguide.iam.vertex.client.dto.UserProfileResponse;
import com.chaosguide.iam.vertex.context.IamContext;
import com.chaosguide.iam.vertex.context.IamCurrentUser;
import com.chaosguide.iam.vertex.exception.IamSdkException;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

/**
 * Explicit current-user profile lookup with a short local cache.
 *
 * <p>Authorization should use {@link IamContext} and resolved authorities. This service is only for
 * callers that need fresher display/profile data from IAM; {@code /api/v1/auth/me.metadata} is
 * profile metadata, not app-scoped authorization attributes.
 */
public class IamUserProfileService {

    private final IamClient client;
    private final IamSecurityProperties props;
    private final Cache<CacheKey, UserProfileResponse> cache;

    public IamUserProfileService(IamClient client, IamSecurityProperties props) {
        this.client = client;
        this.props = props;
        this.cache =
                Caffeine.newBuilder()
                        .maximumSize(Math.max(1, props.getUserProfileCacheMaxSize()))
                        .expireAfterWrite(props.getUserProfileCacheTtl())
                        .build();
    }

    public UserProfileResponse getCurrentProfile() {
        return getCurrentProfile(CachePolicy.DEFAULT);
    }

    public UserProfileResponse getCurrentProfile(CachePolicy policy) {
        IamCurrentUser current = IamContext.requireCurrentUser();
        String token =
                IamContext.currentAccessToken()
                        .orElseThrow(
                                () ->
                                        new IamSdkException(
                                                "current IAM access token is not available"));
        CacheKey key = new CacheKey(current.applicationId(), current.subject());
        if (policy == CachePolicy.BYPASS || !props.isUserProfileCacheEnabled()) {
            UserProfileResponse profile = client.getMe(token);
            cache.put(key, profile);
            return profile;
        }
        return cache.get(key, ignored -> client.getMe(token));
    }

    public void invalidateCurrentProfile() {
        IamCurrentUser current = IamContext.requireCurrentUser();
        cache.invalidate(new CacheKey(current.applicationId(), current.subject()));
    }

    public void invalidateAll() {
        cache.invalidateAll();
    }

    public long estimatedSize() {
        return cache.estimatedSize();
    }

    private record CacheKey(String applicationId, String subject) {
    }
}
