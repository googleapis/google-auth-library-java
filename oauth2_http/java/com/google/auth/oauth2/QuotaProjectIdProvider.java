package com.google.auth.oauth2;

/**
 * Interface for {@link GoogleCredentials} that return a quota project ID.
 */
public interface QuotaProjectIdProvider {
    /**
     * @return the quota project ID used for quota and billing purposes
     */
    String getQuotaProjectId();
}
