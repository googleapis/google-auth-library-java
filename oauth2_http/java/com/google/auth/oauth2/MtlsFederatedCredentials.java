package com.google.auth.oauth2;

import com.google.api.client.googleapis.mtls.MtlsProvider;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpContent;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.json.JsonHttpContent;
import com.google.api.client.json.JsonObjectParser;
import com.google.api.client.util.GenericData;
import com.google.auth.http.MtlsHttpTransportFactory;
import com.google.common.collect.ImmutableMap;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Map;

public class MtlsFederatedCredentials extends GoogleCredentials{
  private static final String IAM_CREDENTIALS_SERVICE_ADDRESS =
      "https://iamcredentials.mtls.googleapis.com/v1/projects/-/serviceAccounts/";
  private static final String RFC3339 = "yyyy-MM-dd'T'HH:mm:ssX";
  private static final int DEFAULT_LIFETIME_IN_SECONDS = 3600;

  private final OAuth2Credentials sourceCredentials;
  private final String serviceAccountEmail;
  private final List<String> scopes;
  private final MtlsHttpTransportFactory mtlsHttpTransportFactory;
  private final MtlsProvider mtlsProvider;

  private final Calendar calendar;

  public MtlsFederatedCredentials(
      OAuth2Credentials sourceCredentials, String serviceAccountEmail,
      List<String> scopes,
      MtlsHttpTransportFactory mtlsHttpTransportFactory,
      MtlsProvider mtlsProvider, Calendar calendar) {
    this.sourceCredentials = sourceCredentials;
    this.serviceAccountEmail = serviceAccountEmail;
    this.scopes = scopes;
    this.mtlsHttpTransportFactory = mtlsHttpTransportFactory;
    this.mtlsProvider = mtlsProvider;
    this.calendar = calendar;
  }

  @Override
  public AccessToken refreshAccessToken() throws IOException {

    HttpTransport httpTransport = null;
    try {
      httpTransport = this.mtlsHttpTransportFactory.newTrustedTransport(mtlsProvider);
    } catch (GeneralSecurityException e) {
      e.printStackTrace();
    }
    JsonObjectParser parser = new JsonObjectParser(OAuth2Utils.JSON_FACTORY);

    HttpRequestFactory requestFactory = httpTransport.createRequestFactory();
    GenericUrl url = new GenericUrl(
        IAM_CREDENTIALS_SERVICE_ADDRESS + serviceAccountEmail + ":generateAccessToken");

    Map<String, Object> body =
        ImmutableMap.<String, Object>of(
            "scope", this.scopes, "lifetime", DEFAULT_LIFETIME_IN_SECONDS + "s");

    HttpContent requestContent = new JsonHttpContent(parser.getJsonFactory(), body);

    HttpRequest request = requestFactory.buildPostRequest(url, requestContent);
    request.setParser(parser);

    HttpResponse response = null;
    try {
      response = request.execute();
    } catch (IOException e) {
      throw new IOException("Error requesting access token", e);
    }

    GenericData responseData = response.parseAs(GenericData.class);
    response.disconnect();

    String accessToken =
        OAuth2Utils.validateString(responseData, "accessToken", "Expected to find an accessToken");
    String expireTime =
        OAuth2Utils.validateString(responseData, "expireTime", "Expected to find an expireTime");

    DateFormat format = new SimpleDateFormat(RFC3339);
    format.setCalendar(calendar);
    try {
      Date date = format.parse(expireTime);
      return new AccessToken(accessToken, date);
    } catch (ParseException pe) {
      throw new IOException("Error parsing expireTime: " + pe.getMessage());
    }
  }

  public static Builder newBuilder() {
    return new Builder();
  }

  public static class Builder extends GoogleCredentials.Builder {
    private OAuth2Credentials sourceCredentials;
    private String serviceAccountEmail;
    private List<String> scopes;
    private MtlsHttpTransportFactory mtlsHttpTransportFactory;
    private MtlsProvider mtlsProvider;
    private Calendar calendar = Calendar.getInstance();

    protected Builder() {}

    public OAuth2Credentials getSourceCredentials() {
      return sourceCredentials;
    }

    public Builder setSourceCredentials(OAuth2Credentials sourceCredentials) {
      this.sourceCredentials = sourceCredentials;
      return this;
    }

    public String getServiceAccountEmail() {
      return serviceAccountEmail;
    }

    public Builder setServiceAccountEmail(String serviceAccountEmail) {
      this.serviceAccountEmail = serviceAccountEmail;
      return this;
    }

    public List<String> getScopes() {
      return scopes;
    }

    public Builder setScopes(List<String> scopes) {
      this.scopes = scopes;
      return this;
    }

    public MtlsHttpTransportFactory getMtlsHttpTransportFactory() {
      return mtlsHttpTransportFactory;
    }

    public Builder setMtlsHttpTransportFactory(
        MtlsHttpTransportFactory mtlsHttpTransportFactory) {
      this.mtlsHttpTransportFactory = mtlsHttpTransportFactory;
      return this;
    }

    public MtlsProvider getMtlsProvider() {
      return mtlsProvider;
    }

    public Builder setMtlsProvider(MtlsProvider mtlsProvider) {
      this.mtlsProvider = mtlsProvider;
      return this;
    }

    public Calendar getCalendar() {
      return calendar;
    }

    public Builder setCalendar(Calendar calendar) {
      this.calendar = calendar;
      return this;
    }
  }
  public MtlsFederatedCredentials build() {
    return new MtlsFederatedCredentials(sourceCredentials, serviceAccountEmail, scopes,
        mtlsHttpTransportFactory, mtlsProvider, calendar);
  }
}
