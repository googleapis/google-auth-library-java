package com.google.auth.oauth2;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.api.client.http.HttpHeaders;
import com.google.api.client.http.HttpResponseException;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.testing.http.MockLowLevelHttpRequest;
import com.google.api.client.util.GenericData;
import com.google.auth.TestUtils;
import com.google.auth.http.HttpTransportFactory;
import com.google.auth.oauth2.StsTokenExchangeRequest.ActingParty;
import com.google.gson.JsonObject;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests for {@link OAuthException}.
 */
@RunWith(JUnit4.class)
public final class OAuthExceptionTest {
  private static final String FULL_MESSAGE_FORMAT = "Error code %s: %s - %s";
  private static final String ERROR_DESCRIPTION_FORMAT = "Error code %s: %s";
  private static final String BASE_MESSAGE_FORMAT = "Error code %s";

  private static final String ERROR_CODE = "errorCode";
  private static final String ERROR_DESCRIPTION = "errorDescription";
  private static final String ERROR_URI = "errorUri";

  @Test
  public void getMessage_fullFormat() {
    OAuthException e = new OAuthException(ERROR_CODE, ERROR_DESCRIPTION, ERROR_URI);

    assertThat(e.getErrorCode()).isEqualTo(ERROR_CODE);
    assertThat(e.getErrorDescription()).isEqualTo(ERROR_DESCRIPTION);
    assertThat(e.getErrorUri()).isEqualTo(ERROR_URI);

    String expectedMessage =
        String.format(FULL_MESSAGE_FORMAT, ERROR_CODE, ERROR_DESCRIPTION, ERROR_URI);
    assertThat(e.getMessage()).isEqualTo(expectedMessage);
  }

  @Test
  public void getMessage_descriptionFormat() {
    OAuthException e = new OAuthException(ERROR_CODE, ERROR_DESCRIPTION, /* errorUri= */null);

    assertThat(e.getErrorCode()).isEqualTo(ERROR_CODE);
    assertThat(e.getErrorDescription()).isEqualTo(ERROR_DESCRIPTION);
    assertThat(e.getErrorUri()).isNull();

    String expectedMessage =
        String.format(ERROR_DESCRIPTION_FORMAT, ERROR_CODE, ERROR_DESCRIPTION);
    assertThat(e.getMessage()).isEqualTo(expectedMessage);
  }

  @Test
  public void getMessage_baseFormat() {
    OAuthException e = new OAuthException(ERROR_CODE, /* errorDescription= */null, /* errorUri= */
        null);

    assertThat(e.getErrorCode()).isEqualTo(ERROR_CODE);
    assertThat(e.getErrorDescription()).isNull();
    assertThat(e.getErrorUri()).isNull();

    String expectedMessage =
        String.format(BASE_MESSAGE_FORMAT, ERROR_CODE);
    assertThat(e.getMessage()).isEqualTo(expectedMessage);
  }
}
