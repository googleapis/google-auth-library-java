package com.google.auth.oauth2.functional;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.auth.http.HttpCredentialsAdapter;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.auth.oauth2.ServiceAccountCredentials;

import java.io.FileInputStream;
import java.io.IOException;
import org.junit.Before;
import org.junit.Test;

public final class ServiceAccountCredentialsTest {
    final String cloudTasksUrl = "https://cloudtasks.googleapis.com/v2/projects/gcloud-devel/locations";
    final String storageUrl = "https://storage.googleapis.com/storage/v1/b";
    
@Test
  public void NoScopeNoAudienceTest() throws Exception {
    final GoogleCredentials credentials = GoogleCredentials.getApplicationDefault();
    
    try {
        GenericUrl genericUrl = new GenericUrl(cloudTasksUrl);
        HttpCredentialsAdapter adapter = new HttpCredentialsAdapter(credentials);
        HttpTransport transport = new NetHttpTransport();
        HttpRequest request = transport.createRequestFactory(adapter).buildGetRequest(genericUrl);
        HttpResponse response = request.execute();
        assertEquals(200, response.getStatusCode());
        //System.out.println( "Hello World! " + response.getStatusCode());
    } catch (IOException e) {
        // TODO Auto-generated catch block
        e.printStackTrace();
    }
  }
}
