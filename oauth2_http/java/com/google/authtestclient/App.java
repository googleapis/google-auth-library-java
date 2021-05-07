package com.google.authtestclient;

import java.io.FileInputStream;
import java.io.IOException;

import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.auth.http.HttpCredentialsAdapter;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.auth.oauth2.IdTokenCredentials;
import com.google.auth.oauth2.IdTokenProvider;

public class App 
{
    public static void main( String[] args ) throws IOException
    {
        GoogleCredentials credentials = GoogleCredentials.fromStream(new FileInputStream("ugly.json"));
        String serviceUrl = "https://helloworld-qk56ikjwfq-uw.a.run.app";
        if (!(credentials instanceof IdTokenProvider)) {
            throw new IllegalArgumentException("Credentials are not an instance of IdTokenProvider.");
          }
          IdTokenCredentials tokenCredential =
              IdTokenCredentials.newBuilder()
                  .setIdTokenProvider((IdTokenProvider) credentials)
                  .setTargetAudience(serviceUrl)
                  .build();
      
          GenericUrl genericUrl = new GenericUrl(serviceUrl);
          HttpCredentialsAdapter adapter = new HttpCredentialsAdapter(tokenCredential);
          HttpTransport transport = new NetHttpTransport();
          HttpRequest request = transport.createRequestFactory(adapter).buildGetRequest(genericUrl);
          HttpResponse response = request.execute();
        System.out.println( "Hello World! " + response.getStatusCode());
    }
}