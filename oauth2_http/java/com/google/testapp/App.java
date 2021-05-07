package com.google.testapp;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Collections;

import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.client.googleapis.auth.oauth2.GoogleCredential;
import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.http.HttpTransport;
import com.google.api.services.sqladmin.SQLAdmin;
import com.google.api.services.sqladmin.SQLAdminScopes;
import com.google.api.services.sqladmin.model.InstancesListResponse;
import com.google.auth.oauth2.GoogleCredentials;

public class App 
{
    public static void main( String[] args ) throws IOException, GeneralSecurityException
    {
      // GoogleCredentials credentials = GoogleCredentials.fromStream(new FileInputStream("D:/wrk/google-auth-library-java/oauth2_http/java/com/google/testapp/ugly.json"))
      // .createScoped(Collections.singleton(SQLAdminScopes.SQLSERVICE_ADMIN));
      // JsonFactory JSON_FACTORY = JacksonFactory.getDefaultInstance();
      // HttpTransport httpTransport = GoogleNetHttpTransport.newTrustedTransport();
        GoogleCredential credentials = GoogleCredential.fromStream(new FileInputStream("D:/wrk/google-auth-library-java/oauth2_http/java/com/google/testapp/ugly.json"))
        .createScoped(Collections.singleton(SQLAdminScopes.SQLSERVICE_ADMIN));
        JsonFactory JSON_FACTORY = JacksonFactory.getDefaultInstance();
        HttpTransport httpTransport = GoogleNetHttpTransport.newTrustedTransport();
        SQLAdmin sqladmin = new SQLAdmin.Builder(httpTransport, JSON_FACTORY, credentials).build();
      
        InstancesListResponse resp = sqladmin.instances().list("api-6404308174320967819-640900").execute();
        System.out.println( "Hello World! ");
    }
}