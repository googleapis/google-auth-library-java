package com.google.auth;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.auth.http.HttpCredentialsAdapter;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.auth.oauth2.IdTokenCredentials;
import com.google.auth.oauth2.IdTokenProvider;
import com.google.auth.oauth2.ServiceAccountCredentials;

public class App 
{
    private static void Runner(int id, IdTokenCredentials credential) {
        System.out.println( "Hello World! #" + id + "  " + Thread.currentThread().getId());
        
        try {
            String serviceUrl = "https://helloworld-qk56ikjwfq-uw.a.run.app";
            GenericUrl genericUrl = new GenericUrl(serviceUrl);
            HttpCredentialsAdapter adapter = new HttpCredentialsAdapter(credential);
            HttpTransport transport = new NetHttpTransport();
            HttpRequest request = transport.createRequestFactory(adapter).buildGetRequest(genericUrl);
            HttpResponse response = request.execute();
            System.out.println( "Hello World! #" + id + "  " + response.getStatusCode());
        } catch (FileNotFoundException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }
    public static void main( String[] args ) throws IOException
    {
        GoogleCredentials credentials;

        credentials = ServiceAccountCredentials.fromStream(new FileInputStream("/Users/stim/Documents/keys/GCP_sandbox.json"))
        .createScoped("foo", "bar");
        String serviceUrl = "https://helloworld-qk56ikjwfq-uw.a.run.app";
        if (!(credentials instanceof IdTokenProvider)) {
            throw new IllegalArgumentException("Credentials are not an instance of IdTokenProvider.");
        }
        final IdTokenCredentials tokenCredential =
            IdTokenCredentials.newBuilder()
                .setIdTokenProvider((IdTokenProvider) credentials)
                .setTargetAudience(serviceUrl)
                .build();
        ScheduledThreadPoolExecutor exec = new ScheduledThreadPoolExecutor(2);
        //null
        exec.schedule(new Runnable() {
            public void run() {
                App.Runner(1, tokenCredential);
            }
        }, 1, TimeUnit.SECONDS);

        // still null
    
        exec.schedule(new Runnable() {
            public void run() {
                App.Runner(2, tokenCredential);
            }
        }, 5, TimeUnit.SECONDS);
        
            // stale
            exec.schedule(new Runnable() {
                public void run() {
                    App.Runner(3, tokenCredential);
                }
            }, 122, TimeUnit.SECONDS);  

            // still stale - should return
            exec.schedule(new Runnable() {
                public void run() {
                    App.Runner(4, tokenCredential);
                }
            }, 127, TimeUnit.SECONDS);  
            
            // fresh
            exec.schedule(new Runnable() {
                public void run() {
                    App.Runner(5, tokenCredential);
                }
            }, 98, TimeUnit.SECONDS);  

             
            // expired
            
            exec.schedule(new Runnable() {
                public void run() {
                    App.Runner(6, tokenCredential);
                }
            }, 428, TimeUnit.SECONDS);  
        }
}
