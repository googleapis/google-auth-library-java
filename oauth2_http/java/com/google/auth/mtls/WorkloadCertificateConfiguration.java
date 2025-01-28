package com.google.auth.mtls;

import com.google.api.client.json.GenericJson;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.JsonObjectParser;
import com.google.api.client.json.gson.GsonFactory;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;

public class WorkloadCertificateConfiguration {

  private String certPath;
  private String privateKeyPath;

  public WorkloadCertificateConfiguration(String certPath, String privateKeyPath) {
    this.certPath = certPath;
    this.privateKeyPath = privateKeyPath;
  }

  public String getCertPath() {
    return certPath;
  }

  public String getPrivateKeyPath() {
    return privateKeyPath;
  }

  public static WorkloadCertificateConfiguration fromCertificateConfigurationStream(
      InputStream certConfigStream) throws IOException {
    JsonFactory jsonFactory = GsonFactory.getDefaultInstance();
    JsonObjectParser parser = new JsonObjectParser(jsonFactory);

    GenericJson fileContents =
        parser.parseAndClose(certConfigStream, StandardCharsets.UTF_8, GenericJson.class);

    Map<String, Object> certConfigs = (Map<String, Object>) fileContents.get("cert_configs");
    Map<String, Object> workloadConfig = (Map<String, Object>) certConfigs.get("workload");

    String certPath = (String) workloadConfig.get("cert_path");
    String privateKeyPath = (String) workloadConfig.get("key_path");

    return new WorkloadCertificateConfiguration(certPath, privateKeyPath);
  }
}
