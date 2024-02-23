package com.google.auth.oauth2;

import org.joda.time.MutableDateTime;
import javax.annotation.concurrent.NotThreadSafe;

/**
 * Holds an mTLS configuration (consists of address of S2A) retrieved from the Metadata Server.
 *
 * Instances of {@link MtlsConfig} are not thread safe. Calls to {@code reset}, {@code getS2AAddress}, {@code isValid}
 * and {@code getExpiry} should be made from a synchronized block. 
 */ 
@NotThreadSafe
public final class MtlsConfig{
	private String s2aAddress;
	private MutableDateTime expiry;

	private static final int MTLS_AUTOCONFIG_EXPIRATION_HOURS = 1;

	public static MtlsConfig createNullMtlsConfig() {
		return new MtlsConfig("", null);
	}

	public static MtlsConfig createMtlsConfig(String addr) {
		MutableDateTime expiry = MutableDateTime.now();
		expiry.addHours(MTLS_AUTOCONFIG_EXPIRATION_HOURS);
		return new MtlsConfig(addr, expiry);	
	}

	public void reset(String addr) {
		this.s2aAddress = addr;
		this.expiry = MutableDateTime.now();
		this.expiry.addHours(MTLS_AUTOCONFIG_EXPIRATION_HOURS);
	}

	public String getS2AAddress() {
		return s2aAddress;
	}

	public boolean isValid() {
		if (expiry == null) { return false; }
		if (MutableDateTime.now().isAfter(this.expiry)) {
			return false;
		}
		return true;
	}
	
	public MutableDateTime getExpiry() {
		return expiry;
	}
	
	private MtlsConfig(String addr, MutableDateTime expiry) {
		this.s2aAddress = addr;
		this.expiry = expiry;
	}
}
