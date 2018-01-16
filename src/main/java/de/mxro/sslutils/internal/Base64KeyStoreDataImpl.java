package de.mxro.sslutils.internal;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;

import de.mxro.sslutils.SslKeyStoreData;

public class Base64KeyStoreDataImpl implements SslKeyStoreData{
	
	private final String data;
	private final String password;
	
	@Override
	public String encoding() {
		return "CUSTOMBASE64";
	}

	@Override
	public InputStream asInputStream() {
		 try {
	            return new ByteArrayInputStream(
	                    data.getBytes("UTF-8"));
	        } catch (final UnsupportedEncodingException e) {
	            throw new RuntimeException(e);
	        }
	}

	@Override
	public char[] getCertificatePassword() {
		
		return password.toCharArray();
	}

	@Override
	public char[] getKeyStorePassword() {

		return password.toCharArray();
	}

	public Base64KeyStoreDataImpl(String data, String password) {
		super();
		this.data = data;
		this.password = password;
	}
	
	

}
