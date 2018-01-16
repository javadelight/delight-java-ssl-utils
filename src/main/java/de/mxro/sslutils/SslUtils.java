package de.mxro.sslutils;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Enumeration;
import java.util.IdentityHashMap;
import java.util.Map;

import javax.net.ssl.SSLContext;

import de.mxro.sslutils.internal.Base64KeyStoreDataImpl;
import de.mxro.sslutils.internal.SslContextFactory;

public class SslUtils {

	public static Map<SslKeyStoreData, SSLContext> cache;

	static {
		cache = new IdentityHashMap<SslKeyStoreData, SSLContext>();
	}

	public static SSLContext createContextForCertificate(final SslKeyStoreData keyStoreData) {
		if (cache.containsKey(keyStoreData)) {
			return cache.get(keyStoreData);
		}

		final SSLContext newContext = SslContextFactory.getServerContext(keyStoreData);

		cache.put(keyStoreData, newContext);

		return newContext;
	}

	public static KeyStore createKeyStore(SslKeyStoreData keyStoreData) {
		return SslContextFactory.getKeyStore(keyStoreData);
	}

	public static long getDaysUntilExpiry(SslKeyStoreData keyStoreData) {
		KeyStore keystore = createKeyStore(keyStoreData);
		Enumeration aliases;
		try {
			aliases = keystore.aliases();

			for (; aliases.hasMoreElements();) {
				String alias = (String) aliases.nextElement();
				Date certExpiryDate = ((X509Certificate) keystore.getCertificate(alias)).getNotAfter();
				
				Date today = new Date();
				long dateDiff = certExpiryDate.getTime() - today.getTime();
				long expiresIn = dateDiff / (24 * 60 * 60 * 1000);
				
				return expiresIn;
				
			}
		} catch (KeyStoreException e) {
			throw new RuntimeException(e);
		}
		return -1;
	}

	public static SslKeyStoreData createBase64KeyStoreData(String data, String password) {
		return new Base64KeyStoreDataImpl(data, password);
	}

}
