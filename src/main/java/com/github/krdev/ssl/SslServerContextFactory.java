package com.github.krdev.ssl;

import org.eclipse.jetty.util.ssl.SniX509ExtendedKeyManager;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.eclipse.jetty.util.ssl.X509;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.*;
import java.io.IOException;
import java.security.*;
import java.security.cert.CRL;
import java.security.cert.CertificateException;
import java.util.*;

public class SslServerContextFactory extends SslContextFactory {

    final SSLContext theContext;
    final KeyManager theKeyManager;
    final TrustManager theTrustManager;
    final KeyStore theKeyStore;
    Logger logger = LoggerFactory.getLogger(SslServerContextFactory.class);

    public SslServerContextFactory(TrustManager tm, KeyManager km, KeyStore ks) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException, IOException {

        System.out.println("### in c'tor");
        theTrustManager = tm;
        theKeyManager = km;
        theKeyStore = ks;
        theContext = SSLContext.getInstance("TLS");
        theContext.init(new KeyManager[]{ theKeyManager }, new TrustManager[] {theTrustManager}, null);
        setSslContext(theContext);
        setKeyStore(theKeyStore);
        SSLParameters p = new SSLParameters();
        setNeedClientAuth(true);

        // setSNISelector(new MySniSelector());
    }

    @Override
    public SSLSocket newSslSocket() throws IOException {
        logger.error("### newSslSocket " );
        SSLSocket socket = newSslSocket();

        javax.net.ssl.SNIMatcher matcher = new MySniMatcher(); // SNIHostName.createSNIMatcher("*");
        Collection<javax.net.ssl.SNIMatcher> matchers = new ArrayList<>(1);
        matchers.add(matcher);
        SSLParameters params = socket.getSSLParameters();
        params.setSNIMatchers(matchers);
        socket.setSSLParameters(params);


        return socket;
    }

    public TrustManager[] getTrustManagers(KeyStore trustStore, Collection<? extends CRL> crls) throws Exception {
        return new TrustManager[] {theTrustManager};
    }



        static class MySniMatcher extends javax.net.ssl.SNIMatcher {
        Logger logger = LoggerFactory.getLogger(MySniMatcher.class);
        public MySniMatcher() {
            super(0);
        }

        @Override
        public boolean matches(javax.net.ssl.SNIServerName sniServerName) {
            logger.error("### MySniMatcher " + sniServerName);
            return false;
        }
    }


    static class MySniSelector implements SniX509ExtendedKeyManager.SniSelector {

        Logger logger = LoggerFactory.getLogger(MySniSelector.class);
        @Override
        public String sniSelect(String s, Principal[] principals, SSLSession sslSession, String sniHost, Collection<X509> collection) throws SSLHandshakeException {
            logger.error("### sniSelect " + sniHost);
            return null;
        }
    }
}