package com.github.krdev.ssl;



import org.eclipse.jetty.http.HttpVersion;
import org.eclipse.jetty.server.*;
import org.eclipse.jetty.server.handler.DefaultHandler;
import org.eclipse.jetty.server.handler.HandlerList;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.*;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;

/**
 * @author kraman
 */

public class SslWebServer {

    Logger logger = LoggerFactory.getLogger(SslWebServer.class);
    final X509ExtendedKeyManager theX509KeyManager;
    final SslServerKeyManager myKeyManager;
    final TrustManager theTrustManager;
    final KeyStore theKeyStore;

    public SslWebServer() throws Exception {

        System.out.println("### in c'tor");

        theKeyStore = KeyStore.getInstance("JKS");
        InputStream is = this.getClass().getClassLoader().getResourceAsStream("server.jks");
        theKeyStore.load(is, "kkk333".toCharArray());
        is.close();

        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(theKeyStore, "kkk333".toCharArray());

        KeyManager[] defaultKm = keyManagerFactory.getKeyManagers();
        KeyManager km = defaultKm[0];
        X509ExtendedKeyManager x509KeyManager = null;
        for (KeyManager keyManager : keyManagerFactory.getKeyManagers()) {
            if (keyManager instanceof X509ExtendedKeyManager) {
                x509KeyManager = ((X509ExtendedKeyManager) keyManager);
                break;
            }
        }

        if (x509KeyManager == null) {
            System.out.println(" ### Null keymanager!! ");
            throw new Exception("invalid key managers");
        }

        theX509KeyManager = x509KeyManager;

        // trust manager

        // trust manager
        KeyStore trustKeyStore = KeyStore.getInstance("JKS");
        is = this.getClass().getClassLoader().getResourceAsStream("etc/keystore/athenz_certificate_bundle.jks");
        trustKeyStore.load(is, "changeit".toCharArray());
        is.close();
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("X509");
        trustManagerFactory.init(trustKeyStore);
        theTrustManager = trustManagerFactory.getTrustManagers()[0];

        myKeyManager = new SslServerKeyManager(theX509KeyManager);
    }

    private SslContextFactory createSslContextFactory(String fn) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException, IOException {
       return new SslServerContextFactory(theTrustManager, myKeyManager, theKeyStore);
    }


    public  Server createServer(int port, int secPort) throws Exception {

        logger.error("### create server");
        String fn = "src/main/resources/etc/keystore/server.jks";
        Path keystorePath = Paths.get(fn).toAbsolutePath();
        if (!Files.exists(keystorePath))
            throw new FileNotFoundException(keystorePath.toString());

        HttpConfiguration httpConfig = new HttpConfiguration();
        httpConfig.setSecureScheme("https");
        httpConfig.setSecurePort(secPort);
        httpConfig.setOutputBufferSize(32768);

        SslContextFactory sslContextFactory = createSslContextFactory(fn); // new SslContextFactory.Server();
        Server server = new Server();


        ServerConnector httpConnector = new ServerConnector(server,
                new HttpConnectionFactory(httpConfig));
        httpConnector.setPort(port);
        httpConnector.setIdleTimeout(30000);


        HttpConfiguration httpsConfig = new HttpConfiguration(httpConfig);
        SecureRequestCustomizer src = new SecureRequestCustomizer();
        src.setStsMaxAge(2000);
        src.setStsIncludeSubDomains(true);
        httpsConfig.addCustomizer(src);

        ServerConnector httpsConnector = new ServerConnector(server,
                new SslConnectionFactory(sslContextFactory, HttpVersion.HTTP_1_1.asString()),
                new HttpConnectionFactory(httpsConfig));
        httpsConnector.setPort(secPort);
        httpsConnector.setIdleTimeout(500000);

        server.setConnectors(new Connector[]{httpConnector, httpsConnector});

        // Add the ResourceHandler to the server.
        HandlerList handlers = new HandlerList();
        handlers.setHandlers(new Handler[]{ new DefaultHandler()});
        server.setHandler(handlers);

        return server;
    }


    public static void main (String []args) throws Exception {

        SslWebServer ws = new SslWebServer();
        Server server = ws.createServer(8080, 4443);
        server.start();
        server.join();

    }
}
