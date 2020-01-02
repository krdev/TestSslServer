package com.github.krdev.ssl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.*;
import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.List;

public class SslServerKeyManager extends X509ExtendedKeyManager {

    final X509ExtendedKeyManager theKeyManager;

    Logger logger = LoggerFactory.getLogger(SslServerKeyManager.class);
    public SslServerKeyManager(X509ExtendedKeyManager km) {
        logger.error ("### key manager c'tor");
        this.theKeyManager = km;
    }


    @Override
    public String[] getClientAliases(String s, Principal[] principals) {

        logger.error("### getClientAliases");
        return this.theKeyManager.getClientAliases(s, principals);
    }

    @Override
    public String chooseClientAlias(String[] strings, Principal[] principals, Socket socket) {

        logger.error("### chooseClientAlias");
        return this.theKeyManager.chooseClientAlias(strings, principals, socket);
    }

    @Override
    public String[] getServerAliases(String s, Principal[] principals) {
        logger.error("### getServerAliases");
        return theKeyManager.getServerAliases(s, principals);
    }

    @Override
    public String chooseServerAlias(String s, Principal[] principals, Socket socket) {
        logger.error("### chooseServerAlias");
        return theKeyManager.chooseServerAlias(s, principals, socket);
    }

    @Override
    public X509Certificate[] getCertificateChain(String s) {
        logger.error("### getCertificateChain");
        return theKeyManager.getCertificateChain(s);
    }

    @Override
    public PrivateKey getPrivateKey(String s) {
        logger.error("### getPrivateKey " + s);
        return theKeyManager.getPrivateKey(s);
    }

    @Override
    public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine) {
        logger.error("### chooseEngineServerAlias " );

        try {
            Certificate[] pcerts = engine.getSession().getPeerCertificates();
            logger.error("###*** chooseEngineServerAlias " + pcerts.length + ", " + pcerts[0]);
        } catch (SSLPeerUnverifiedException e) {
            e.printStackTrace();
        }


        SSLParameters p = engine.getSSLParameters();
        return theKeyManager.chooseEngineServerAlias(keyType, issuers, engine);
    }

    @Override
    public String chooseEngineClientAlias(String[] keyType, Principal[] issuers, SSLEngine engine) {

        logger.error("### chooseEngineClientAlias " );
        try {
            Certificate[] pcerts = engine.getSession().getPeerCertificates();
            logger.error("###*** chooseEngineServerAlias " + pcerts.length + ", " + pcerts[0]);
        } catch (SSLPeerUnverifiedException e) {
            e.printStackTrace();
        }


        return theKeyManager.chooseEngineClientAlias(keyType, issuers, engine);
    }

}

