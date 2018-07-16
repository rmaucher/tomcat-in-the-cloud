/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.tomcat.cloud.stream;

import java.io.IOException;
import java.io.InputStream;
import java.net.URLConnection;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class InsecureStreamProvider extends AbstractStreamProvider {
    private static final Logger log = Logger.getLogger(InsecureStreamProvider.class.getName());

    static final HostnameVerifier INSECURE_HOSTNAME_VERIFIER = new HostnameVerifier() {
        public boolean verify(String arg0, SSLSession arg1) {
            return true;
        }
    };

    public static final TrustManager[] INSECURE_TRUST_MANAGERS = new TrustManager[] {
        new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {}
            public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {}
            public X509Certificate[] getAcceptedIssuers() {
                return null;
            }
        }
    };

    private final SSLSocketFactory factory;

    public InsecureStreamProvider() throws Exception {
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null,  INSECURE_TRUST_MANAGERS, null);
        factory = context.getSocketFactory();
    }

    public InputStream openStream(String url, Map<String, String> headers, int connectTimeout, int readTimeout) throws IOException {
        URLConnection connection = openConnection(url, headers, connectTimeout, readTimeout);
        if (connection instanceof HttpsURLConnection) {
            HttpsURLConnection httpsConnection = HttpsURLConnection.class.cast(connection);
            httpsConnection.setHostnameVerifier(INSECURE_HOSTNAME_VERIFIER);
            httpsConnection.setSSLSocketFactory(factory);
            if (log.isLoggable(Level.FINE)) {
                log.fine(String.format("Using HttpsURLConnection with SSLSocketFactory [%s] for url [%s].", factory, url));
            }
        } else {
            if (log.isLoggable(Level.FINE)) {
                log.fine(String.format("Using URLConnection for url [%s].", url));
            }
        }
        return connection.getInputStream();
    }

}