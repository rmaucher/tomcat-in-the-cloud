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

package org.apache.tomcat.cloud;

import java.io.IOException;
import java.net.InetAddress;
import java.security.AccessController;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivilegedAction;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.logging.Logger;

import org.apache.catalina.tribes.membership.Membership;
import org.apache.catalina.tribes.membership.MembershipProviderBase;
import org.apache.tomcat.cloud.stream.StreamProvider;

public abstract class AbstractMemberProvider extends MembershipProviderBase {
    private static final Logger log = Logger.getLogger(AbstractMemberProvider.class.getName());

    protected String url;
    protected StreamProvider streamProvider;
    protected int connectionTimeout;
    protected int readTimeout;

    protected Instant startTime;
    protected MessageDigest md5;

    protected Map<String, String> headers = new HashMap<>();

    protected int port;
    protected String hostName;

    public AbstractMemberProvider() {
        try {
            md5 = MessageDigest.getInstance("md5");
        } catch (NoSuchAlgorithmException e) {
            // Ignore
        }
    }

    // Get value of environment variable named keys[0]
    // If keys[0] isn't found, try keys[1], keys[2], ...
    // If nothing is found, return null
    protected static String getEnv(String... keys) {
        String val = null;

        for (String key : keys) {
            val = AccessController.doPrivileged((PrivilegedAction<String>) () -> System.getenv(key));
            if (val != null)
                break;
        }

        return val;
    }

    @Override
    public void init(Properties properties) throws IOException {
        startTime = Instant.now();

        connectionTimeout = Integer.parseInt(properties.getProperty("connectionTimeout", "1000"));
        readTimeout = Integer.parseInt(properties.getProperty("readTimeout", "1000"));

        hostName = InetAddress.getLocalHost().getHostName();
        port = Integer.parseInt(properties.getProperty("tcpListenPort"));
    }

    public void setMembership(Membership membership) {
        this.membership = membership;
    }
}
