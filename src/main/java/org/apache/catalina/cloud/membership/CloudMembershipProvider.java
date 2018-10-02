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

package org.apache.catalina.cloud.membership;

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

import org.apache.catalina.cloud.stream.StreamProvider;
import org.apache.catalina.tribes.Heartbeat;
import org.apache.catalina.tribes.Member;
import org.apache.catalina.tribes.MembershipListener;
import org.apache.catalina.tribes.MembershipService;
import org.apache.catalina.tribes.membership.Membership;
import org.apache.catalina.tribes.membership.MembershipProviderBase;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;

public abstract class CloudMembershipProvider extends MembershipProviderBase implements Heartbeat {
    private static final Log log = LogFactory.getLog(KubernetesMembershipProvider.class);

    protected String url;
    protected StreamProvider streamProvider;
    protected int connectionTimeout;
    protected int readTimeout;

    protected Instant startTime;
    protected MessageDigest md5;

    protected Map<String, String> headers = new HashMap<>();

    protected int port;
    protected String hostName;

    // FIXME: remove after Tomcat 9.0.13
    protected MembershipService service = null;

    public CloudMembershipProvider() {
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

    @Override
    public void start(int level) throws Exception {
        if (membership == null) {
            membership = new Membership(service.getLocalMember(true));
        }
    }

    @Override
    public boolean stop(int level) throws Exception {
        return true;
    }

    // FIXME: remove after Tomcat 9.0.13
    @Override
    public void setMembershipListener(MembershipListener listener) {
        super.setMembershipListener(listener);
        if (listener instanceof MembershipService) {
            service = (MembershipService) listener;
        }
    }

    @Override
    public void heartbeat() {
        log.debug("Fetching announced members");
        Member[] announcedMembers = fetchMembers();
        // Add new members or refresh the members in the membership
        for (Member member : announcedMembers) {
            if (membership.memberAlive(member)) {
                membershipListener.memberAdded(member);
            }
        }
        // Remove non refreshed members from the membership
        Member[] expired = membership.expire(100); // TODO: is 100ms a good value?
        for (Member member : expired) {
            if (log.isDebugEnabled()) {
                log.debug("Member is dead: " + member);
            }
            membershipListener.memberDisappeared(member);
        }
    }

    /**
     * Fetch current cluster members from the cloud orchestration.
     * @return the member array
     */
    protected abstract Member[] fetchMembers();
}
