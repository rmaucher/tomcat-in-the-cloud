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

package org.apache.catalina.cloud;

import java.io.IOException;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.apache.catalina.tribes.Heartbeat;
import org.apache.catalina.tribes.Member;
import org.apache.catalina.tribes.MembershipListener;
import org.apache.catalina.tribes.MembershipProvider;
import org.apache.catalina.tribes.MembershipService;
import org.apache.catalina.tribes.membership.Membership;
import org.apache.catalina.tribes.membership.MembershipServiceBase;
import org.apache.catalina.tribes.membership.StaticMember;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;

public class CloudMembershipService extends MembershipServiceBase implements Heartbeat {
    private static final Log log = LogFactory.getLog(CloudMembershipService.class);

    private MembershipProvider membershipProvider;
    private StaticMember localMember;

    /*
     * Unlike the normal Catalina design, the membership service owns the membership
     * object which allows having more meaningful code in fetchMembers.
     */
    private Membership membership;

    private byte[] payload;
    private byte[] domain;

    public boolean setProperty(String name, String value) {
        return (properties.setProperty(name, value) == null);
    }

    @Override
    public void start(int level) throws Exception {
        if ((level & MembershipService.MBR_RX) == 0)
            return;

        if (membershipProvider == null) {
            String provider = properties.getProperty("membershipProviderClassName", "org.apache.catalina.cloud.membership.KubernetesMembershipProvider");
            if (log.isDebugEnabled()) {
                log.debug("Using membershipProvider: " + provider);
            }
            if ("kubernetes".equals(provider)) {
                provider = "org.apache.catalina.cloud.membership.KubernetesMembershipProvider";
            }
            membershipProvider = (MembershipProvider) Class.forName(provider).newInstance();
        }
        channel.addMembershipListener(this);

        // TODO: check that all required properties are set
        if (log.isDebugEnabled()) {
            log.debug("start(" + level + ")");
        }

        createOrUpdateLocalMember();
        localMember.setMemberAliveTime(100);
        localMember.setPayload(payload);
        localMember.setDomain(domain);
        localMember.setServiceStartTime(System.currentTimeMillis());

        if (membership == null) {
            membership = new Membership(localMember);
        } else {
            membership.reset();
            membership.addMember(localMember);
        }
        try {
            // Invoke setMembership on AbstractMembershipProvider
            Method method = membershipProvider.getClass().getMethod("setMembership", Membership.class);
            method.invoke(membershipProvider, membership);
        } catch (NoSuchMethodException e) {
            log.error("Failed to set Membership on MembershipProvider", e);
        }

        try {
            membershipProvider.init(properties);
            membershipProvider.start(level);
        } catch (Exception e) {
            log.error("Membership provider start failed", e);
        }
        fetchMembers(); // Fetch members synchronously once before starting thread

    }

    @Override
    public void stop(int level) {
        if (log.isDebugEnabled()) {
            log.debug("stop(" + level + ")");
        }
        if ((level & MembershipService.MBR_RX) == 0)
            return;
        try {
            membershipProvider.stop(level);
        } catch (Exception e) {
            log.error("Membership provider stop failed", e);
        }
    }

    private void fetchMembers() {
        if (membershipProvider == null)
            return;

        if (log.isDebugEnabled()) {
            log.debug("fetchMembers()");
        }
        Member[] members = membershipProvider.getMembers();

        if (members == null) {
            // TODO: how to handle this?
            if (log.isDebugEnabled()) {
                log.debug("members == null");
            }
            return;
        }

        if (log.isDebugEnabled()) {
            // Display current list of members
            for (Member member : members) {
                log.debug(member);
            }
            log.debug("===");
        }

        // Add new members & refresh lastHeardFrom timestamp for already known members
        for (Member member : members) {
            if (membership.memberAlive(member)) {
                if (log.isDebugEnabled()) {
                    log.debug("New member: " + member);
                }
                if (channel instanceof MembershipListener) {
                    ((MembershipListener) channel).memberAdded(member);
                }
            }
        }

        // Delete old members, i.e. those that weren't refreshed in the last update
        Member[] expired = membership.expire(100); // TODO: is 100ms a good value?
        for (Member member : expired) {
            if (log.isDebugEnabled()) {
                log.debug("Member is dead: " + member);
            }
            if (channel instanceof MembershipListener) {
                ((MembershipListener) channel).memberDisappeared(member);
            }
        }
    }

    @Override
    public Member getLocalMember(boolean incAliveTime) {
        if (log.isDebugEnabled()) {
            log.debug("getLocalMember: " + incAliveTime);
        }
        if (incAliveTime && localMember != null)
            localMember.setMemberAliveTime(System.currentTimeMillis() - localMember.getServiceStartTime());

        if (log.isDebugEnabled() && localMember != null) {
            log.info("aliveTime: " + localMember.getMemberAliveTime());
        }
        return localMember;
    }

    @Override
    public void setLocalMemberProperties(String listenHost, int listenPort, int securePort, int udpPort) {
        if (log.isDebugEnabled()) {
            log.debug(String.format("setLocalMemberProperties(%s, %d, %d, %d)", listenHost, listenPort, securePort, udpPort));
        }
        properties.setProperty("tcpListenHost", listenHost);
        properties.setProperty("tcpListenPort", String.valueOf(listenPort));
        properties.setProperty("udpListenPort", String.valueOf(udpPort));
        properties.setProperty("tcpSecurePort", String.valueOf(securePort));

        try {
            createOrUpdateLocalMember();

            localMember.setPayload(this.payload);
            localMember.setDomain(this.domain);
            localMember.getData(true, true);
        } catch (IOException e) {
            throw new IllegalArgumentException(e);
        }
    }

    private void createOrUpdateLocalMember() throws IOException {
        String host = properties.getProperty("tcpListenHost");
        int port = Integer.parseInt(properties.getProperty("tcpListenPort"));
        int securePort = Integer.parseInt(properties.getProperty("tcpSecurePort"));
        int udpPort = Integer.parseInt(properties.getProperty("udpListenPort"));

        if (localMember == null) {
            localMember = new StaticMember(host, port, 0);
            try {
                // Set localMember unique ID to md5 hash of hostname
                localMember.setUniqueId(MessageDigest
                        .getInstance("md5")
                        .digest(InetAddress
                                .getLocalHost().getHostName().getBytes()));
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }

            localMember.setLocal(true);
        } else {
            localMember.setHostname(host);
            localMember.setPort(port);
        }

        localMember.setSecurePort(securePort);
        localMember.setUdpPort(udpPort);
        localMember.getData(true, true);
    }

    @Override
    public void setPayload(byte[] payload) {
        this.payload = payload;
        if (localMember != null) {
            localMember.setPayload(payload);
        }
    }

    @Override
    public void setDomain(byte[] domain) {
        this.domain = domain;
        if (localMember != null) {
            localMember.setDomain(domain);
        }
    }

    @Override
    public MembershipProvider getMembershipProvider() {
        return membershipProvider;
    }

    public void setMembershipProvider(MembershipProvider memberProvider) {
        this.membershipProvider = memberProvider;
    }

    @Override
    public void heartbeat() {
        fetchMembers();
    }
}
