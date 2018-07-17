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

package org.apache.tomcat.cloud.membership;

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

    private StaticMember localMember;
    private Membership membership;

    private MembershipProvider memberProvider;

    private byte[] payload;
    private byte[] domain;

    @Override
    public void start(int level) throws Exception {
        if ((level & MembershipService.MBR_RX) == 0)
            return;

        if (memberProvider == null) {
            String provider = properties.getProperty("membershipProvider", "org.apache.tomcat.cloud.KubernetesMemberProvider");
            if ("kubernetes".equals(provider)) {
                provider = "org.apache.tomcat.cloud.KubernetesMemberProvider";
            }
            memberProvider = (MembershipProvider) Class.forName(provider).newInstance();
        }
        try {
            // Invoke setMembership on AbstractMemberProvider
            Method method = memberProvider.getClass().getMethod("setMembership", Membership.class);
            method.invoke(memberProvider, membership);
        } catch (NoSuchMethodException e) {
            log.info("Failed to set Membership on MembershipProvider", e);
        }

        // TODO: check that all required properties are set
        log.info("start(" + level + ")");

        if (membership == null) {
            membership = new Membership(localMember);
        } else {
            membership.reset();
        }

        createOrUpdateLocalMember();
        localMember.setMemberAliveTime(100);
        localMember.setPayload(payload);
        localMember.setDomain(domain);
        localMember.setServiceStartTime(System.currentTimeMillis());

        memberProvider.init(properties);
        fetchMembers(); // Fetch members synchronously once before starting thread

    }

    @Override
    public void stop(int level) {
        log.info("stop(" + level + ")");
        if ((level & MembershipService.MBR_RX) == 0)
            return;
    }

    private void fetchMembers() {
        if (memberProvider == null)
            return;

        log.info("fetchMembers()");
        Member[] members = memberProvider.getMembers();

        if (members == null) {
            // TODO: how to handle this?
            log.info("members == null");
            return;
        }

        // Display current list of members
        for (Member member : members) {
            log.info(member);
        }
        log.info("===");

        // Add new members & refresh lastHeardFrom timestamp for already known members
        for (Member member : members) {
            if (membership.memberAlive(member)) {
                log.info("New member: " + member);
                if (channel instanceof MembershipListener) {
                    ((MembershipListener) channel).memberAdded(member);
                }
            }
        }

        // Delete old members, i.e. those that weren't refreshed in the last update
        Member[] expired = membership.expire(100); // TODO: is 100ms a good value?
        for (Member member : expired) {
            log.info("Member is dead: " + member);
            if (channel instanceof MembershipListener) {
                ((MembershipListener) channel).memberDisappeared(member);
            }
        }
    }

    @Override
    public Member getLocalMember(boolean incAliveTime) {
        log.info("getLocalMember: " + incAliveTime);
        if (incAliveTime && localMember != null)
            localMember.setMemberAliveTime(System.currentTimeMillis() - localMember.getServiceStartTime());

        if (localMember != null)
            log.info("aliveTime: " + localMember.getMemberAliveTime());
        return localMember;
    }

    @Override
    public void setLocalMemberProperties(String listenHost, int listenPort, int securePort, int udpPort) {
        log.info(String.format("setLocalMemberProperties(%s, %d, %d, %d)", listenHost, listenPort, securePort, udpPort));
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
        return memberProvider;
    }

    public void setMembershipProvider(MembershipProvider memberProvider) {
        this.memberProvider = memberProvider;
    }

    @Override
    public void heartbeat() {
        fetchMembers();
    }
}