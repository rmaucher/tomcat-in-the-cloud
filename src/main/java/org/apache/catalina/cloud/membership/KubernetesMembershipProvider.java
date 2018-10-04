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
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URLEncoder;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import org.apache.catalina.cloud.stream.CertificateStreamProvider;
import org.apache.catalina.cloud.stream.TokenStreamProvider;
import org.apache.catalina.tribes.Member;
import org.apache.catalina.tribes.MembershipService;
import org.apache.catalina.tribes.membership.MemberImpl;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.codec.binary.StringUtils;

import com.github.openjson.JSONArray;
import com.github.openjson.JSONException;
import com.github.openjson.JSONObject;
import com.github.openjson.JSONTokener;


public class KubernetesMembershipProvider extends CloudMembershipProvider {
    private static final Log log = LogFactory.getLog(KubernetesMembershipProvider.class);

    private static final String CUSTOM_ENV_PREFIX = "OPENSHIFT_KUBE_PING_";

    @Override
    public void start(int level) throws Exception {
        if ((level & MembershipService.MBR_RX) == 0) {
            return;
        }

        super.start(level);

        // Set up Kubernetes API parameters
        String namespace = getEnv("KUBERNETES_NAMESPACE", CUSTOM_ENV_PREFIX + "NAMESPACE");
        if (namespace == null || namespace.length() == 0)
            throw new RuntimeException("Namespace not set; clustering disabled");

        if (log.isDebugEnabled()) {
            log.debug(String.format("Namespace [%s] set; clustering enabled", namespace));
        }

        String protocol = getEnv("KUBERNETES_MASTER_PROTOCOL", CUSTOM_ENV_PREFIX + "MASTER_PROTOCOL");
        String masterHost = getEnv("KUBERNETES_SERVICE_HOST", CUSTOM_ENV_PREFIX + "MASTER_HOST");
        String masterPort = getEnv("KUBERNETES_SERVICE_PORT", CUSTOM_ENV_PREFIX + "MASTER_PORT");

        String clientCertificateFile = getEnv("KUBERNETES_CLIENT_CERTIFICATE_FILE", CUSTOM_ENV_PREFIX + "CLIENT_CERT_FILE");
        String caCertFile = getEnv("KUBERNETES_CA_CERTIFICATE_FILE", CUSTOM_ENV_PREFIX + "CA_CERT_FILE");
        if (caCertFile == null) {
            caCertFile = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt";
        }

        if (clientCertificateFile == null) {
            if (protocol == null) {
                protocol = "https";
            }
            String saTokenFile = getEnv("SA_TOKEN_FILE", CUSTOM_ENV_PREFIX + "SA_TOKEN_FILE");
            if (saTokenFile == null) {
                saTokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token";
            }
            byte[] bytes = Files.readAllBytes(FileSystems.getDefault().getPath(saTokenFile));
            streamProvider = new TokenStreamProvider(StringUtils.newStringUsAscii(bytes), caCertFile);
        } else {
            if (protocol == null) {
                protocol = "http";
            }
            String clientKeyFile = getEnv("KUBERNETES_CLIENT_KEY_FILE");
            String clientKeyPassword = getEnv("KUBERNETES_CLIENT_KEY_PASSWORD");
            String clientKeyAlgo = getEnv("KUBERNETES_CLIENT_KEY_ALGO");
            if (clientKeyAlgo == null) {
                clientKeyAlgo = "RSA";
            }
            streamProvider = new CertificateStreamProvider(clientCertificateFile, clientKeyFile, clientKeyPassword, clientKeyAlgo, caCertFile);
        }

        String ver = getEnv("KUBERNETES_API_VERSION", CUSTOM_ENV_PREFIX + "API_VERSION");
        if (ver == null)
            ver = "v1";

        String labels = getEnv("KUBERNETES_LABELS", CUSTOM_ENV_PREFIX + "LABELS");

        namespace = URLEncoder.encode(namespace, "UTF-8");
        labels = labels == null ? null : URLEncoder.encode(labels, "UTF-8");

        url = String.format("%s://%s:%s/api/%s/namespaces/%s/pods", protocol, masterHost, masterPort, ver, namespace);
        if (labels != null && labels.length() > 0) {
            url = url + "?labelSelector=" + labels;
        }

        // Fetch initial members
        heartbeat();
    }

    @Override
    public boolean stop(int level) throws Exception {
        try {
            return super.stop(level);
        } finally {
            streamProvider = null;
        }
    }

    @Override
    protected Member[] fetchMembers() {
        if (streamProvider == null) {
            return new Member[0];
        }

        List<MemberImpl> members = new ArrayList<>();

        try (InputStream stream = streamProvider.openStream(url, headers, connectionTimeout, readTimeout)) {
            JSONObject json = new JSONObject(new JSONTokener(new InputStreamReader(stream, "UTF-8")));

            JSONArray items = json.getJSONArray("items");

            for (int i = 0; i < items.length(); i++) {
                String phase;
                String ip;
                String name;
                Instant creationTime;

                try {
                    JSONObject item = items.getJSONObject(i);
                    JSONObject status = item.getJSONObject("status");
                    phase = status.getString("phase");

                    // Ignore shutdown pods
                    if (!phase.equals("Running"))
                        continue;

                    ip = status.getString("podIP");

                    // Get name & start time
                    JSONObject metadata = item.getJSONObject("metadata");
                    name = metadata.getString("name");
                    String timestamp = metadata.getString("creationTimestamp");
                    creationTime = Instant.parse(timestamp);
                } catch (JSONException e) {
                    log.warn("JSON Exception: ", e);
                    continue;
                }

                // We found ourselves, ignore
                if (name.equals(hostName))
                    continue;

                // id = md5(hostname)
                byte[] id = md5.digest(name.getBytes());
                long aliveTime = Duration.between(creationTime, startTime).getSeconds() * 1000; // aliveTime is in ms

                MemberImpl member = null;
                try {
                    member = new MemberImpl(ip, port, aliveTime);
                } catch (IOException e) {
                    // Shouldn't happen:
                    // an exception is thrown if hostname can't be resolved to IP, but we already provide an IP
                    log.warn("Exception: ", e);
                    continue;
                }

                member.setUniqueId(id);
                members.add(member);
            }
        } catch (IOException e) {
            log.warn("Failed stream open", e);
        }

        return members.toArray(new Member[0]);
    }

}
