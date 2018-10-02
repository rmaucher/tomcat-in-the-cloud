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
import java.net.URLEncoder;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import org.apache.catalina.cloud.stream.TokenStreamProvider;
import org.apache.catalina.tribes.Member;
import org.apache.catalina.tribes.MembershipService;
import org.apache.catalina.tribes.membership.MemberImpl;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;


public class KubernetesMembershipProvider extends AbstractMembershipProvider {
    private static final Log log = LogFactory.getLog(KubernetesMembershipProvider.class);

    // TODO: what about "pure" Kubernetes?
    private static final String ENV_PREFIX = "OPENSHIFT_KUBE_PING_";

    @Override
    public void start(int level) throws Exception {
        if ((level & MembershipService.MBR_RX) == 0) {
            return;
        }

        super.start(level);

        // Set up Kubernetes API parameters
        String namespace = getEnv(ENV_PREFIX + "NAMESPACE", "KUBERNETES_NAMESPACE");
        if (namespace == null || namespace.length() == 0)
            throw new RuntimeException("Namespace not set; clustering disabled");

        if (log.isDebugEnabled()) {
            log.debug(String.format("Namespace [%s] set; clustering enabled", namespace));
        }

        String protocol = getEnv(ENV_PREFIX + "MASTER_PROTOCOL", "KUBERNETES_MASTER_PROTOCOL");
        String masterHost = null;
        String masterPort = null;

        String clientCertificateFile = getEnv(ENV_PREFIX + "CLIENT_CERT_FILE", "KUBERNETES_CLIENT_CERTIFICATE_FILE");
        String caCertFile = getEnv(ENV_PREFIX + "CA_CERT_FILE", "KUBERNETES_CA_CERTIFICATE_FILE");
        if (caCertFile == null) {
            caCertFile = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt";
        }

        if (clientCertificateFile == null) {
            if (protocol == null) {
                protocol = "https";
            }

            masterHost = getEnv(ENV_PREFIX + "MASTER_HOST", "KUBERNETES_SERVICE_HOST");
            masterPort = getEnv(ENV_PREFIX + "MASTER_PORT", "KUBERNETES_SERVICE_PORT");
            String saTokenFile = getEnv(ENV_PREFIX + "SA_TOKEN_FILE", "SA_TOKEN_FILE");
            if (saTokenFile == null) {
                saTokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token";
            }

            byte[] bytes = Files.readAllBytes(FileSystems.getDefault().getPath(saTokenFile));
            String saToken = new String(bytes);

            // Preemptively add authorization token in headers
            // (TokenStreamProvider does it too, but too late)
            headers.clear();
            headers.put("Authorization", "Bearer " + saToken);
            streamProvider = new TokenStreamProvider(saToken, caCertFile);
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
            // TODO: implement CertificateStreamProvider
            throw new UnsupportedOperationException();
        }

        String ver = getEnv(ENV_PREFIX + "API_VERSION", "KUBERNETES_API_VERSION");
        if (ver == null)
            ver = "v1";

        String labels = getEnv(ENV_PREFIX + "LABELS", "KUBERNETES_LABELS");

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
            JSONObject json = new JSONObject(new JSONTokener(stream));

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
