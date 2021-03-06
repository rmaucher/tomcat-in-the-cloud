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

package org.example.tomcat.cloud;

import java.io.File;
import java.io.IOException;

import org.apache.catalina.Context;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.cloud.CloudMembershipService;
import org.apache.catalina.cloud.membership.KubernetesMembershipProvider;
import org.apache.catalina.ha.tcp.SimpleTcpCluster;
import org.apache.catalina.startup.Tomcat;
import org.apache.catalina.tribes.MembershipProvider;
import org.apache.catalina.tribes.group.GroupChannel;

public class Main {
    public static void main(String[] args) throws LifecycleException, IOException {
        // Embedded Tomcat Configuration:

        try {
            Tomcat tomcat = new Tomcat();
            tomcat.setPort(8080); // HTTP port for Tomcat; make sure to set the same value in pom.xml
            tomcat.getConnector();

            // Servlet Configuration:
            if (args.length > 1 && args[0].equals("--war")) {
                System.out.println("im in !");
                File war = new File(args[1]);
                Context ctx = tomcat.addWebapp("/", war.getAbsolutePath());
                ctx.setDistributable(true);
            }

            // Cluster configuration
            SimpleTcpCluster cluster = new SimpleTcpCluster();
            tomcat.getEngine().setCluster(cluster);

            GroupChannel channel = (GroupChannel) cluster.getChannel();

            // The interesting part: use CloudMembershipService (with KubernetesMembershipProvider)
            MembershipProvider provider = new KubernetesMembershipProvider();
            CloudMembershipService service = new CloudMembershipService();
            service.setMembershipProvider(provider);
            channel.setMembershipService(service);

            // Start Tomcat
            tomcat.start();
            tomcat.getServer().await();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
