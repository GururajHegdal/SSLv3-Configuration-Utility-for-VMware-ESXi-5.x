/**
 * Utility method to automatically enable/disable SSLv3 security protocol on
 * ~ VMware ESXi 5.0 P13 (ESXi500-201606001 release)
 * ~ VMware ESXi 5.1 P09 (ESXi510-201605001 release)
 * ~ VMware ESXi 5.5U3b release
 *
 * Copyright (c) 2016
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation files
 * (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * @author Gururaja Hegdal (ghegdal@vmware.com)
 * @version 1.0
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

package com.vmware.secprotomgmt;

import java.util.Arrays;
import java.util.List;

// Entry point into the ESXi - SSL Security protocol configuration tool
public class RunApp
{
    /**
     * Usage method - how to use/invoke the script, reveals the options supported through this script
     */
    public static void usageSSLScript()
    {
        System.out.println("\n~~~~~~~~~~~~~~~~~~~~~~~~~~ SSLv3 CONFIGURATION (ENABLE/DISABLE) ~~~~~~~~~~~~~~~~~~~~~~~~~~");
        System.out.println(
            "Usage: java -jar secprotomgmt.jar --vsphereip <vc/esxi server IP> --username <uname> --password <pwd> [gethosts] [--hostsinfofile <pathToHostsListfile>] [enablessl] [disablessl]");
        System.out.println("\nExample 1: To obtain hosts file information from vCenter Server");
        System.out.println(
            "\"java -jar secprotomgmt.jar --vsphereip 10.1.2.3 --username adminUser --password dummy gethosts\"");
        System.out.println("\nExample 2: To enable SSLv3 on multiple ESXi hosts");
        System.out.println(
            "\"java -jar secprotomgmt.jar --vsphereip 10.1.2.3 --username adminUser --password dummy --hostsinfofile c:\\SecurityProtoMgmt\\esxihosts.csv enablessl\"");
        System.out.println("\nExample 3: To disable SSLv3 on a SINGLE ESXi host");
        System.out.println(
            "\"java -jar secprotomgmt.jar --vsphereip 10.4.5.6 --username rootUser --password dummyRoot disablessl\"");
     }

    public static void usagePwdEncryptUtility()
    {
        System.out.println("\n~~~~~~~~~~~~~~~~~~~~~~~~~~ ESXi PASSWORD ENCRYPTION UTILITY ~~~~~~~~~~~~~~~~~~~~~~~~~~");
        System.out.println(
            "For encrypting password (incase plain password of ESXi host can NOT be recorded in hostsinfofile), "
            + "use the following utility program");
        System.out.println("\"java -jar passwordEncrypter.jar\"");
        System.out.println(
            "Follow the instructions and record the provided encrypted string into hostsfile."
            + "SSL/TLS configuration utility has capability to decrypt this password with provided SecretKey\n");
    }

    /**
     * Main entry point into the SSL-TLS Script
     */
    public static void main(String[] args) {

        System.out
            .println("######################### SSL Configuration Script execution STARTED #########################");

        // Read command line arguments
        if (args.length > 0 && args.length >= 7) {
            List<String> cmdLineArgs = Arrays.asList(args);
            if (cmdLineArgs.contains("enablessl") || cmdLineArgs.contains("disablessl") ||
                cmdLineArgs.contains("gethosts")) {
                // Request is for SSL configuration
                ESXi5xSSLConfigUpdater sslScript = new ESXi5xSSLConfigUpdater(args);
                if (sslScript.validateProperties()) {
                    sslScript.executeScriptFlow();
                }
            } else {
                usageSSLScript();
                usagePwdEncryptUtility();
            }
        } else {
            usageSSLScript();
            usagePwdEncryptUtility();
        }
        try {
            Thread.sleep(1000 * 2);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        System.out.println(
            "######################### SSL Configuration Script execution completed #########################");
    }
}