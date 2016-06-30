/**
 * Utility method to enable/disable SSLv3 security protocol
 * on VMware ESXi 5.0 P13 / 5.1 P09 / 5.5U3b (P07).
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

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.regex.Pattern;

import com.vmware.vim25.HostRuntimeInfo;
import com.vmware.vim25.HostService;
import com.vmware.vim25.HostSystemConnectionState;
import com.vmware.vim25.mo.HostServiceSystem;
import com.vmware.vim25.mo.HostSystem;
import com.vmware.vim25.mo.InventoryNavigator;
import com.vmware.vim25.mo.ManagedEntity;
import com.vmware.vim25.mo.ServiceInstance;

import ch.ethz.ssh2.Connection;

public class ESXi5xSSLConfigUpdater
{
    private String vsphereIp;
    private String userName;
    private String password;
    private boolean getHosts;
    private String hostsInfoFileLocation;
    private String url;
    private ServiceInstance si;

    // Supported release versions of 55 for SSLv3 enablement
    private final String SUPPORTED_55P07_VERSION = "5.5.0";
    private final Integer SUPPORTED_55P07_UPDATE_VER = 3; // Update 3 and above
    private final Integer SUPPORTED_55P07_BUILD_NUMBER = 3248547; // GA 5.5U3b (P07)

    // Supported release versions of 5.1 for SSLv3 enablement
    private final String SUPPORTED_51_VERSION = "5.1.0";
    private final Integer SUPPORTED_51_UPDATE_VER = 3; // Update 3 and above
    private final Integer SUPPORTED_51_BUILD_NUMBER = 3872664; // GA 5.1P09 (ESXi510-201605001)

    // Supported release versions of 5.0 for SSLv3 enablement
    private final String SUPPORTED_50_VERSION = "5.0.0";
    private final Integer SUPPORTED_50_UPDATE_VER = 3; // Update 3 and above
    private final Integer SUPPORTED_50_BUILD_NUMBER = 3982828; // GA 5.0P13 (ESXi500-201606001)

    // Configuration files of services
    private final String RHTTPPROXY_CONFIG_FILE = "/etc/vmware/rhttpproxy/config.xml";
    private final String RHTTPPROXY_CONFIG_BACKUP_FILE = "/etc/vmware/rhttpproxy/config.xml.bkup";
    private final String SFCBD_CONFIG_FILE = "/etc/sfcb/sfcb.cfg";
    private final String SFCBD_CONFIG_BACKUP_FILE = "/etc/sfcb/sfcb.cfg.bkup";
    private final String SFCBD_SSLV3 = "enableSSLv3";

    // List of services
    private final String SERVICE_RHTTPPROXY = "/etc/init.d/rhttpproxy";
    private final String SERVICE_HOSTD = "/etc/init.d/hostd";
    private final String SERVICE_VSAN_VP = "/etc/init.d/vsanvpd";
    private final String SERVICE_SFCBD = "/etc/init.d/sfcbd-watchdog";

    // Commands for TLS protocol configuration on various services
    private final String SET_CMD = "esxcli system settings advanced set -o ";
    private final String LIST_CMD = "esxcli system settings advanced list -o ";

    private final String CMD_RHTTP_PROXY = SET_CMD + "/UserVars/ESXiRhttpproxyDisabledProtocols -s ";
    private final String CMD_RHTTP_PROXY_51 = SET_CMD + "/UserVars/ESXiRhttpproxyDisabledProtocols51 -s ";

    // On 5.0 its Hostd service that takes all incoming request on ESXi
    private final String CMD_HOSTD = SET_CMD + "/UserVars/ESXiHostdDisabledProtocols -s ";

    private final String CMD_VSAN_VP = SET_CMD + "/UserVars/ESXiVPsDisabledProtocols -s ";
    private final String CMD_AUTHD = SET_CMD + "/UserVars/VMAuthdDisabledProtocols -s ";
    private final String CMD_AUTHD_LIST_PROTOS = LIST_CMD + "/UserVars/VMAuthdDisabledProtocols";

    private final String CMD_AUTHD_51 = SET_CMD + "/UserVars/VMAuthdDisabledProtocols51 -s ";
    private final String CMD_AUTHD_LIST_PROTOS_51 = LIST_CMD + "/UserVars/VMAuthdDisabledProtocols51";

    private final String CMD_AUTHD_50 = SET_CMD + "/UserVars/VMAuthdDisabledProtocols50 -s ";
    private final String CMD_AUTHD_LIST_PROTOS_50 = LIST_CMD + "/UserVars/VMAuthdDisabledProtocols50";

    private final String CMD_VERSION_CHECK = "esxcli system version get";

    // Security protocol strings
    private final String PROTO_SSLV3 = "sslv3";
    private final String PROTO_TLS10 = "tlsv1";
    private final String PROTO_TLS11 = "tlsv1.1";
    private final String PROTO_TLS12 = "tlsv1.2";

    // Decimal value to Enable SSLv3, along with TLSv1,1.1,1.2
    private final String CONFIG_OPT_NEW_ENTRY_VALUE = "16924672";

    private final String SSL_OPTIONS_TAG = "sslOptions";

    // TLSv1.0 protocol as seen by TestSSLServer open source tool
    private final String TESTSSLSERVER_PROTO_TLS10 = "TLSv1.0";

    private List<String> defaultSecProtoList;

    /*
     * Map of Port & Protocols 'about to be' enabled. This would be used for
     * cleanup process
     */
    private Map<Integer, List<String>> enabledInpSecProtoMap = null;

    // SSH service
    private final String SSH_SERVICE = "TSM-SSH";
    private String SERVICE_RUNNING = "on";
    private String SERVICE_STOPPED = "off";
    private boolean cleanupStopSSHService = false;
    private static Connection sshConnObjCurrentHost;
    private static HostSystem currentHostSys;
    private static String currentHostName;

    // VC inventory related objects
    public static final String DC_MOR_TYPE = "Datacenter";
    public static final String CLUSTER_COMPRES_MOR_TYPE = "ClusterComputeResource";
    public static final String VC_ROOT_TYPE = "VCRoot";
    public static final String HOST_MOR_TYPE = "HostSystem";
    public static final String VM_MOR_TYPE = "VirtualMachine";

    /*
     * Services and their Port numbers
     */
    // RHTTP proxy, hostd
    private final int RHTTP_PROXY_PORT = 443;

    // Authd - VMRC/NFC/VIClient/VC
    private final int AUTHD_PORT = 902;

    // SFCBD - Configuration for CIM
    private final int SFCBD_PORT = 5989;

    // vSAN VP
    private final int VSAN_VP_PORT = 8080;

    // Map Port -> Service Name
    public final Map<Integer, String> portToServiceNameMap = new HashMap<Integer, String>() {{
        put(RHTTP_PROXY_PORT,"RHTTPPROXY/HOSTD");
        put(AUTHD_PORT,"AUTHD");
        put(SFCBD_PORT,"SFCBD");
        put(VSAN_VP_PORT,"VSAN_VP");
    }};

    private String tls_protos_enable;
    private Boolean enableSsl;
    private ArrayList<String> secProtosToEnable;
    private File existingFilePtr;
    private boolean disableESXiVerCheck;
    private boolean isStandAloneHost;
    private boolean is51Host;
    private boolean is50Host;

    /*
     * Nested map to store result of host's-all port's TLS configuration information
     * <<PortNumber>, <Before-TLS-Protocols, After-TLS-Protocols>
     */
    private HashMap<String, List<HostSSLResultHolderClass>> hostSSLconfigResultHolderObj;


    /**
     * Constructor
     */
    public ESXi5xSSLConfigUpdater(String[] cmdProps)
    {
        makeProperties(cmdProps);
    }

    /**
     * Default constructor
     */
    public ESXi5xSSLConfigUpdater()
    {
        //Placeholder
    }

    /**
     * Read properties from command line arguments
     */
    private void
    makeProperties(String[] cmdProps)
    {
        // get the property value and print it out
        System.out.println("Reading vSphere IP and Credentials information from command line arguments");
        System.out.println("-------------------------------------------------------------------");

        for (int i = 0; i < cmdProps.length; i++) {
            if (cmdProps[i].equals("--vsphereip")) {
                vsphereIp = cmdProps[i + 1];
                System.out.println("vSphere IP:" + vsphereIp);
            } else if (cmdProps[i].equals("--username")) {
                userName = cmdProps[i + 1];
                System.out.println("Username:" + userName);
            } else if (cmdProps[i].equals("--password")) {
                password = cmdProps[i + 1];
                System.out.println("password: ******");
            } else if (cmdProps[i].equals("gethosts")) {
                getHosts = true;
                System.out.println("Retrieve Hosts information: true");
            } else if (cmdProps[i].equals("--hostsinfofile")) {
                hostsInfoFileLocation = cmdProps[i + 1];
                System.out.println("Hosts information file:" + hostsInfoFileLocation);
            } else if (cmdProps[i].equals("enablessl")) {
                tls_protos_enable = PROTO_SSLV3 + "," + PROTO_TLS10 + "," + PROTO_TLS11 + "," + PROTO_TLS12;
                enableSsl = true;
                System.out.println("SSLv3 Protocol : Enable");
            } else if (cmdProps[i].equals("disablessl")) {
                tls_protos_enable = PROTO_TLS10 + "," + PROTO_TLS11 + "," + PROTO_TLS12;
                enableSsl = false;
                System.out.println("SSLv3 Protocol : Disable");
            } else if (cmdProps[i].equals("disableversioncheck")) {
                disableESXiVerCheck = true;
            }
        }
        System.out.println("-------------------------------------------------------------------\n");
    }

    /**
     * Validate property values
     */
    boolean
    validateProperties()
    {
        boolean val = false;

        if (!getHosts && !enableSsl) {
            boolean warningAccepted = false;
            Scanner sc = new Scanner(System.in);
            try {

                System.out.println("\n * * * * * * * * * * * W A R N I N G * * * * * * * * * * *");
                System.out.println(
                    "Disabling SSLv3 protocol might break VC/ESXi product interoperability and with"
                        + " Solutions that are on top of vSphere. \nPlease refer to compatibility guide, before proceeding\n");

                System.out.print("Would you like to continue? Please enter [Yes/No] ...: ");
                String readInput = sc.next();
                String proceed = "yes";
                if (proceed.equalsIgnoreCase(readInput)) {
                    System.out.println("\nContinuing the script execution ...");
                    warningAccepted = true;
                } else {
                    System.out.println("\nEnding the script execution");
                }
            } catch (Exception e) {
                System.err.println("Error occurred while reading input. Please try again...");
                e.printStackTrace();
            }
            sc.reset();
            if (!warningAccepted) {
                return false;
            }
        }

        if (vsphereIp != null) {
            url = "https://" + vsphereIp + "/sdk";

            // Login to provided server IP to determine if we are running against single ESXi
            try {
                System.out.println("Logging into vSphere : " + vsphereIp + ", with provided credentials");
                si = loginTovSphere(url);

                if (si != null) {
                    System.out.println("Succesfully logged into vSphere: " + vsphereIp);

                    if (si.getAboutInfo().getApiType().equalsIgnoreCase("HostAgent")) {
                        // We are running against single ESXi server
                        isStandAloneHost = true;
                    }
                    val = true;
                } else {
                    System.err.println(
                        "Service Instance object for vSphere:" + vsphereIp + " is null, probably we failed to login");
                    printFailedLoginReasons();
                    val = false;
                }
            } catch (Exception e) {
                System.err.println("Caught an exception, while logging into vSphere :" + vsphereIp + " with provided credentials");
                printFailedLoginReasons();
                val = false;
            }

            if (!getHosts && val) {
                if (tls_protos_enable != null) {
                    this.secProtosToEnable = new ArrayList<String>();
                    if (enableSsl) {
                        this.secProtosToEnable.add(PROTO_SSLV3);
                        this.secProtosToEnable.add(PROTO_TLS10);
                        this.secProtosToEnable.add(PROTO_TLS11);
                        this.secProtosToEnable.add(PROTO_TLS12);
                        val = true;
                    } else {
                        this.secProtosToEnable.add(PROTO_TLS10);
                        this.secProtosToEnable.add(PROTO_TLS11);
                        this.secProtosToEnable.add(PROTO_TLS12);
                        val = true;
                    }
                } else {
                    System.err.println("SSL Protocol to enable or disable property is null. See below the usage of script");
                    RunApp.usageSSLScript();
                    RunApp.usagePwdEncryptUtility();
                    val = false;
                }

                // Check if file consisting of ESXi hosts information is provided
                if (val) {
                    if (hostsInfoFileLocation != null) {
                        // FileHandling operation -- validate if provided file indeed exists
                        existingFilePtr = new File(hostsInfoFileLocation);
                        if (existingFilePtr.canRead()) {
                            System.out.println("Found the provided hosts information file: " + hostsInfoFileLocation);
                            val = true;
                        } else {
                            System.err.println(
                                "Could not find/read the provided hosts information file: " + hostsInfoFileLocation);
                            System.err.println("Please check if file really exists and is read'able");
                            val = false;
                        }
                    } else if (isStandAloneHost) {
                        // Its a single ESXi host, on which we have to carry out TLS toggling. No need of
                        // hosts information file. We will validate this later.
                        val = true;
                    } else {
                        System.err.println(
                            "Hosts file information is not provided for applying SSL configurations. See below the usage of script");
                        RunApp.usageSSLScript();
                        RunApp.usagePwdEncryptUtility();
                        val = false;
                    }
                }
            } else if (getHosts && val) {
                System.out.println("Request is to fetch ESXi hosts information");
                val = true;
            }
        } else {
            System.err.println("VC IP is null. See below the usage of script");
            RunApp.usageSSLScript();
            RunApp.usagePwdEncryptUtility();
        }

        Scanner sc = new Scanner(System.in);
        try {
            /*
             * @internal
             * ALERT customer that they have chosen to disable VERSION check
             */
            if (val && disableESXiVerCheck) {
                System.out.println("* * * * * * * * * * * A L E R T : Version Check Disabled * * * * * * * * * * *");
                System.out.println(
                    "You have chosen to disable version check. You might end up running the script on unsupported ESXi hosts");
                System.out.println(
                    "This might lead to environment inconsistencies, such as ESXi services not coming up, host getting disconnected from VC and etc");
                System.out.print("Are you sure to continue? Please enter [Yes/No]...: ");
                String readInput = sc.next();
                String proceed = "yes";
                if (proceed.equalsIgnoreCase(readInput)) {
                    System.out.println("\nContinuing the script execution ...");
                    val = true;
                } else {
                    System.out.println("\nEnding the script execution");
                    val = false;
                }
            }
        } catch (Exception e) {
            System.err.println("Error occurred while reading input. Please try again...");
            e.printStackTrace();
            val = false;
        } finally {
            sc.reset();
        }
        return val;
    }

    /**
     * Method prints out possible reasons for failed login
     */
    private void printFailedLoginReasons()
    {
        System.err.println(
            "Possible reasons:\n1. Provided username/password credentials are incorrect\n"
                + "2. If username/password or other fields contain special characters, surround them with double "
                + "quotes and for non-windows environment with single quotes (Refer readme doc for more information)\n"
                + "3. vCenter Server/ESXi server might not be reachable");
    }

    /**
     * Core method to start off SSL Configuration
     */
    public boolean
    executeScriptFlow()
    {
        hostSSLconfigResultHolderObj = new HashMap<String, List<HostSSLResultHolderClass>>();

        try {
            if (si != null) {
                List<HostInfoHelper.HostsInfoHolderClass> hostsListFromFile = null;
                if (getHosts) {
                    System.out.println("Try to retrieve ESXi hosts information from VC ...");
                    List<HostSystem> allHostSys = retrieveHosts();
                    if (allHostSys != null && allHostSys.size() > 0) {
                        // Create hosts file information, if the request be and
                        // return back to the caller
                        return HostInfoHelper.createHostsInformationFile(allHostSys);
                    } else {
                        System.err.println(
                            "Could not retrieve hosts from VC:" + vsphereIp
                                + ", Either all hosts are NOT in connected state, or we failed retrieving hosts");
                        return false;
                    }
                } else {
                    if (isStandAloneHost) {
                        hostsListFromFile = new ArrayList<HostInfoHelper.HostsInfoHolderClass>();
                        HostInfoHelper.HostsInfoHolderClass tempSingleHostInfoObject = new HostInfoHelper.HostsInfoHolderClass();
                        HostSystem tempSingleHostSys = retrieveSingleHostSys(vsphereIp);
                        if (tempSingleHostSys != null) {
                            tempSingleHostInfoObject.hostName = vsphereIp;
                            tempSingleHostInfoObject.hostSys = tempSingleHostSys;
                            tempSingleHostInfoObject.hostVer = tempSingleHostSys.getConfig().getProduct().getFullName();
                            tempSingleHostInfoObject.username = userName;
                            tempSingleHostInfoObject.password = password;
                            // Write the object information into list
                            hostsListFromFile.add(tempSingleHostInfoObject);
                        } else {
                            System.err.println("Unable to obtain ESXi hosts HostSystem object");
                            return false;
                        }
                    } else {
                        // read hosts file information, to know on what all hosts
                        // SSL configuration need to be done
                        System.out.println("Retrieve ESXi hosts information from file ...");

                        List<HostInfoHelper.HostsInfoHolderClass> tempAllHostsListFromFile = HostInfoHelper
                            .readHostsInfoFile(existingFilePtr);
                        if (tempAllHostsListFromFile != null && tempAllHostsListFromFile.size() > 0) {
                            System.out.println("Check if ESXi hosts exist & connected in VC inventory ...");
                            hostsListFromFile = new ArrayList<HostInfoHelper.HostsInfoHolderClass>();
                            for (HostInfoHelper.HostsInfoHolderClass tempHostInfo : tempAllHostsListFromFile) {
                                HostSystem tempHostSys = retrieveSingleHostSys(tempHostInfo.hostName);
                                if (tempHostSys != null) {
                                    tempHostInfo.hostSys = tempHostSys;
                                    hostsListFromFile.add(tempHostInfo);
                                } else {
                                    System.out.println(
                                        "Skipping ESXi host: " + tempHostInfo.hostName
                                            + ", as NOW; neither it is in connected state NOR exists in inventory");
                                }
                            }
                        }
                    }
                }

                if (hostsListFromFile != null && hostsListFromFile.size() > 0) {

                    // Construct the default List of Supported Protocols
                    defaultSecProtoList = new ArrayList<String>();
                    defaultSecProtoList.add(PROTO_TLS10);
                    defaultSecProtoList.add(PROTO_TLS11);
                    defaultSecProtoList.add(PROTO_TLS12);

                    // Services/port to configure
                    Map<Integer, List<String>> userMap_secProtoToEnableOnServices = new LinkedHashMap<Integer, List<String>>();
                    userMap_secProtoToEnableOnServices.put(AUTHD_PORT, this.secProtosToEnable);
                     userMap_secProtoToEnableOnServices.put(RHTTP_PROXY_PORT, this.secProtosToEnable);
                     userMap_secProtoToEnableOnServices.put(SFCBD_PORT, this.secProtosToEnable);
                     userMap_secProtoToEnableOnServices.put(VSAN_VP_PORT, this.secProtosToEnable);

                    int serviceCount = userMap_secProtoToEnableOnServices.size();

                    /*
                     * Hosts loop
                     */
                    for (HostInfoHelper.HostsInfoHolderClass hostInfo : hostsListFromFile) {
                        try {
                            currentHostName = hostInfo.hostSys.getName();
                            currentHostSys = hostInfo.hostSys;
                            String userName = hostInfo.username;
                            String pwd = hostInfo.password;

                            List<HostSSLResultHolderClass> allPortsResultHolder =
                                new ArrayList<HostSSLResultHolderClass>();

                            System.out.println(
                                "\n******************************************************************************");
                            System.out.println("\t\t\tHost : " + currentHostName);
                            System.out.println(
                                "******************************************************************************");
                            Thread.sleep(500);

                            /*
                             * Get SSHConnection for host. If we fail to get
                             * SSHConnection, return back to the caller.
                             */
                            System.out.println(
                                "Try to start SSH Service, if its not started already. "
                                    + "This is needed to establish SSH Connection with ESXi host");
                            if (startSSHService(currentHostSys)) {
                                System.out.println("Logging into host: " + currentHostName + " through SSH");
                                try {
                                    boolean sslConfigSuppportedHost = false;

                                    // Check the version of ESXi host, to
                                    // determine if SSL toggling is supported
                                    try {
                                        sshConnObjCurrentHost = SSHUtil
                                            .getSSHConnection(currentHostName, userName, pwd);
                                    } catch (Exception e) {
                                        System.err.println(
                                            "Please check ESXi username/password information provided is indeed correct");
                                    }
                                    if (sshConnObjCurrentHost != null) {
                                        if (!disableESXiVerCheck) {
                                            sslConfigSuppportedHost = hostVerCheckerForSslSupport();
                                        } else {
                                            System.out.println("As requested, ESXi version check is SKIPPED");
                                            sslConfigSuppportedHost = true;
                                        }
                                    } else {
                                        System.err
                                            .println("Unable to log into host: " + currentHostName + " through SSH");
                                    }

                                    if (sslConfigSuppportedHost) {
                                        int tempCounter = 0;

                                        if (is51Host || is50Host) {
                                            // remove from default supported protocol list: 51 supports only TLSv10
                                            defaultSecProtoList.remove(PROTO_TLS11);
                                            defaultSecProtoList.remove(PROTO_TLS12);
                                            this.secProtosToEnable.remove(PROTO_TLS11);
                                            this.secProtosToEnable.remove(PROTO_TLS12);

                                            // There is NO vSanvpd in 50/51
                                            userMap_secProtoToEnableOnServices.remove(VSAN_VP_PORT);

                                            if (enableSsl) {
                                                tls_protos_enable = PROTO_SSLV3 + "," + PROTO_TLS10;
                                            } else {
                                                tls_protos_enable = PROTO_TLS10;
                                            }
                                            serviceCount = userMap_secProtoToEnableOnServices.size();
                                        }

                                        /*
                                         * Iterate through user provided list of
                                         * ports and protocols to enable on each
                                         * of the port
                                         */
                                        enabledInpSecProtoMap = new LinkedHashMap<Integer, List<String>>();

                                        for (Integer servicePort : userMap_secProtoToEnableOnServices.keySet()) {
                                            Boolean isPortConfigSuccessful = null;
                                            List<String> tempSecProtosToEnable = userMap_secProtoToEnableOnServices
                                                .get(servicePort);

                                            switch (servicePort) {
                                            case RHTTP_PROXY_PORT:
                                            case AUTHD_PORT:
                                            case SFCBD_PORT:
                                            case VSAN_VP_PORT:
                                                System.out.println(
                                                    "\n**** Service/Port to Configure : "
                                                        + portToServiceNameMap.get(servicePort) + "(" + servicePort
                                                        + ") **** ");

                                                if (servicePort == VSAN_VP_PORT) {
                                                    boolean vsanVpServiceStarted = false;
                                                    if (!(SSHUtil
                                                        .isServiceRunning(sshConnObjCurrentHost, SERVICE_VSAN_VP))) {
                                                        vsanVpServiceStarted = SSHUtil
                                                            .startService(sshConnObjCurrentHost, SERVICE_VSAN_VP);
                                                    } else {
                                                        vsanVpServiceStarted = true;
                                                    }

                                                    if (!vsanVpServiceStarted) {
                                                        System.err
                                                            .println("Could not find VSAN_VP service in running state");
                                                        break;
                                                    }
                                                }

                                                boolean sslFoundEnabledForDisableOp = false;
                                                System.out.println(
                                                    "Scan and obtain list of protocols that are currently enabled...");
                                                List<String> secProtosBeforeChange = null;

                                                if (servicePort == AUTHD_PORT) {
                                                    secProtosBeforeChange = authdProtocolFetcher(
                                                        currentHostName,
                                                        servicePort);
                                                } else {
                                                    secProtosBeforeChange = securityProtocolScanner(
                                                        currentHostName,
                                                        servicePort);
                                                }

                                                if (!enableSsl) {
                                                    if (secProtosBeforeChange.contains(PROTO_SSLV3)) {
                                                        // we found SSLv3 enabled, we need to disable it
                                                        sslFoundEnabledForDisableOp = true;
                                                    } else {
                                                        System.out.println(PROTO_SSLV3 + " is already disabled");
                                                        System.out.println("------------------------------------------");
                                                        System.out.println("List of security protocols currenty enabled");
                                                        System.out.println(secProtosBeforeChange.toString());
                                                        System.out.println("------------------------------------------");
                                                        isPortConfigSuccessful = true;
                                                        enabledInpSecProtoMap.put(servicePort, secProtosBeforeChange);

                                                        // Store the before, after TLS proto information, for printing purpose
                                                        HostSSLResultHolderClass individualPortResultClassObj =
                                                            new HostSSLResultHolderClass();
                                                        individualPortResultClassObj.port = servicePort;
                                                        individualPortResultClassObj.afterProtoList = secProtosBeforeChange.toString();
                                                        individualPortResultClassObj.beforeProtoList = secProtosBeforeChange.toString();
                                                        allPortsResultHolder.add(individualPortResultClassObj);
                                                        ++ tempCounter;
                                                    }
                                                }

                                                if (enableSsl || sslFoundEnabledForDisableOp) {

                                                    if (servicePort == AUTHD_PORT) {
                                                        isPortConfigSuccessful = updateAuthdServiceSecProto(
                                                            servicePort,
                                                            tempSecProtosToEnable,
                                                            secProtosBeforeChange);
                                                    } else {
                                                        isPortConfigSuccessful = updateESXiServiceSecProto(
                                                            servicePort,
                                                            tempSecProtosToEnable,
                                                            secProtosBeforeChange);
                                                    }

                                                    if (isPortConfigSuccessful) {

                                                        // Store the before, after TLS proto information, for printing
                                                        // purpose
                                                        HostSSLResultHolderClass individualPortResultClassObj = new HostSSLResultHolderClass();
                                                        individualPortResultClassObj.port = servicePort;
                                                        individualPortResultClassObj.afterProtoList = tempSecProtosToEnable
                                                            .toString();
                                                        individualPortResultClassObj.beforeProtoList = enabledInpSecProtoMap
                                                            .get(servicePort).toString();
                                                        allPortsResultHolder.add(individualPortResultClassObj);
                                                        ++tempCounter;
                                                    }
                                                }

                                                break;

                                            default:
                                                System.err.println(
                                                    "List contains invalid Service Port (" + servicePort
                                                        + "( or Service of which configuration"
                                                        + " is NOT supported yet");
                                                break;
                                            } // End of switch loop

                                            /*
                                             * In case of configuration failure of any single port, SKIP further
                                             * configuration of ports on the host
                                             */
                                            if (isPortConfigSuccessful != null && (!isPortConfigSuccessful)) {
                                                // Try reverting the configuration changes made to other ports
                                                System.out.println(
                                                    "Configuration update was not successful, check & revert the changes made, if any");
                                                restoreConfiguration();
                                                break;
                                            } else if (tempCounter == serviceCount){
                                                // All operations went through fine, populate the result holder object
                                                hostSSLconfigResultHolderObj.put(currentHostName, allPortsResultHolder);
                                            }

                                        } // End of ports-services loop
                                    }
                                } catch (Exception e) {
                                    System.err
                                        .println("Caught an exception while configuring host: " + currentHostName);
                                    e.printStackTrace();
                                }
                            } else {
                                System.err.println(
                                    SSH_SERVICE + " Service could not be started, which is a must to continue!");
                            }

                        } catch (Exception e) {
                            System.out.println("[Hosts Loop Entry] Caught exception:" + e.getLocalizedMessage());
                            restoreConfiguration();
                        } finally {
                            // Cleanup- Restore SSH service state
                            if (cleanupStopSSHService == true) {
                                System.out.println("Reverting the SSH Service state, as it was before");
                                if (currentHostSys.getName() == null) {
                                    if (isStandAloneHost) {
                                        si = loginTovSphere(url);
                                    }
                                    currentHostSys = retrieveSingleHostSys(currentHostName);
                                }
                                stopSSHService(currentHostSys);
                            }

                            // cleanup the objects
                            currentHostName = null;
                            currentHostSys = null;
                            enabledInpSecProtoMap = null;

                            // Close the SSHConnection
                            if (sshConnObjCurrentHost != null) {
                                sshConnObjCurrentHost.close();
                                sshConnObjCurrentHost = null;
                            }
                        }

                        /*
                         * Print the final SSL Configuration result of host
                         */
                        printSslConfigResult(hostInfo.hostSys.getName());


                    } // End of Hosts loop

                } else {
                    System.err.println(
                        "Could not find ESXi hosts entry in hosts information file. Either Hosts are not in connected"
                        + " state or part of current VC inventory, or we failed reading the file entries correctly. "
                        + "Please check and try again");
                }

            } else {
                System.err.println("ServiceInstance object is null");
            }

        } catch (Exception e) {
            System.err.println("[Execute Script Flow] Caught exception: " + e.getLocalizedMessage());
        }

        /*
         *  If standalone host, NO need to print ALL hosts result, as we would have previously already done
         *  the same.
         */
        if (!isStandAloneHost) {
            printSslConfigResult(null);

            // And print the result into file
            try {
                if (hostSSLconfigResultHolderObj != null && hostSSLconfigResultHolderObj.size() > 0) {
                    HostInfoHelper.createHostsSSLConfigResultFile(hostSSLconfigResultHolderObj, tls_protos_enable);
                }
            } catch (IOException e) {
                System.err.println("Caught an exception while writing TLS Configuration result into file");
                e.printStackTrace();
            }
        }

        return true;
    }

    /**
     * Print SSL Configuration result of provided or all hosts
     */
    private void
    printSslConfigResult(String hostName)
    {
        try {
            if (hostSSLconfigResultHolderObj != null && hostSSLconfigResultHolderObj.size() > 0) {
                if (hostName == null) {
                    System.out.println("@@@@@@@@@@@@@@@@@ ALL HOSTS SSL CONFIGURATION RESULT @@@@@@@@@@@@@@@@@");
                    for (String tempHostNameResultObj : hostSSLconfigResultHolderObj.keySet()) {
                            System.out.println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
                            System.out.println(" SSL CONFIGURATION RESULT FOR HOST: " + tempHostNameResultObj);
                            System.out.println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
                            System.out.println("Protocol configuration (as requested by user) : SSLv3 - " + (enableSsl?"enable":"disable") + "\n");

                            ResultTablePrinter resultObj = new ResultTablePrinter();
                            resultObj.addLine("------------", "----", "------------------------", "-----------------------");
                            resultObj.addLine("SERVICE NAME", "PORT", "Before SSL/TLS Protocols", "After SSL/TLS Protocols");
                            resultObj.addLine("------------", "----", "------------------------", "-----------------------");

                            for (HostSSLResultHolderClass tempTlsResultObj : hostSSLconfigResultHolderObj
                                .get(tempHostNameResultObj)) {
                                resultObj.addLine(
                                    portToServiceNameMap.get(tempTlsResultObj.port),
                                    tempTlsResultObj.port.toString(),
                                    tempTlsResultObj.beforeProtoList,
                                    tempTlsResultObj.afterProtoList);
                            }
                            resultObj.addLine("------------", "----", "------------------------", "-----------------------");
                            resultObj.print();
                    }
                } else {
                    for (String tempHostNameResultObj : hostSSLconfigResultHolderObj.keySet()) {
                        if (tempHostNameResultObj.equals(hostName)) {
                            System.out.println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
                            System.out.println(" SSL CONFIGURATION RESULT FOR HOST: " + tempHostNameResultObj);
                            System.out.println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
                            System.out.println("Protocol configuration (as requested by user) : SSLv3 - " + (enableSsl?"enable":"disable") + "\n");

                            ResultTablePrinter resultObj = new ResultTablePrinter();
                            resultObj.addLine("------------", "----", "------------------------", "-----------------------");
                            resultObj.addLine("SERVICE NAME", "PORT", "Before SSL/TLS Protocols", "After SSL/TLS Protocols");
                            resultObj.addLine("------------", "----", "------------------------", "-----------------------");

                            for (HostSSLResultHolderClass tempTlsResultObj : hostSSLconfigResultHolderObj
                                .get(tempHostNameResultObj)) {
                                resultObj.addLine(
                                    portToServiceNameMap.get(tempTlsResultObj.port),
                                    tempTlsResultObj.port.toString(),
                                    tempTlsResultObj.beforeProtoList,
                                    tempTlsResultObj.afterProtoList);
                            }
                            resultObj.addLine("------------", "----", "------------------------", "-----------------------");
                            resultObj.print();
                        }
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("Caught an exception, while printing out SSL Configuration result");
        }
    }

    /**
     * Check ESXi hosts version to determine if SSL configuration is supported or not
     * SSL Configuration supported on 5.5P07, 55P08, 51P09, 50P13 onwards
     */
    private boolean
    hostVerCheckerForSslSupport()
    {
        String esxi_version = null;
        Integer esxi_build = null;
        Integer esxi_update = null;
        boolean sslConfigSupported = false;
        String supportedVersion = null;
        Integer supportedUpdateVersion = null;
        Integer supportedBuildNumber = null;

        try {
            String verCmdoutput = SSHUtil.getSSHOutputStream(sshConnObjCurrentHost, CMD_VERSION_CHECK);

            if (verCmdoutput != "" || verCmdoutput != null) {
                String[] fullVersionString = verCmdoutput.split("\n");
                for (String tempfullVerString : fullVersionString) {
                    String productInfo = tempfullVerString.replaceAll("( )+", "").trim().toLowerCase();
                    if (productInfo.contains("version")) {
                        esxi_version = productInfo.split(":")[1];
                        if (esxi_version.contains(SUPPORTED_55P07_VERSION)) {
                            supportedVersion = SUPPORTED_55P07_VERSION;
                            supportedUpdateVersion = SUPPORTED_55P07_UPDATE_VER;
                            supportedBuildNumber = SUPPORTED_55P07_BUILD_NUMBER;
                        } else if (esxi_version.contains(SUPPORTED_51_VERSION)) {
                            is51Host = true;
                            supportedVersion = SUPPORTED_51_VERSION;
                            supportedUpdateVersion = SUPPORTED_51_UPDATE_VER;
                            supportedBuildNumber = SUPPORTED_51_BUILD_NUMBER;
                        } else if (esxi_version.contains(SUPPORTED_50_VERSION)) {
                            is50Host = true;
                            supportedVersion = SUPPORTED_50_VERSION;
                            supportedUpdateVersion = SUPPORTED_50_UPDATE_VER;
                            supportedBuildNumber = SUPPORTED_50_BUILD_NUMBER;
                        }
                    } else if (productInfo.contains("build")) {
                        esxi_build = Integer.parseInt(productInfo.split(":")[1].replace("releasebuild-", ""));
                    } else if (productInfo.contains("update")) {
                        esxi_update = Integer.parseInt(productInfo.split(":")[1]);
                    }
                }
            }

            /*
             * Returns 0 : if current version == supported Version
             * Returns =<-1 (i.e. < 0): if current version is lower than supported version
             * Returns >=1 (i.e. > 0): if current version is higher than supported version
             */

            int isVerSupported = 1; //Not supported, to start off
            if (supportedVersion != null) {
                isVerSupported = compare(esxi_version, supportedVersion);
            }

            if ((isVerSupported == 0 &&
                (esxi_update.compareTo(supportedUpdateVersion) >= 0) &&
                (esxi_build.compareTo(supportedBuildNumber) >= 0))) {
                // Version check done - supported version of ESXi for SSL toggling
                System.out.println(
                    "This ESXi host (" + esxi_version + ", Update-" + esxi_update + " Build-" + esxi_build
                        + ") is supported for SSL security protocol configuration");
                sslConfigSupported = true;
            } else {
                System.err.println(
                    "This ESXi host (" + esxi_version + ", Update-" + esxi_update + " Build-" + esxi_build
                        + ") is NOT supported for SSL security protocol configuration");
                if (supportedVersion != null) {
                    System.err.println(
                        "SSL Security protocol configuration is supported on version: " + supportedVersion + " Update-"
                            + supportedUpdateVersion + " Build-" + supportedBuildNumber);
                } else {
                    System.err.println(
                        "SSL Security protocol configuration is supported on release: 5.0P13 / 5.1P09/ 5.5P07 and onwards");
                }
                System.err.println(
                    "If your ESXi hosts version/build number is higher, "
                        + "please check if its an HotPatch build, built on top of base "
                        + "ESXi release-where SSL protocol configuration was not supported initially");
            }
        } catch (Exception e) {
            System.err.println("Caught exception while determining SSL Configuration support for ESXi hosts");
            e.printStackTrace();
        }

        return sslConfigSupported;
    }

    /**
     * Compare version strings * Returns 0 : if current version == supported
     * Version Returns =<-1 (i.e. < 0): if current version is lower than
     * supported version Returns >=1 (i.e. > 0): if current version is higher
     * than supported version
     */
    private int
    compare(String currVer, String supportedVer)
    {
        currVer = normalizedVersion(currVer);
        supportedVer = normalizedVersion(supportedVer);
        int cmp = currVer.compareTo(supportedVer);
        return cmp;
    }

    /**
     * Normalize the strings passed from Compare method
     */
    private
    String normalizedVersion(String version)
    {
        String separator = ".";
        int maxWidth = 3;
        String[] split = Pattern.compile(separator, Pattern.LITERAL).split(version);
        StringBuilder sb = new StringBuilder();
        for (String s : split) {
            sb.append(String.format("%" + maxWidth + 's', s));
        }
        return sb.toString();
    }

    /**
     * Restore previous configuration, as it was before start of protocol updation
     */
    private void
    restoreConfiguration()
    {
        if ((this.enabledInpSecProtoMap != null && this.enabledInpSecProtoMap.size() > 0)) {
            /*
             *  Remove the host related information - to throw away all information we stored earlier
             *  while port configuration was done on this host. Now this object will hold information
             *  only regarding roll back done for host where we fail to configure SSL protocols for all ports.
             */
            hostSSLconfigResultHolderObj.remove(currentHostName);

            List<HostSSLResultHolderClass> allPortsResultHolder =
                new ArrayList<HostSSLResultHolderClass>();

            System.out.println("Reverting the configuration changes made earlier...");
            /*
             * Iterate through user provided list of ports and protocols to
             * enable on each of the port
             */
            for (Integer restoreServicePort : this.enabledInpSecProtoMap.keySet()) {
                List<String> tempRestoreSecProtos = this.enabledInpSecProtoMap.get(restoreServicePort);

                switch (restoreServicePort) {
                case RHTTP_PROXY_PORT:
                    System.out.println("\n**** Reverting changes made on : RHTTPPROXY/HOSTD (" + restoreServicePort + ") ****");

                    // Store the before, after TLS proto information, for printing purpose
                    HostSSLResultHolderClass hostdPortResultClassObj =
                        new HostSSLResultHolderClass();
                    hostdPortResultClassObj.port = restoreServicePort;
                    hostdPortResultClassObj.beforeProtoList = tempRestoreSecProtos.toString();

                    if (is50Host || is51Host) {
                        if (restoreESXiServiceSecProto(restoreServicePort, tempRestoreSecProtos)) {
                            hostdPortResultClassObj.afterProtoList = tempRestoreSecProtos.toString();
                        } else {
                            hostdPortResultClassObj.afterProtoList = "NULL (Pls Check logs)";
                        }
                    } else {
                        // 55P07 host, to revert configuration changes : Need to revert configuration file
                        if (restoreHostdSecProto(restoreServicePort, tempRestoreSecProtos)) {
                            hostdPortResultClassObj.afterProtoList = tempRestoreSecProtos.toString();
                        } else {
                            hostdPortResultClassObj.afterProtoList = "NULL (Pls Check logs)";
                        }
                    }

                    allPortsResultHolder.add(hostdPortResultClassObj);
                    break;

                case AUTHD_PORT:
                    System.out.println("\n**** Reverting changes made on : AUTHD (" + restoreServicePort + ") ****");

                    // Store the before, after TLS proto information, for printing purpose
                    HostSSLResultHolderClass authdPortResultClassObj =
                        new HostSSLResultHolderClass();
                    authdPortResultClassObj.port = restoreServicePort;
                    authdPortResultClassObj.beforeProtoList = tempRestoreSecProtos.toString();

                    if(restoreAuthdSecProto(restoreServicePort, tempRestoreSecProtos)) {
                        authdPortResultClassObj.afterProtoList = tempRestoreSecProtos.toString();
                    } else {
                        authdPortResultClassObj.afterProtoList = "NULL (Pls Check logs)";
                    }
                    allPortsResultHolder.add(authdPortResultClassObj);
                    break;

                case SFCBD_PORT:
                    System.out.println("**** Reverting changes made on : SFCBD (" + restoreServicePort + ") ****");

                    // Store the before, after TLS proto information, for printing purpose
                    HostSSLResultHolderClass sfcbdPortResultClassObj =
                        new HostSSLResultHolderClass();
                    sfcbdPortResultClassObj.port = restoreServicePort;
                    sfcbdPortResultClassObj.beforeProtoList = tempRestoreSecProtos.toString();

                    if(restoreSFCBDSecProto(restoreServicePort, tempRestoreSecProtos)) {
                        sfcbdPortResultClassObj.afterProtoList = tempRestoreSecProtos.toString();
                    } else {
                        sfcbdPortResultClassObj.afterProtoList = "NULL (Pls Check logs)";
                    }
                    allPortsResultHolder.add(sfcbdPortResultClassObj);
                    break;

                case VSAN_VP_PORT:
                    System.out.println("\n**** Reverting changes made on : VSAN_VP (" + restoreServicePort + ") ****");

                    // Store the before, after TLS proto information, for printing purpose
                    HostSSLResultHolderClass vsanPortResultClassObj =
                        new HostSSLResultHolderClass();
                    vsanPortResultClassObj.port = restoreServicePort;
                    vsanPortResultClassObj.beforeProtoList = tempRestoreSecProtos.toString();

                    if (restoreESXiServiceSecProto(restoreServicePort, tempRestoreSecProtos)) {
                        vsanPortResultClassObj.afterProtoList = tempRestoreSecProtos.toString();
                    } else {
                        vsanPortResultClassObj.afterProtoList = "NULL (Pls Check logs)";
                    }
                    allPortsResultHolder.add(vsanPortResultClassObj);
                    break;
                }
            }

            // All operations completed, populate the result holder object
            hostSSLconfigResultHolderObj.put(currentHostName, allPortsResultHolder);

        } else {
            System.out.println(
                "There is nothing to cleanup / restore, as none of the service/port configuration is fully completed previously");
        }
    }

    /**
     * Restore AUTHD security protocols
     */
    private boolean
    restoreAuthdSecProto(Integer restoreServicePort, List<String> tempRestoreSecProtos)
    {
        boolean restoreDone = false;
        try {
            List<String> currSecProtos = null;
            try {
                currSecProtos = authdProtocolFetcher(currentHostName, restoreServicePort);
            } catch (Exception e) {
                System.out.println(
                    "Caught exception while fetching currently enabled security protocols, May be service itself is down");
                System.out.println("Continuing with restoring the configuration ...");
            }

            if (currSecProtos != null && secProtoChecker(currSecProtos, tempRestoreSecProtos)) {
                // Required protocols are ALREADY enabled on port, No need to do anything here, print out exit
                System.out.println("Successfully restored security protocol configuration");
                return true;
            } else {
                // Required protocols needs to be enabled
                System.out.println("Reverting the security protocol configuration changes ...");

                // Get the disabled protocol list command for esxcli cmd execution
                String disabledProtos = GetDisableProtocolString(tempRestoreSecProtos);
                if (disabledProtos != null) {
                    String authCmdToSetProtos = CMD_AUTHD;
                    if (is50Host) {
                        authCmdToSetProtos = CMD_AUTHD_50;
                    } else if (is51Host) {
                        authCmdToSetProtos = CMD_AUTHD_51;
                    }

                    String fullCmd = authCmdToSetProtos + "\"" + disabledProtos + "\"";

                    if (SSHUtil.executeRemoteSSHCommand(sshConnObjCurrentHost, fullCmd)) {
                        System.out.println("Successfully executed the command for updating security protocol list");

                        /*
                         * Scan and Check if user requested protocols are indeed
                         * show up as enabled by running security scanner
                         */
                        System.out.println(
                            "Perform Post validation to check if"
                                + " user expected protocols are indeed persisted ...");
                        List<String> secProtosAfterChange = authdProtocolFetcher(currentHostName, restoreServicePort);

                        if (secProtoListPostValidater(tempRestoreSecProtos, secProtosAfterChange)) {
                            System.out.println("Successfully enabled : \"" + tempRestoreSecProtos.toString() + "\" "
                                + "protocols on port: " + restoreServicePort);
                            System.out.println("------------------------------------------");
                            System.out.println("List of security protocols currenty enabled (AFTER change)");
                            System.out.println(secProtosAfterChange.toString());
                            System.out.println("------------------------------------------");
                            restoreDone = true;
                        } else {
                            System.err.println(
                                "Failed to enable : \"" + tempRestoreSecProtos.toString() + "\" " + "protocols port: "
                                    + restoreServicePort);
                        }
                    } else {
                        System.err.println("Could not execute the command for updating security protocol list");
                    }

                } else {
                    System.err.println("Could not obtain command list to disable unwanted Security protocols");
                }

            }
        } catch (Exception e) {
            System.out.println("Caught exception while restorting the configuration changes");
        }
        return restoreDone;
    }

    /**
     * Security Protocol Scanner
     */
    private List<String>
    securityProtocolScanner(String host, int port)
    {
        List<String> secProtocolList = null;

        try {
            List<String> tempSecProtoList = TestSSLServer.SecurityProtoScanner(host, port);

            /*
             * Convert the strings according to ESXi side implementation of
             * protocol strings All protocols are in small cases AND TSLv1.0 is
             * used as "tlsv1"
             */
            secProtocolList = new ArrayList<String>();
            for (String tempProtocol : tempSecProtoList) {
                if (tempProtocol.equals(TESTSSLSERVER_PROTO_TLS10)) {
                    secProtocolList.add(PROTO_TLS10);
                } else {
                    secProtocolList.add(tempProtocol.toLowerCase());
                }
            }
        } catch (Exception e) {
            System.err.println("[TestSSLServer Scanner] Caught exception while running scanner: " + e.getMessage());
        }

        return secProtocolList;
    }

    /**
     * TLS Security Protocol configuration method for ... Rhttpproxy/Hostd VSANVP SFCBD services
     */
    private boolean
    updateESXiServiceSecProto(Integer portNum, List<String> user_secProtosToEnable, List<String> secProtosBeforeChange) throws Exception
    {
        boolean isUpdateSuccess = false;

        if (secProtosBeforeChange != null) {
            // Check if its valid security protocols combination - to enable
            if (enableSsl) {
                if (!secProtosBeforeChange.containsAll(defaultSecProtoList)) {
                    System.err.println(
                        PROTO_SSLV3 + " protocol can not be enabled. Combination of SSL and TLS protocols"
                            + " to enable is NOT supported");
                    secProtosBeforeChange.add(PROTO_SSLV3);
                    System.err.println("Requested : " + secProtosBeforeChange);
                    List<String> supportedList = new ArrayList<>();
                    supportedList.addAll(defaultSecProtoList);
                    supportedList.add(PROTO_SSLV3);
                    System.err.println("Supported : " + supportedList.toString());
                    return false;
                }
            }

            /*
             * Store the Service port & security protocols already
             * enabled - for restoring purpose, if something goes wrong
             * with updation later.
             */
            enabledInpSecProtoMap.put(portNum, secProtosBeforeChange);

            if (secProtoChecker(secProtosBeforeChange, user_secProtosToEnable)) {
                // Required protocols are ALREADY enabled on port, No need to do anything here, print out exit
                System.out.println("------------------------------------------");
                System.out.println("List of security protocols REQUESTED");
                System.out.println(user_secProtosToEnable.toString());
                System.out.println("------------------------------------------");
                System.out.println("List of security protocols currenty enabled");
                System.out.println(secProtosBeforeChange.toString());
                System.out.println("------------------------------------------");
                isUpdateSuccess = true;
            } else {
                // Required protocols needs to be enabled
                System.out.println("------------------------------------------");
                System.out.println("List of security protocols currenty enabled (BEFORE change)");
                System.out.println(secProtosBeforeChange.toString());
                System.out.println("------------------------------------------");
                System.out.println("List of security protocols REQUESTED, which YET TO BE ENABLED");
                System.out.println(user_secProtosToEnable.toString());
                System.out.println("------------------------------------------");

                System.out.println("Starting configuration ...");
                /*
                 * Get the disabled protocol list command for esxcli cmd execution. SSLv3 will be disabled by default
                 */
                String disabledProtos = GetDisableProtocolString(user_secProtosToEnable);

                if (disabledProtos != null) {
                    String fullCmd = "\"" + disabledProtos + "\"";
                    String serviceName = null;
                    if (portNum == RHTTP_PROXY_PORT) {
                        if (is50Host) {
                            fullCmd = CMD_HOSTD + fullCmd;
                            serviceName = SERVICE_HOSTD;
                        } else if (is51Host) {
                            fullCmd = CMD_RHTTP_PROXY_51 + fullCmd;
                            serviceName = SERVICE_RHTTPPROXY;
                        } else {
                            // Its 55P07 type of host : follow old way of configuring rhttproxy/hostd config
                            boolean isHostdConfigSuccess = false;
                            try {
                                isHostdConfigSuccess = updateHostdSecProto(user_secProtosToEnable);
                            } catch (Exception e) {
                                System.err.println(
                                    "Caught an exception while updating RHTTPPROXY/HOSTD security Configuration protocols");
                            }
                            return isHostdConfigSuccess;
                        }

                    } else if (portNum == VSAN_VP_PORT) {
                        fullCmd = CMD_VSAN_VP + fullCmd;
                        serviceName = SERVICE_VSAN_VP;
                    } else if (portNum == SFCBD_PORT) {
                        boolean isSfcbdConfigSuccess = false;
                        try {
                            isSfcbdConfigSuccess = updateSFCBDSecProto(user_secProtosToEnable);
                        } catch (Exception e) {
                            System.err
                                .println("Caught an exception while updating SFCBD security Configuration protocols");
                        }
                        return isSfcbdConfigSuccess;
                    }

                    boolean restartedService = false;
                    if (SSHUtil.executeRemoteSSHCommand(sshConnObjCurrentHost, fullCmd)) {
                        System.out.println("Successfully executed the command for updating security protocol list");

                        // Restart services and check if we were indeed successful in applying the changes
                        System.out
                            .println("Trying to restart service: " + serviceName + ", for changes to take effect");
                        if (is50Host && (portNum == RHTTP_PROXY_PORT)) {
                            SSHUtil.executeAsyncRemoteSSHCommand(sshConnObjCurrentHost, SERVICE_HOSTD + " stop");
                            if (SSHUtil.waitTillServiceisStopped(sshConnObjCurrentHost, SERVICE_HOSTD)) {
                                SSHUtil.executeAsyncRemoteSSHCommand(sshConnObjCurrentHost, SERVICE_HOSTD + " start");
                                restartedService = SSHUtil.waitTillServiceisStarted(sshConnObjCurrentHost, SERVICE_HOSTD);
                            }
                        } else {
                            restartedService = SSHUtil.restartService(sshConnObjCurrentHost, serviceName);
                        }

                        if (restartedService) {
                            /*
                             * Scan and Check if user requested protocols are
                             * indeed show up as enabled by running security scanner
                             */
                            System.out.println(
                                "Perform Post validation to check if"
                                    + " user expected protocols show up with security scanner ...");
                            List<String> secProtosAfterChange = securityProtocolScanner(currentHostName, portNum);

                            if (secProtoListPostValidater(user_secProtosToEnable, secProtosAfterChange)) {
                                System.out.println("Successfully enabled : \"" + user_secProtosToEnable.toString()
                                    + "\" " + "protocols on port: " + portNum);
                                System.out.println("------------------------------------------");
                                System.out.println("List of security protocols currenty enabled (AFTER change)");
                                System.out.println(secProtosAfterChange.toString());
                                System.out.println("------------------------------------------");
                                isUpdateSuccess = true;
                            } else {
                                System.err.println(
                                    "Failed to enable : \"" + user_secProtosToEnable.toString() + "\" "
                                        + "protocols port: " + portNum);
                            }

                        } else {
                            System.err.println("Could not restart service: " + serviceName);
                        }

                    } else {
                        System.err.println("Could not execute the command for updating security protocol list");
                    }

                } else {
                    System.err.println("Could not obtain command list to disable unwanated Security protocols");
                }
            }

        } else {
            System.err.println("Could not fetch list of currently enabled security protocols");
        }

        return isUpdateSuccess;
    }

    /**
     * Update security protocol configuration for RHTTPPROXY/HOSTD
     * @throws Exception
     */
    private boolean
    updateHostdSecProto(List<String> user_secProtosToEnable) throws Exception
    {
        boolean configurationSuccess = false;

     // take backup of file
        System.out.println("Trying to backup file: "
                 + RHTTPPROXY_CONFIG_FILE
                 + ", before modification");
        if (SSHUtil.copyFileOnHost(sshConnObjCurrentHost,
                 RHTTPPROXY_CONFIG_FILE,
                 RHTTPPROXY_CONFIG_BACKUP_FILE)) {
           if (SSHUtil.fileExistsOnHost(sshConnObjCurrentHost,
                    RHTTPPROXY_CONFIG_BACKUP_FILE)) {
              System.out.println("Took backup of "
                       + RHTTPPROXY_CONFIG_FILE
                       + " file. Backed up file name:"
                       + RHTTPPROXY_CONFIG_BACKUP_FILE);
              // alter the config file content
              System.out.println("Performing configuration file updation now...");
              System.out.println("Trying to update file: "
                       + RHTTPPROXY_CONFIG_FILE
                       + ", with SSLOptions entry");

              if (updateConfigFile(sshConnObjCurrentHost,
                       RHTTPPROXY_CONFIG_FILE)) {
                 System.out.println("Successfully updated  "
                          + RHTTPPROXY_CONFIG_FILE
                          + " file with ssloption");

                 // restart the services
                 System.out.println("Trying to restart service: "
                          + SERVICE_RHTTPPROXY
                          + ", for changes to take effect");
                 if (SSHUtil.restartService(sshConnObjCurrentHost,
                          SERVICE_RHTTPPROXY)) {
                    /*
                     * Scan and Check if user requested protocols are
                     * indeed show up as enabled by running security scanner
                     */
                    System.out.println(
                        "Perform Post validation to check if"
                            + " user expected protocols show up with security scanner ...");
                    List<String> secProtosAfterChange = securityProtocolScanner(currentHostName, RHTTP_PROXY_PORT);

                    if (secProtoListPostValidater(user_secProtosToEnable, secProtosAfterChange)) {
                        System.out.println("Successfully enabled : \"" + user_secProtosToEnable.toString()
                            + "\" " + "protocols on port: " + RHTTP_PROXY_PORT);
                        System.out.println("------------------------------------------");
                        System.out.println("List of security protocols currenty enabled (AFTER change)");
                        System.out.println(secProtosAfterChange.toString());
                        System.out.println("------------------------------------------");
                        configurationSuccess = true;
                    } else {
                        System.err.println(
                            "Failed to enable : \"" + user_secProtosToEnable.toString() + "\" "
                                + "protocols port: " + RHTTP_PROXY_PORT);
                    }
                 } else {
                     System.err.println("Could not restart service: "
                         + SERVICE_RHTTPPROXY + " after updating its configuration file");
                 }
              } else {
                 System.err.println("Unable to update  "
                          + RHTTPPROXY_CONFIG_FILE
                          + " file with ssloption");
              }
           } else {
              System.err.println("Could not find backedup file: "
                       + RHTTPPROXY_CONFIG_BACKUP_FILE);
           }
        } else {
           System.err.println("Could not take backup of "
                    + RHTTPPROXY_CONFIG_FILE + " file");
        }

        return configurationSuccess;
    }

    /**
     * Update the config file with SSL option to enable SSLv3
     *
     * @throws Exception
     */
    private boolean updateConfigFile(Connection conn,
                                     String configFilePath)
    {
       boolean fileUpdated = false;

       try {
           if (enableSsl) {
               // Add new entry
               System.out.println("Could not find any existing sslOptions entry");
               System.out.println("Add new sslOptions entry with decimal value: "
                        + CONFIG_OPT_NEW_ENTRY_VALUE
                        + " (for user expected security protocols)");

               String tempConfigFilePath = configFilePath + "-TEMP";
               String CMD_ADD_SSLOPTION_ENTRY = "awk -F\"[<>]\" '/<vmacore>/ {f=1} /^<mm>/ && "
                        + "!/<vmacore>/ {f=0} f && "
                        + "/<\\/ssl>/ {q=1} f && q "
                        + "{print \"          <sslOptions>"
                        + CONFIG_OPT_NEW_ENTRY_VALUE
                        + "</sslOptions>\";"
                        + "f=q=0}1' ";

               // Update the file
               String fullCmd = CMD_ADD_SSLOPTION_ENTRY + configFilePath + ">"
                        + tempConfigFilePath + "; mv " + tempConfigFilePath + " "
                        + configFilePath;
               if (SSHUtil.executeRemoteSSHCommand(conn, fullCmd)) {
                  // Check if we indeed were successful in adding the entry
                  String tempOptionString = "<" + SSL_OPTIONS_TAG + ">"
                           + CONFIG_OPT_NEW_ENTRY_VALUE + "</" + SSL_OPTIONS_TAG
                           + ">";

                  if (checkConfigEntry(conn, configFilePath, tempOptionString)) {
                     fileUpdated = true;
                  }
               } else {
                  System.err.println("Could not execute the command for updating "
                           + configFilePath);
               }
           } else {
               System.out.println("Check for the sslOptions entry in config file and delete");
                /*
                 * Delete the sslOptions entry
                 * sed -i -e '/<sslOptions>369098111<\/sslOptions>/d' config.xml
                 */
                String delSslOpDecValCmd = "sed -i -e '/<sslOptions>" + CONFIG_OPT_NEW_ENTRY_VALUE + "<\\/sslOptions>/d' " + configFilePath;

                if (SSHUtil.executeRemoteSSHCommand(conn, delSslOpDecValCmd)) {
                    // Check if we indeed were successful in deleting the entry
                    String tempOptionString = "<" + SSL_OPTIONS_TAG + ">" + CONFIG_OPT_NEW_ENTRY_VALUE + "</"
                        + SSL_OPTIONS_TAG + ">";

                    if (!checkConfigEntry(conn, configFilePath, tempOptionString)) {
                        fileUpdated = true;
                    }
                } else {
                    System.err.println("Could not execute the command for updating " + configFilePath);
                }
            }

           if (fileUpdated) {
              System.out.println("Succesfully updated sslOptions entry in config file: "
                       + configFilePath);
           } else {
              System.err.println("Unable to update sslOptions entry in config file: "
                       + configFilePath);
           }

       } catch (Exception e) {
           System.err.println("Caught exception while updating configuration file: " + configFilePath);
           e.printStackTrace();
           fileUpdated = false;
       }

       return fileUpdated;
    }

    /**
     * Check if user provided entry exists in config file
     */
    private boolean checkConfigEntry(Connection conn,
                                     String configFilePath,
                                     String searchStr)
       throws Exception
    {
       boolean entryFound = false;
       String searchCmd = "grep \"" + searchStr + "\" " + configFilePath;
       Map<String, String> cmdOutputMap = SSHUtil.getRemoteSSHCmdOutput(conn,
                searchCmd);

       String error = cmdOutputMap.get(SSHUtil.SSH_ERROR_STREAM);
       if (((!error.equals("")) || error != null) && error.length() > 0) {
          System.err.println("Shell command returned error :" + error);
          throw new Exception();
       } else {
          String output = cmdOutputMap.get(SSHUtil.SSH_OUTPUT_STREAM).trim();
          if (output.equals(searchStr)) {
             entryFound = true;
             System.out.println("Succesfully found entry " + searchStr
                      + " in config file: " + configFilePath);
          } else {
             System.out.println("Could not find entry " + searchStr
                      + " in config file: " + configFilePath);
          }
       }

       return entryFound;
    }


    /**
     * Restore RHTTPROXY/HOSTD security protocols to default, as it was before
     */
    private boolean
    restoreHostdSecProto(Integer restoreServicePort, List<String> tempRestoreSecProtos)
    {
        boolean restoreDone = false;
        try {
            List<String> currSecProtos = null;
            try {
                currSecProtos = securityProtocolScanner(currentHostName, restoreServicePort);
            } catch (Exception e) {
                System.out
                    .println("Caught exception while running security tool scanner, May be service itself is down");
                System.out.println("Continuing with restoring the configuration ...");
            }

            if (currSecProtos != null && secProtoChecker(currSecProtos, tempRestoreSecProtos)) {
                // Required protocols are ALREADY enabled on port, No
                // need to do anything here, print out exit
                System.out.println("Successfully restored security protocol configuration");
                return true;
            }

            // Required protocols needs to be enabled
            System.out.println("Reverting the security protocol configuration changes ...");

            if (SSHUtil.fileExistsOnHost(sshConnObjCurrentHost, RHTTPPROXY_CONFIG_BACKUP_FILE)) {
                if (SSHUtil.copyFileOnHost(sshConnObjCurrentHost, RHTTPPROXY_CONFIG_BACKUP_FILE, RHTTPPROXY_CONFIG_FILE)) {
                    // restart the services
                    System.out.println("Trying to restart service: " + SERVICE_RHTTPPROXY + ", for changes to take effect");
                    if (SSHUtil.restartService(sshConnObjCurrentHost, SERVICE_RHTTPPROXY)) {

                        /*
                         * Scan and Check if user requested protocols are indeed
                         * show up as enabled by running security scanner
                         */
                        System.out.println(
                            "Perform Post config file updation validation to check if"
                                + " user expected protocols show up with security scanner ...");
                        List<String> secProtosAfterChange = securityProtocolScanner(currentHostName, restoreServicePort);

                        if (secProtoListPostValidater(tempRestoreSecProtos, secProtosAfterChange)) {
                            System.out.println("Successfully restored : \"" + tempRestoreSecProtos.toString() + "\" "
                                + "protocols on RHTTPPROXY service on port: " + restoreServicePort);
                            System.out.println("------------------------------------------");
                            System.out.println("List of security protocols currenty enabled (AFTER change)");
                            System.out.println(secProtosAfterChange.toString());
                            System.out.println("------------------------------------------");
                            restoreDone = true;
                        } else {
                            System.err.println(
                                "Failed to restore : \"" + tempRestoreSecProtos.toString() + "\" "
                                    + "protocols on RHTTPPROXY service on port: " + SFCBD_PORT);
                        }

                    } else {
                        System.err.println(
                            "Could not restore RHTTPPROXY configuration file from backedup file: "
                                + RHTTPPROXY_CONFIG_BACKUP_FILE);
                    }

                } else {
                    System.err.println("Could not find backedup file: " + RHTTPPROXY_CONFIG_BACKUP_FILE);
                }
            }

        } catch (Exception e) {
            System.out.println("Caught an exception while restoring the RHTTPPROXY configurations");
        }

        return restoreDone;
    }

    /**
     * Update security protocol configuration for SFCBD
     */
    private boolean
    updateSFCBDSecProto(List<String> user_secProtosToEnable) throws Exception
    {
        boolean isUpdateSuccess = false;

        // take backup of file
        System.out.println("Trying to backup file: " + SFCBD_CONFIG_FILE + ", before modification");
        if (SSHUtil.copyFileOnHost(sshConnObjCurrentHost, SFCBD_CONFIG_FILE, SFCBD_CONFIG_BACKUP_FILE)) {
            if (SSHUtil.fileExistsOnHost(sshConnObjCurrentHost, SFCBD_CONFIG_BACKUP_FILE)) {
                System.out.println(
                    "Took backup of " + SFCBD_CONFIG_FILE + " file. Backed up file name:" + SFCBD_CONFIG_BACKUP_FILE);

                // alter the config file content
                System.out.println("Performing configuration file updation now...");
                System.out.println("Trying to update file: " + SFCBD_CONFIG_FILE + ", with Security options entry");

                if (updateSFCBDConfigFile(SFCBD_CONFIG_FILE, user_secProtosToEnable)) {
                    System.out.println("Successfully updated  " + SFCBD_CONFIG_FILE + " file with Security options");

                    // restart the services
                    System.out.println("Trying to restart service: " + SERVICE_SFCBD + ", for changes to take effect");
                    if (SSHUtil.restartService(sshConnObjCurrentHost, SERVICE_SFCBD)) {
                        /*
                         * Scan and Check if user requested protocols are indeed
                         * show up as enabled by running security scanner
                         */
                        System.out.println(
                            "Perform Post config file updation validation to check if"
                                + " user expected protocols show up with security scanner ...");
                        List<String> secProtosAfterChange = securityProtocolScanner(currentHostName, SFCBD_PORT);

                        if (secProtoListPostValidater(user_secProtosToEnable, secProtosAfterChange)) {
                            System.out.println("Successfully enabled : \"" + user_secProtosToEnable.toString() + "\" "
                                + "protocols on SFCBD service on port: " + SFCBD_PORT);
                            System.out.println("------------------------------------------");
                            System.out.println("List of security protocols currenty enabled (AFTER change)");
                            System.out.println(secProtosAfterChange.toString());
                            System.out.println("------------------------------------------");
                            isUpdateSuccess = true;
                        } else {
                            System.err.println(
                                "Failed to enable : \"" + user_secProtosToEnable.toString() + "\" "
                                    + "protocols on SFCBD service on port: " + SFCBD_PORT);
                        }

                    }
                } else {
                    System.err
                        .println("Unable to update  " + SFCBD_CONFIG_FILE + " file with security protocol options");
                }

            } else {
                System.err.println("Could not find backedup file: " + SFCBD_CONFIG_BACKUP_FILE);
            }

        } else {
            System.err.println("Could not take backup of " + SFCBD_CONFIG_FILE + " file");
        }

        return isUpdateSuccess;
    }

    /**
     * Update SFCBD Configuration file
     */
    private boolean
    updateSFCBDConfigFile(String configFilePath, List<String> user_secProtosToEnable) throws Exception
    {
        boolean isConfigUpdateSuccess = false;

        // String to hold full command for security protocol updation
        String fullCmd = "";

        try {
            // Check for SSL Option
            String sslSearchString = "cat " + configFilePath + " | grep " + SFCBD_SSLV3;
            Map<String, String> sslCmdOutputMap = SSHUtil.getRemoteSSHCmdOutput(sshConnObjCurrentHost, sslSearchString);

            String err = sslCmdOutputMap.get(SSHUtil.SSH_ERROR_STREAM);
            if (((!err.equals("")) || err != null) && err.length() > 0) {
                System.err.println("Shell command returned error :" + err);
            } else {
                String tempsslStrings = sslCmdOutputMap.get(SSHUtil.SSH_OUTPUT_STREAM).trim();
                if (!tempsslStrings.equals("")) {
                    String[] tempSslkeyValArr = tempsslStrings.split(":");
                    // SSL Option is already present in config file
                    if (enableSsl) {
                        fullCmd += "sed -i -e 's/" + tempSslkeyValArr[0] + ":" + tempSslkeyValArr[1] + "/" + SFCBD_SSLV3
                            + ":true/g' " + SFCBD_CONFIG_FILE;
                    } else {
                        fullCmd += "sed -i -e 's/" + tempSslkeyValArr[0] + ":" + tempSslkeyValArr[1] + "/" + SFCBD_SSLV3
                            + ":false/g' " + SFCBD_CONFIG_FILE;
                    }

                } else {
                    // SSL Option is not present, ADD new entry
                    String appendEntry = "";
                    if (enableSsl) {
                        appendEntry += "echo " + SFCBD_SSLV3 + ":true";
                    } else {
                        appendEntry += "echo " + SFCBD_SSLV3 + ":false";
                    }
                    fullCmd = appendEntry + " >> " + SFCBD_CONFIG_FILE;
                }
            }

        } catch (Exception e) {
            System.err.println("Caught exception while constructing command for SFCBD configuration file updation");
        }

        if (!fullCmd.equals("")) {
            if (SSHUtil.executeRemoteSSHCommand(sshConnObjCurrentHost, fullCmd)) {
                isConfigUpdateSuccess = true;
            }
        } else {
            System.err.println("Could not construct command for updating SFCBD Configuration file");
        }

        return isConfigUpdateSuccess;
    }

    /**
     * Restore SFCBD security protocols to default, as it was before
     */
    private boolean
    restoreSFCBDSecProto(Integer restoreServicePort, List<String> tempRestoreSecProtos)
    {
        boolean restoreDone = false;
        try {
            List<String> currSecProtos = null;
            try {
                currSecProtos = securityProtocolScanner(currentHostName, restoreServicePort);
            } catch (Exception e) {
                System.out
                    .println("Caught exception while running security tool scanner, May be service itself is down");
                System.out.println("Continuing with restoring the configuration ...");
            }

            if (currSecProtos != null && secProtoChecker(currSecProtos, tempRestoreSecProtos)) {
                // Required protocols are ALREADY enabled on port, No
                // need to do anything here, print out exit
                System.out.println("Successfully restored security protocol configuration");
                return true;
            }

            // Required protocols needs to be enabled
            System.out.println("Reverting the security protocol configuration changes ...");

            if (SSHUtil.fileExistsOnHost(sshConnObjCurrentHost, SFCBD_CONFIG_BACKUP_FILE)) {
                if (SSHUtil.copyFileOnHost(sshConnObjCurrentHost, SFCBD_CONFIG_BACKUP_FILE, SFCBD_CONFIG_FILE)) {
                    // restart the services
                    System.out.println("Trying to restart service: " + SERVICE_SFCBD + ", for changes to take effect");
                    if (SSHUtil.restartService(sshConnObjCurrentHost, SERVICE_SFCBD)) {

                        /*
                         * Scan and Check if user requested protocols are indeed
                         * show up as enabled by running security scanner
                         */
                        System.out.println(
                            "Perform Post config file updation validation to check if"
                                + " user expected protocols show up with security scanner ...");
                        List<String> secProtosAfterChange = securityProtocolScanner(currentHostName, SFCBD_PORT);

                        if (secProtoListPostValidater(tempRestoreSecProtos, secProtosAfterChange)) {
                            System.out.println("Successfully restored : \"" + tempRestoreSecProtos.toString() + "\" "
                                + "protocols on SFCBD service on port: " + SFCBD_PORT);
                            System.out.println("------------------------------------------");
                            System.out.println("List of security protocols currenty enabled (AFTER change)");
                            System.out.println(secProtosAfterChange.toString());
                            System.out.println("------------------------------------------");
                            restoreDone = true;
                        } else {
                            System.err.println(
                                "Failed to restore : \"" + tempRestoreSecProtos.toString() + "\" "
                                    + "protocols on SFCBD service on port: " + SFCBD_PORT);
                        }

                    } else {
                        System.err.println(
                            "Could not restore SFCBD configuration file from backedup file: "
                                + SFCBD_CONFIG_BACKUP_FILE);
                    }

                } else {
                    System.err.println("Could not find backedup file: " + SFCBD_CONFIG_BACKUP_FILE);
                }
            }

        } catch (Exception e) {
            System.out.println("Caught an exception while restoring the SFCBD configurations");
        }

        return restoreDone;
    }

    /**
     * Restore rhttpproxy/hostd security protocols to default, as it was before
     */
    private boolean
    restoreESXiServiceSecProto(Integer restoreServicePort, List<String> tempRestoreSecProtos)
    {
        boolean restoreDone = false;
        try {
            List<String> currSecProtos = null;
            try {
                currSecProtos = securityProtocolScanner(currentHostName, restoreServicePort);
            } catch (Exception e) {
                System.out
                    .println("Caught exception while running security tool scanner, May be service itself is down");
                System.out.println("Continuing with restoring the configuration ...");
            }

            if (currSecProtos != null && secProtoChecker(currSecProtos, tempRestoreSecProtos)) {
                // Required protocols are ALREADY enabled on port, No
                // need to do anything here, print out exit
                System.out.println("Successfully restored security protocol configuration");
                return true;
            }
            // Required protocols needs to be enabled
            System.out.println("Reverting the security protocol configuration changes ...");

            /*
             * Get the disabled protocol list command for esxcli cmd execution
             */
            String disabledProtos = GetDisableProtocolString(tempRestoreSecProtos);
            if (disabledProtos != null) {
                String restoreFullCmd = "\"" + disabledProtos + "\"";
                String restoreServiceName = null;
                if (restoreServicePort == RHTTP_PROXY_PORT) {
                    if (is50Host) {
                        restoreFullCmd = CMD_HOSTD + restoreFullCmd;
                        restoreServiceName = SERVICE_HOSTD;
                    } else if(is51Host){
                        restoreFullCmd = CMD_RHTTP_PROXY_51 + restoreFullCmd;
                        restoreServiceName = SERVICE_RHTTPPROXY;
                    } else {
                        restoreFullCmd = CMD_RHTTP_PROXY + restoreFullCmd;
                        restoreServiceName = SERVICE_RHTTPPROXY;
                    }
                } else if (restoreServicePort == VSAN_VP_PORT) {
                    restoreFullCmd = CMD_VSAN_VP + restoreFullCmd;
                    restoreServiceName = SERVICE_VSAN_VP;
                }

                if (SSHUtil.executeRemoteSSHCommand(sshConnObjCurrentHost, restoreFullCmd)) {
                    System.out.println("Successfully executed the command for restoring security protocol list");

                    // Restart services and check if we were indeed
                    // successful in applying the changes
                    System.out
                        .println("Trying to restart service: " + restoreServiceName + ", for changes to take effect");
                    boolean restartedService = false;
                    if (is50Host && (restoreServicePort == RHTTP_PROXY_PORT)) {
                        SSHUtil.executeAsyncRemoteSSHCommand(sshConnObjCurrentHost, SERVICE_HOSTD + " stop");
                        if (SSHUtil.waitTillServiceisStopped(sshConnObjCurrentHost, SERVICE_HOSTD)) {
                            SSHUtil.executeAsyncRemoteSSHCommand(sshConnObjCurrentHost, SERVICE_HOSTD + " start");
                            restartedService  = SSHUtil.waitTillServiceisStarted(sshConnObjCurrentHost, SERVICE_HOSTD);
                        }
                    } else {
                        restartedService = SSHUtil.restartService(sshConnObjCurrentHost, restoreServiceName);
                    }

                    if (restartedService) {
                        /*
                         * Scan and Check if user requested protocols are indeed
                         * show up as enabled by running security scanner
                         */
                        System.out.println(
                            "Perform Post validation to check if"
                                + " user expected protocols show up with security scanner ...");
                        List<String> secProtosAfterRestore = securityProtocolScanner(
                            currentHostName,
                            restoreServicePort);

                        if (secProtoListPostValidater(secProtosAfterRestore, tempRestoreSecProtos)) {
                            System.out.println("Successfully restored security protocols : \""
                                + secProtosAfterRestore.toString() + "\" " + " on port: " + restoreServicePort);
                            restoreDone = true;
                        } else {
                            System.err.println(
                                "Failed to restore : \"" + tempRestoreSecProtos.toString() + "\" "
                                    + "protocols on port: " + restoreServicePort);
                        }

                    } else {
                        System.err.println("Could not restart service: " + restoreServiceName);
                    }

                } else {
                    System.err.println("Could not execute the command for updating security protocol list");
                }

            } else {
                System.err.println("Could not obtain command list to disable unwanted Security protocols");
            }

        } catch (Exception e) {
            System.out.println("Caught an exception while restoring the configuration");
        }

        return restoreDone;
    }

    /**
     * TLS Security protocol configuration for... Authd service
     */
    private boolean
    updateAuthdServiceSecProto(Integer portNum, List<String> user_secProtosToEnable, List<String> secProtosBeforeChange) throws Exception
    {
        boolean isUpdateSuccess = false;

        if (secProtosBeforeChange != null) {
            // Check if its valid security protocols combination - to enable
            if (enableSsl) {
                if (!secProtosBeforeChange.containsAll(defaultSecProtoList)) {
                    System.err.println(PROTO_SSLV3 + " protocol can not be enabled. Combination of SSL and TLS protocols"
                        + " to enable is NOT supported");
                    secProtosBeforeChange.add(PROTO_SSLV3);
                    System.err.println("Requested : " + secProtosBeforeChange);
                    List<String> supportedList = new ArrayList<>();
                    supportedList.addAll(defaultSecProtoList);
                    supportedList.add(PROTO_SSLV3);
                    System.err.println("Supported : " + supportedList.toString());
                    return false;
                }
            }

            /*
             * Store the Service port & security protocols already
             * enabled - for restoring purpose, if something goes wrong
             * with updation later.
             */
            enabledInpSecProtoMap.put(portNum, secProtosBeforeChange);

            if (secProtoChecker(secProtosBeforeChange, user_secProtosToEnable)) {
                // Required protocols are ALREADY enabled on port, No
                // need to do anything here, print out exit
                System.out.println("------------------------------------------");
                System.out.println("List of security protocols REQUESTED");
                System.out.println(user_secProtosToEnable.toString());
                System.out.println("------------------------------------------");
                System.out.println("List of security protocols currenty enabled");
                System.out.println(secProtosBeforeChange.toString());
                System.out.println("------------------------------------------");
                isUpdateSuccess = true;
            } else {
                // Required protocols needs to be enabled
                System.out.println("------------------------------------------");
                System.out.println("List of security protocols currenty enabled (BEFORE change)");
                System.out.println(secProtosBeforeChange.toString());
                System.out.println("------------------------------------------");
                System.out.println("List of security protocols REQUESTED, which YET TO BE ENABLED");
                System.out.println(user_secProtosToEnable.toString());
                System.out.println("------------------------------------------");

                System.out.println("Starting configuration ...");
                /*
                 * Get the disabled protocol list command for esxcli cmd
                 * execution. SSLv3 will be disabled by default
                 */
                String disabledProtos = GetDisableProtocolString(user_secProtosToEnable);

                if (disabledProtos != null) {
                    String authCmdToSetProtos = CMD_AUTHD;
                    if (is50Host) {
                        authCmdToSetProtos = CMD_AUTHD_50;
                    } else if (is51Host) {
                        authCmdToSetProtos = CMD_AUTHD_51;
                    }
                    String fullCmd = authCmdToSetProtos + "\"" + disabledProtos + "\"";

                    if (SSHUtil.executeRemoteSSHCommand(sshConnObjCurrentHost, fullCmd)) {
                        System.out.println("Successfully executed the command for updating security protocol list");
                        /*
                         * Scan and Check if user requested protocols are indeed
                         * show up as enabled by running security scanner
                         */
                        System.out.println(
                            "Perform Post validation to check if"
                                + " user expected protocols are indeed persisted ...");
                        List<String> secProtosAfterChange = authdProtocolFetcher(currentHostName, portNum);

                        if (secProtoListPostValidater(user_secProtosToEnable, secProtosAfterChange)) {
                            System.out.println("Successfully enabled : \"" + user_secProtosToEnable.toString() + "\" "
                                + "protocols on port: " + portNum);
                            System.out.println("------------------------------------------");
                            System.out.println("List of security protocols currenty enabled (AFTER change)");
                            System.out.println(secProtosAfterChange.toString());
                            System.out.println("------------------------------------------");
                            isUpdateSuccess = true;
                        } else {
                            System.err.println(
                                "Failed to enable : \"" + user_secProtosToEnable.toString() + "\" " + "protocols port: "
                                    + portNum);
                        }

                    } else {
                        System.err.println("Could not execute the command for updating security protocol list");
                    }
                } else {
                    System.err.println("Could not obtain command list to disable unwanated Security protocols");
                }
            }

        } else {
            System.err.println("Could not fetch list of currently enabled security protocols");
        }

        return isUpdateSuccess;
    }


    /**
     * Read configuration file and determine the current enabled protocols
     */
    private List<String>
    authdProtocolFetcher(String hostName, Integer portNum) throws Exception
    {
        List<String> allDefaultProtos = new ArrayList<String>();
        String listAuthdProtosCmd = CMD_AUTHD_LIST_PROTOS;

        if (is50Host) {
            listAuthdProtosCmd = CMD_AUTHD_LIST_PROTOS_50;
        } else if (is51Host) {
            listAuthdProtosCmd = CMD_AUTHD_LIST_PROTOS_51;
        }

        String cmdOutput = SSHUtil.getSSHOutputStream(sshConnObjCurrentHost, listAuthdProtosCmd);
        cmdOutput = cmdOutput.substring(cmdOutput.indexOf("String Value:"), cmdOutput.indexOf("Default String Value:"))
            .replace("String Value:", "").trim();

        if (cmdOutput.equals("")) {
            allDefaultProtos.add(PROTO_SSLV3);
            allDefaultProtos.addAll(defaultSecProtoList);
        } else if (cmdOutput.equals("sslv3")) {
            allDefaultProtos.addAll(defaultSecProtoList);
        }

        return allDefaultProtos;
    }

    /**
     * Get Disabled Protocol list
     */
    private String
    GetDisableProtocolString(List<String> user_secProtosToEnable)
    {
        String listOfDisabledProtocol = null;

        if (user_secProtosToEnable.contains(PROTO_SSLV3)) {
            listOfDisabledProtocol = "";
        } else {
            listOfDisabledProtocol = PROTO_SSLV3;
        }

        return listOfDisabledProtocol;
    }

    /**
     * Check if port is already running with user requested security protocols
     */
    private Boolean
    secProtoChecker(List<String> currList, List<String> expList)
    {
        Boolean areListsEqual = null;
        if (currList != null && currList.size() > 0) {
            areListsEqual = false;
            if (currList.containsAll(expList) && currList.size() == expList.size()) {
                System.out.println("Requested security protocol(s) is/are already enabled");
                areListsEqual = true;
            } else {
                System.out.println("Requested security protocol(s) needs to be enabled");
            }
        }
        return areListsEqual;
    }

    /**
     * Security protocol list validator - before and after modification
     * validates for number of elements and values.
     */
    private boolean
    secProtoListPostValidater(List<String> expList, List<String> afterChange) throws InterruptedException
    {
        boolean areListsEqual = false;

        if (afterChange != null && afterChange.size() > 0) {
            if (afterChange.size() == (expList.size())) {
                System.out
                    .println("Count of Protocol enabled list (" + "after updation of config file) is as expected");
                for (String tempSecProto : afterChange) {
                    if (expList.contains(tempSecProto)) {
                        System.out.println("Security protocol: \"" + tempSecProto + "\" found enabled");
                        areListsEqual = true;
                    } else {
                        System.err.println(
                            "Found unexpected Security protocol: \"" + tempSecProto
                                + "\" in the list after updation of config file");
                        areListsEqual = false;
                        break;
                    }
                }
            } else {
                System.err.println(
                    "Number of elements in the protocol enabled list "
                        + "(after updation of config file) is not as expected");
                Thread.sleep(100);
                System.out.println(" -------- BEFORE -------");
                System.out.println(expList.toString());
                System.out.println(" -------- AFTER -------");
                System.out.println(afterChange.toString());
                areListsEqual = false;
            }
        } else {
            System.err.println("Security Protocols list either before/After change is null");
        }
        return areListsEqual;
    }

    /**
     * Start SSH Services
     */
    private boolean
    startSSHService(HostSystem hostSys) throws Exception
    {
        boolean startedService = false;

        try {
            HostServiceSystem hss = hostSys.getHostServiceSystem();
            for (HostService tempHs : hss.getServiceInfo().getService()) {
                String id = tempHs.getKey();
                if (SSH_SERVICE.equalsIgnoreCase(id)) {
                    if (!(getServiceState(hostSys, id).equalsIgnoreCase(SERVICE_RUNNING))) {
                        hss.startService(id);

                        // Check if we indeed were successful in starting services
                        if (getServiceState(hostSys, id).equalsIgnoreCase(SERVICE_RUNNING)) {
                            System.out.println(SSH_SERVICE + " service is in running state now");
                            startedService = true;

                            // below flag is for cleanup purpose - restoring
                            // previous state
                            cleanupStopSSHService = true;
                            break;
                        } else {
                            System.err.println(SSH_SERVICE + " service could not be started");
                            break;
                        }
                    } else {
                        System.out.println(SSH_SERVICE + " service is already in running state");
                        startedService = true;
                        break;
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("Caught exception while starting SSH service");
        }

        return startedService;
    }

    /**
     * Stop SSH Services
     */
    private boolean
    stopSSHService(HostSystem hostSys) throws Exception
    {
        boolean stoppedService = false;

        try {
            HostServiceSystem hss = hostSys.getHostServiceSystem();
            for (HostService tempHs : hss.getServiceInfo().getService()) {
                String id = tempHs.getKey();
                if (SSH_SERVICE.equalsIgnoreCase(id)) {
                    if (!(getServiceState(hostSys, id).equalsIgnoreCase(SERVICE_STOPPED))) {
                        hss.stopService(id);

                        // Check if we indeed were successful in stopping services
                        if (getServiceState(hostSys, id).equalsIgnoreCase(SERVICE_STOPPED)) {
                            System.out.println(SSH_SERVICE + " service is stopped now");
                            stoppedService = true;
                            break;
                        } else {
                            System.err.println(SSH_SERVICE + " service could not be stopped");
                            break;
                        }
                    } else {
                        System.out.println(SSH_SERVICE + " service is already stopped");
                        stoppedService = true;
                        break;
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("Caught exception while turning off SSH service");
        }

        return stoppedService;
    }

    /**
     * Get ServiceState
     */
    private String
    getServiceState(HostSystem hs, String id) throws Exception
    {
        String serviceState = null;

        HostServiceSystem hss = hs.getHostServiceSystem();
        for (HostService tempHsService : hss.getServiceInfo().getService()) {
            if (id.equalsIgnoreCase(tempHsService.getKey())) {
                if (tempHsService.isRunning()) {
                    serviceState = SERVICE_RUNNING;
                } else {
                    serviceState = SERVICE_STOPPED;
                }
            }
        }

        return serviceState;
    }

    /**
     * Login method to VC
     */
    private ServiceInstance
    loginTovSphere(String url)
    {
        try {
            si = new ServiceInstance(new URL(url), userName, password, true);
        } catch (Exception e) {
            System.out.println("Caught exception while logging into vSphere server");
            e.printStackTrace();
        }
        return si;
    }

    /**
     * All connected hosts
     */
    private List<HostSystem>
    retrieveHosts()
    {
        // get first datacenters in the environment.
        InventoryNavigator navigator = new InventoryNavigator(si.getRootFolder());

        List<HostSystem> activeHosts = null;
        try {
            ManagedEntity[] allTempHosts = navigator.searchManagedEntities(HOST_MOR_TYPE);

            if (allTempHosts != null) {
                activeHosts = new ArrayList<HostSystem>();
                for (ManagedEntity host : allTempHosts) {
                    HostSystem tempHostSys = (HostSystem) host;
                    HostRuntimeInfo hostruntimeInfo = tempHostSys.getRuntime();
                    if ((hostruntimeInfo.getConnectionState().equals(HostSystemConnectionState.connected))) {
                        activeHosts.add(tempHostSys);
                    }
                }
            }

        } catch (Exception e) {
            System.err.println("[Error] Unable to retrieve Hosts from inventory");
            e.printStackTrace();
        }
        return activeHosts;
    }

    /**
     * Return hosts reference
     */
    private HostSystem retrieveSingleHostSys(String hostName) {
        HostSystem hostSys = null;

        // get first datacenters in the environment.
        InventoryNavigator navigator = new InventoryNavigator(si.getRootFolder());

        try {
            if (isStandAloneHost) {
                hostSys = (HostSystem) navigator.searchManagedEntities(HOST_MOR_TYPE)[0];
            } else {
                hostSys = (HostSystem) navigator.searchManagedEntity(HOST_MOR_TYPE, hostName);
            }

        } catch (Exception e) {
            System.err.println("Unable to retrieve provided Host's HostSystem object from inventory");
        }
        return hostSys;
    }

    /*
     * Class to hold the TLS configuration result of a host.
     * Consist of hostname, port configured - previous TLS versions, TLS versions after updation
     */
    class HostSSLResultHolderClass
    {
        Integer port;
        String beforeProtoList;
        String afterProtoList;
    }
}