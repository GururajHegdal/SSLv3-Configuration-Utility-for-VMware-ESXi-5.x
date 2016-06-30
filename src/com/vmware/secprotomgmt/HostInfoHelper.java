/**
 * Utility program to create hosts information file for ESXi hosts
 * present in vCenter Server inventory and read the same when provided
 * as input.
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

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashMap;
import java.util.List;

import com.vmware.secprotomgmt.ESXi5xSSLConfigUpdater.HostSSLResultHolderClass;
import com.vmware.vim25.mo.HostSystem;

public class HostInfoHelper
{

    /**
     * Get hosts list from VC and create a CSV file populating hosts related
     * information such as, hostname/IP, version, SSL Configurable or not,
     * username, password
     */
    public static boolean
    createHostsInformationFile(List<HostSystem> allHostSys) throws IOException
    {
        boolean hostsInfoFileCreated = false;
        FileWriter fw = null;
        BufferedWriter bw = null;
        try {
            String dir = Paths.get(".").toAbsolutePath().normalize().toString();
            String fileName = "hostsinfo.csv";
            File file = new File(dir, fileName);

            System.out.println("Trying to create  ESXi hosts information file: " + dir + "/" + fileName);
            if (file.createNewFile()) {
                System.out.println("Successfully created file");
                System.out.println("Start writing ESXi hosts information into file");
                fw = new FileWriter(file.getAbsoluteFile());
                bw = new BufferedWriter(fw);
                bw.write("HOSTNAME," + "VERSION," + "USERNAME," + "PASSWORD," + "PASSWORD_ENCRYPTED\n");

                // Write Host contents into the file
                for (HostSystem tempHostSys : allHostSys) {
                    bw.write(
                        tempHostSys.getName() + "," + tempHostSys.getConfig().getProduct().getFullName() + "," + " "
                            + "," + " " + "," + "no\n");
                }
                System.out.println(
                    "ESXi Hosts information has been successfully populated into file: " + dir + "/" + fileName);
                hostsInfoFileCreated = true;
            } else {
                System.err.println(
                    "Could not create ESXi hosts information file. Check if the file that we want to create already exists");
            }
        } catch (Exception e) {
            System.err.println("Could not create/populate ESXi hosts data into hosts information file");
        } finally {
            // cleanup the writer handles
            if (bw != null)
                bw.close();
            if (fw != null)
                fw.close();
        }

        return hostsInfoFileCreated;
    }

    /**
     * Class to hold ESXi hosts information - Name, version, user credentials (for logging into host) and etc
     */
    public static class HostsInfoHolderClass
    {
        String hostName;
        String hostVer;
        String username;
        String password;
        HostSystem hostSys;
    }

    /**
     * Method to read the hosts information file and push them into array of
     * HostsInfoHolderClass objects
     */
    public static
    List<HostsInfoHolderClass> readHostsInfoFile(File fileHandle)
    {
        List<HostsInfoHolderClass> hostsListFromFile = null;
        try {
            FileReader existingFileRdr = new FileReader(fileHandle);
            BufferedReader br = new BufferedReader(existingFileRdr);
            int lineNum = 0;
            String line;
            String key = null;
            hostsListFromFile = new ArrayList<HostsInfoHolderClass>();
            while ((line = br.readLine()) != null) {
                if (lineNum > 0) { // Ignore the header of file
                    String[] hostFields = line.split(",");
                    HostsInfoHolderClass obj = new HostsInfoHolderClass();
                    obj.hostName = hostFields[0].trim();
                    obj.hostVer = hostFields[1].trim();
                    obj.username = hostFields[2].trim();

                    String isPwdEncrypted = hostFields[4].trim();
                    if (isPwdEncrypted.equalsIgnoreCase("yes")) {
                        System.out.println(
                            "ESXi host- " + obj.hostName + " password has been encrypted. Trying to decrypt ...");
                        String encryptedStr = hostFields[3].trim();

                        if (lineNum == 1 || key == null) {
                            /*
                             * Only for the first time request user to provide information to decrypt the password
                             * for rest of the iterations, same key can be used for decryption
                             */
                            List<String> decryptedData = PasswdEncrypter.decryptValueWithUserEnteredKey(encryptedStr);
                            if (decryptedData != null && decryptedData.size() == 2) {
                                key = decryptedData.get(0);
                                obj.password = decryptedData.get(1);
                            } else {
                                System.err.println(
                                    "Skipping ESXi host: " + obj.hostName + ", as we failed to decrypt password");
                                ++lineNum;
                                continue;
                            }
                        } else {
                            key = key.trim(); // Removing leading or trailing spaces
                            String tempDecryptedPwd = PasswdEncrypter.decrypt(key, encryptedStr);
                            if (tempDecryptedPwd != null) {
                                System.out.println("Successfully decrypted ESXi password for host: " + obj.hostName);
                                //System.out.println("[TESTED] Password is:" + tempDecryptedPwd);
                                obj.password = tempDecryptedPwd;
                            } else {
                                System.err.println(
                                    "Skipping ESXi host: " + obj.hostName + ", as we failed to decrypt password");
                                ++lineNum;
                                continue;
                            }
                        }

                    } else {
                        obj.password = hostFields[3].trim();
                    }

                    hostsListFromFile.add(obj);
                }
                ++lineNum;
            }
            br.close();
        } catch (Exception e) {
            System.err.println("Caught exception while retrieving hosts information from file");
            hostsListFromFile = null;
        }

        return hostsListFromFile;
    }

    /**
     * Write the SSL configuration result of all hosts into a CSV file
     */
    public static boolean
    createHostsSSLConfigResultFile(HashMap<String, List<HostSSLResultHolderClass>> resultHoldingObj,
        String reqToenableProtos) throws IOException
    {
        boolean hostsResultFileCreated = false;
        FileWriter fw = null;
        BufferedWriter bw = null;
        try {
            String dir = Paths.get(".").toAbsolutePath().normalize().toString();
            String timeStamp = new SimpleDateFormat("yyyyMMdd_HHmmss").format(Calendar.getInstance().getTime());
            String fileName = "HostsSSLConfigResult-" + timeStamp + ".csv";
            File file = new File(dir, fileName);

            System.out.println("Trying to create  ESXi hosts result file: " + dir + "/" + fileName);
            if (file.createNewFile()) {
                System.out.println("Successfully created file");
                System.out.println("Start writing ESXi hosts SSL Configuration result into file");
                fw = new FileWriter(file.getAbsoluteFile());
                bw = new BufferedWriter(fw);
                bw.write("@@@@@@@@@@@@@@@@@ ALL HOSTS SSL CONFIGURATION RESULT @@@@@@@@@@@@@@@@@,\n");
                ESXi5xSSLConfigUpdater tempParentClassObj = new ESXi5xSSLConfigUpdater();
                for (String tempHostName : resultHoldingObj.keySet()) {
                    bw.write("HOST: " + tempHostName + ",\n");
                    bw.write("Protocols to ENABLE (as requested by user) : " + reqToenableProtos.replaceAll(",", " ") + ",\n");
                    bw.write("SERVICE NAME," + "PORT," + "Before SSL Protocols," + "After SSL Protocols\n");

                    for (HostSSLResultHolderClass tempSSLResultObj : resultHoldingObj.get(tempHostName)) {
                        String serviceName = tempParentClassObj.portToServiceNameMap.get(tempSSLResultObj.port);
                        String port = tempSSLResultObj.port.toString();
                        String beforeProtoList = tempSSLResultObj.beforeProtoList.replaceAll(",", " ");
                        String afterProtoList = tempSSLResultObj.afterProtoList.replaceAll(",", " ");
                        bw.write(serviceName + "," + port + "," + beforeProtoList + "," + afterProtoList + "\n");
                    }
                    bw.write(",\n");
                }
                   System.out.println(
                    "ESXi Hosts information has been successfully populated into file: " + dir + "/" + fileName);
                hostsResultFileCreated = true;
            } else {
                System.err.println(
                    "Could not create ESXi result information file. Check if the file that we want to create already exists");
            }
        } catch (Exception e) {
            System.err.println("Could not create/populate ESXi hosts data into hosts information file");
        } finally {
            // cleanup the writer handles
            if (bw != null)
                bw.close();
            if (fw != null)
                fw.close();
        }

        return hostsResultFileCreated;
    }
}