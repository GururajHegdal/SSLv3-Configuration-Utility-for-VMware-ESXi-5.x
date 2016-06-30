/**
 * Utility program to handle SSH Connection to ESXi hosts, running commands,
 * starting/stopping/restaring of services including management processes running
 * on VMware ESXi host
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
 * @author VMware
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
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ch.ethz.ssh2.ChannelCondition;
import ch.ethz.ssh2.Connection;
import ch.ethz.ssh2.InteractiveCallback;
import ch.ethz.ssh2.Session;
import ch.ethz.ssh2.StreamGobbler;

public class SSHUtil
{
    public static final long SSHCOMMAND_TIMEOUT = 300;
    public static final String SSH_ERROR_STREAM = "SSHErrorStream";
    public static final String SSH_OUTPUT_STREAM = "SSHOutputStream";
    public static final String SSH_EXIT_CODE = "SSHExitCode";
    public static final String SERVICE_STATE_RUNNING = "RUNNING";
    public static final String SERVICE_STATE_NOT_RUNNING = "NOT RUNNING";
    public static final String SERVICE_STATE_STOPPED = "STOPPED";

    /**
     * Connects to the remote host using SSH
     *
     * @param hostName host to connect
     * @param userName username to authenticate
     * @param password password to authenticate
     * @return SSH Connection
     * @throws Exception
     */
    public static Connection
    getSSHConnection(String hostName, String userName, final String password) throws Exception
    {
        Connection conn = new Connection(hostName);
        String[] strArray;
        // Now try to connect
        conn.connect();

        try {
            strArray = conn.getRemainingAuthMethods(userName);
        } catch (IOException e) {
            throw new Exception("Getting Remaining AuthMethods failed with IOException: " + e.getMessage());
        }
        if (strArray == null) {
            System.out.println("conn.getRemainingAuthMethods returns null");
            try {
                conn.authenticateWithPassword(userName, password);
            } catch (Exception e) {
                String warning = "";
                if (password.equals("")) {
                    warning += " : " + "Warning: Implementation of this package "
                        + "does not allow empty passwords for authentication";
                }
                throw new Exception("Authentication with password failed: " + e.getMessage() + warning);
            }
        } else {
            List<String> authMethods = Arrays.asList(strArray);
            // Authenticate
            if (authMethods.contains("password")) {
                if (!conn.authenticateWithPassword(userName, password)) {
                    throw new Exception("Password based authentication failed.");
                }
            } else if (authMethods.contains("keyboard-interactive")) {
                InteractiveCallback cb = new InteractiveCallback() {
                    @Override
                    public String[] replyToChallenge(String name, String instruction, int numPrompts, String[] prompt,
                        boolean[] echo) throws Exception {
                        /*
                         * Going with the assumption that the only thing servers
                         * asks for is password
                         */
                        String[] response = new String[numPrompts];
                        for (int i = 0; i < response.length; i++) {
                            response[i] = password;
                        }
                        return response;
                    }
                };
                if (!conn.authenticateWithKeyboardInteractive(userName, cb)) {
                    throw new Exception("Keyboard-interactive based authentication failed.");
                }
            } else {
                throw new Exception("SSH Server doesnt support password or keyboard-interactive logins");
            }
        }
        System.out.println("Successfully connected to the remote ssh host: " + hostName);
        return conn;
    }

    /**
     * Closes the SSH Connection to the remote host
     *
     * @param conn SSH Connection
     * @return true if successful, exception raised otherwise
     * @throws Exception
     */
    public static boolean
    closeSSHConnection(Connection conn) throws Exception
    {
        boolean success = true;
        if (conn != null) {
            conn.close();
            System.out.println("SSH Connection closed");
        }
        return success;
    }

    /**
     * Executes the given command on the remote host using ssh
     *
     * @param conn SSH Connection
     * @param command Command to be executed
     * @param timeout Timeout in seconds
     * @return HashMap with both error and output stream contents
     * @throws IOException , Exception
     */
    public static Map<String, String>
    getRemoteSSHCmdOutput(Connection conn, String command, long timeout) throws Exception
    {
        Session session = null;
        InputStream stderr = null;
        InputStream stdout = null;
        Map<String, String> returnData = new HashMap<String, String>();
        try {
            session = conn.openSession();
            System.out.println("Running command '" + command + "' with timeout of " + timeout + " seconds");
            session.execCommand(command);
            // Wait until command completes or times out
            int result = session.waitForCondition(ChannelCondition.EOF, timeout * 1000);
            if ((result & ChannelCondition.TIMEOUT) != 0) {
                System.out.println("A timeout occured while waiting for data from the " + "server");
                if (session != null) {
                    session.close();
                }
                return returnData;
            }
            stderr = new StreamGobbler(session.getStderr());
            stdout = new StreamGobbler(session.getStdout());
            // populate output stream
            StringBuffer outputDataStream = getInputStreamString(stdout);
            returnData.put(SSH_OUTPUT_STREAM, outputDataStream.toString());
            // populate error stream
            StringBuffer errorDataStream = getInputStreamString(stderr);
            returnData.put(SSH_ERROR_STREAM, errorDataStream.toString());
            Integer exitStatus = session.getExitStatus();
            if (errorDataStream.length() != 0) {
                // command execution failed ( even if execution of one command fails)
                System.err.println("SSH session ExitCode: " + exitStatus);
                System.err.println("Error while executing '" + command + "' command on remote ssh host");
                System.err.println("Error Stream: \n" + errorDataStream);
                System.out.println("Output Stream: \n" + outputDataStream);
            } else {
                // command executed successfully , populate the output stream
                System.out.println("SSH session ExitCode: " + exitStatus);
                System.out.println("Successfully executed '" + command + "' command on remote ssh host");
            }
        } finally {
            if (session != null) {
                session.close();
            }
            if (stderr != null) {
                stderr.close();
            }
            if (stdout != null) {
                stdout.close();
            }
        }
        // returnData must contain Error as well as output stream
        // and the test cases would decide accordingly
        return returnData;
    }

    /**
     * Populate a StringBuffer with the contents of an InputStream
     *
     * @param out InputStream to process
     * @return StringBuffer object containing InputStream contents
     * @throws IOException
     */
    public static StringBuffer
    getInputStreamString(final InputStream in) throws Exception
    {
        StringBuffer out = null;
        if (in != null) {
            final BufferedReader reader = new BufferedReader(new InputStreamReader(in));
            try {
                out = new StringBuffer();
                String tmp = "";
                while ((tmp = reader.readLine()) != null) {
                    out.append(tmp + "\n");
                }
            } finally {
                if (reader != null) {
                    reader.close();
                }
            }
        } else {
            System.err.println("InputStream parameter is null");
        }
        return out;
    }

    /**
     * Method to execute and return command output, without having to specify timeout.
     * default timeout is considered.
     */
    public static Map<String, String>
    getRemoteSSHCmdOutput(Connection conn, String command) throws Exception
    {
        return getRemoteSSHCmdOutput(conn, command, SSHCOMMAND_TIMEOUT);
    }

    /**
     * Executes the given command on the remote host using ssh
     *
     * @param conn SSH Connection
     * @param command Command to be executed
     * @param maxTimeout The max number of seconds to wait for the command to
     *            execute
     * @return true, if successful, false, otherwise
     * @throws IOException , Exception
     */
    public static boolean
    executeRemoteSSHCommand(Connection conn, String command, long maxTimeout) throws Exception
    {
        boolean success = false;
        Session session = null;
        try {
            session = conn.openSession();
            success = executeRemoteSSHCommand(session, command, maxTimeout);
        } finally {
            if (session != null) {
                session.close();
            }
        }
        return success;
    }

    /**
     * Asynchronously executes the given command on the remote host using ssh. It
     * doesn't waits for command to complete on the remote host.
     *
     * @param Connection SSH Connection
     * @param command Command to be executed
     * @throws IOException , Exception
     */
    public static void
    executeAsyncRemoteSSHCommand(Connection conn, String command) throws Exception
    {
        Session session = null;
        try {
            session = conn.openSession();
            System.out.println(
                "Running command '" + command + "' asynchronously. "
                    + " It doesn't wait for command to complete on remote host.");
            session.execCommand(command);
            int sleep = 10;
            System.out.println("Sleep for " + sleep + " seconds for command to kick in.");
            Thread.sleep(sleep * 1000);

        } finally {
            if (session != null) {
                session.close();
            }
        }
    }

    /**
     * Executes the given command on the remote host using ssh
     *
     * @param session session of a SSH Connection
     * @param command Command to be executed
     * @param maxTimeout The max number of seconds to wait for the command to
     *            execute
     * @return true, if successful, false, otherwise
     * @throws IOException , Exception
     */
    public static boolean
    executeRemoteSSHCommand(Session session, String command, long maxTimeout) throws Exception
    {
        StreamReader isReader = null;
        StreamReader errReader = null;
        String errorDataStream = null;
        boolean success = false;

        try {
            System.out.println("Running command '" + command + "' with timeout of " + maxTimeout + " seconds");
            session.execCommand(command);

            /*
             * Start stream reader for standard output
             */
            isReader = new StreamReader(new BufferedReader(new InputStreamReader(session.getStdout())), "InputStream");

            Thread outThread = new Thread(isReader);
            outThread.start();

            /*
             * Start stream reader for error stream
             */
            errReader = new StreamReader(new BufferedReader(new InputStreamReader(session.getStderr())), "ErrorStream");
            Thread errThread = new Thread(errReader);
            errThread.start();

            /*
             * Wait until command completes or times out
             */
            int result = session.waitForCondition(ChannelCondition.EOF, maxTimeout * 1000);
            if ((result & ChannelCondition.TIMEOUT) != 0) {
                System.out.println("A timeout occured while waiting for data from the " + "server");
            } else {
                /*
                 * It is possible that the errReader thread has not completely
                 * finished saving error data at this point, since
                 * waitForCondition and errReader are running concurrently.
                 * Sleep 2 seconds to allow errReader thread extra time to
                 * finish.
                 */
                Thread.sleep(2000);
                errorDataStream = errReader.getDataStream();
                if ((errorDataStream == null || errorDataStream.length() == 0)) {
                    /*
                     * Some server implementations do not return an exit status
                     */
                    Integer exitStatus = session.getExitStatus();
                    if (exitStatus == null) {
                        System.out.println("'" + command + "' command did not return an " + "exit status value");
                        success = true;
                    } else {
                        /*
                         * Nonzero exit status value is an error
                         */
                        System.out
                            .println("'" + command + "' command returned an exit " + "status value: " + exitStatus);
                        if (exitStatus.equals(0)) {
                            success = true;
                        } else {
                            System.out.println("'" + command + "' command returned a nonzero " + "exit status value");
                        }
                    }
                } else {
                    System.out.println("Error data stream contains a message");
                    if (errorDataStream.contains("Terminating watchdog process")
                        || errorDataStream.contains("Picked up JAVA_TOOL_OPTIONS:")) {
                        // ignore this error mesg.
                        success = true;
                    }

                    String output = isReader.getDataStream();
                }
            }
            if (success) {
                System.out.println("Successfully executed '" + command + "' command on remote ssh host");
            }
        } finally {
            if (isReader != null) {
                isReader.stopThread();
            }
            if (errReader != null) {
                errReader.stopThread();
            }
        }
        return success;
    }

    /**
     * Executes the given command on the remote host using ssh. This method calls
     * an overloaded method with a hard-coded delay of .SSHCOMMAND_TIMEOUT
     * seconds.
     *
     * @param conn SSH Connection
     * @param command Command to be executed
     * @return true, if successful, false, otherwise
     */
    public static boolean
    executeRemoteSSHCommand(Connection conn, String command) throws Exception
    {
        // Pass default timeout seconds
        return executeRemoteSSHCommand(conn, command, SSHCOMMAND_TIMEOUT);
    }

    /**
     * Check if file exists on a remote host
     *
     * @param conn Connection to remote host
     * @param filePath path to file
     * @return true, if file exists, false, otherwise
     * @throws Exception
     */
    public static boolean
    fileExistsOnHost(Connection conn, String filePath) throws Exception
    {
        boolean fileExists = false;
        if (conn != null) {
            fileExists = SSHUtil.executeRemoteSSHCommand(conn, "ls " + filePath);
            if (fileExists) {
                System.out.println("File exists: " + filePath);
            } else {
                System.out.println("File does not exist: " + filePath);
            }
        } else {
            System.err.println("Connection is null");
        }
        return fileExists;
    }

    /**
     * Copy a file on remote host from its source to the specified destination.
     */
    public static boolean
    copyFileOnHost(Connection conn, String src, String dest) throws Exception
    {
        boolean taskSuccess = false;
        /*
         * Call ssh command to copy the file from source to destination
         * location
         */
        if (conn != null) {
            if (src != null && src.length() > 0 && dest != null && dest.length() > 0) {
                taskSuccess = executeRemoteSSHCommand(conn, "cp " + src + " " + dest);

                if (taskSuccess) {
                    System.out.println("Successfully copied file " + src + " to " + dest);
                } else {
                    System.err.println("Failed to copy file " + src + " to " + dest);
                }
            } else {
                System.err.println("The source and/or destination file names are invalid");
            }
        } else {
            System.err.println("SSH Connection object is null");
        }

        return taskSuccess;
    }

    /**
     * Executes the given command on the remote host using ssh and returns only
     * the OutputStream string
     *
     * @param conn SSH Connection
     * @param command Command to be executed
     * @param timeout Timeout in seconds
     * @return String containing only the OutputStream value
     * @throws Exception
     */
    public static String
    getSSHOutputStream(Connection conn, String command, long timeout) throws Exception
    {
        String output = null;
        String key = "SSHOutputStream";
        try {
            Map<String, String> outputMap = getRemoteSSHCmdOutput(conn, command, timeout);
            if (outputMap.containsKey(key)) {
                output = outputMap.get(key);
            } else {
                System.out.println("SSH output does not contain any output stream");
            }
        } catch (Exception e) {
            System.err.println("Exception thrown: " + e.getStackTrace());
        }
        return output;
    }

    public static String
    getSSHOutputStream(Connection conn, String command) throws Exception
    {
        return getSSHOutputStream(conn, command, SSHCOMMAND_TIMEOUT);
    }

    /**
     * Method to start a service on a host machine by using SSH. The host should
     * have a SSH server running on it.
     */
    public static boolean startService(Connection conn, String service) throws Exception {
        boolean result = false;
        if (conn != null) {
            String command = service + " start";

            if (SSHUtil.executeRemoteSSHCommand(conn, command, SSHCOMMAND_TIMEOUT)) {
                if (waitTillServiceisStarted(conn, service)) {
                    System.out.println("Successfully started the service: " + service);
                    result = true;
                    /*
                     * Sleep for few seconds, before exiting out, as right after service is restarted
                     * it might take sometime to become operational
                     */
                    Thread.sleep(5000);
                } else {
                    System.err.println("Failed to start the service: " + service);
                }
            } else {
                System.err.println("Failed in executing the command for starting service: " + service);
            }

        } else {
            System.err.println("Connection is null");
        }
        return result;
    }

    /**
     * Method to re-start a service on a host machine by using SSH. The host should
     * have a SSH server running on it.
     */
    public static boolean
    restartService(Connection conn, String service) throws Exception
    {
        boolean result = false;
        if (conn != null) {
            if (stopService(conn, service)) {
                // Sleep for couple of seconds before querying & starting for the state of the process
                Thread.sleep(4000);
                if (startService(conn, service)) {
                    System.out.println("Successfully restarted the service: " + service);
                    result = true;
                } else {
                    System.err.println("Failed to restart the service: " + service);
                }
            } else {
                System.err.println("Connection is null");
            }
        }
        return result;
    }

    /**
     * Checks whether the specified service is running on the provided host
     */
    public static boolean
    isServiceRunning(Connection conn, String service) throws Exception
    {
        boolean isServiceRunning = false;
        Map<String, String> sshResponse = null;
        String output = null;
        String command = null;
        command = service + " status";
        sshResponse = SSHUtil.getRemoteSSHCmdOutput(conn, command);
        output = sshResponse.get(SSH_OUTPUT_STREAM);
        if (output != null && (!output.toUpperCase().contains(SERVICE_STATE_NOT_RUNNING))
            && output.toUpperCase().contains(SERVICE_STATE_RUNNING)) {
            isServiceRunning = true;
            System.out.println("Service " + service + " is running");
        } else {
            System.out.println("Service " + service + " is not running");
        }

        return isServiceRunning;
    }

    /**
     * Checks whether the specified service is stopped on the provided host
     */
    public static boolean
    waitTillServiceisStopped(Connection conn, String service) throws Exception
    {
        boolean isServiceStopped = false;
        int waitCount = 24;
        String command = null;
        Map<String, String> sshResponse = null;
        String output = null;
        command = service + " status";
        while (waitCount != 0) {
            sshResponse = SSHUtil.getRemoteSSHCmdOutput(conn, command);
            output = sshResponse.get(SSH_OUTPUT_STREAM);
            System.out.println("Printing the " + command + " command output");
            System.out.println(output);
            if (output != null && (output.toUpperCase().contains(SERVICE_STATE_STOPPED)
                || output.toUpperCase().contains(SERVICE_STATE_NOT_RUNNING))) {
                isServiceStopped = true;
                System.out.println("Service " + service + " is stopped");
                break;
            } else {
                waitCount--;
                System.out.println("Service " + service + " is not stopped");
                System.out.println("Sleeping for 10 secs before querying again for the service status");
                Thread.sleep(10000);
            }
        }

        return isServiceStopped;
    }

    /**
     * Checks whether the specified service is stopped on the provided host
     */
    public static boolean
    waitTillServiceisStarted(Connection conn, String service) throws Exception
    {
        boolean isServiceStarted = false;
        int waitCount = 24;
        while (waitCount != 0) {
            if (isServiceRunning(conn, service)) {
                isServiceStarted = true;
                System.out.println("Service " + service + " is started");
                break;
            } else {
                waitCount--;
                System.out.println("Service " + service + " is not started");
                System.out.println("Sleeping for 10 secs before querying again for the service status");
                Thread.sleep(10000);
            }
        }

        return isServiceStarted;
    }

    /**
     * Method to stop a service on a host machine by using SSH. The host should
     * have a SSH server running on it.
     */
    public static boolean
    stopService(Connection conn, String service) throws Exception
    {
        boolean result = false;
        if (conn != null) {
            String command = service + " stop";
            if(SSHUtil.executeRemoteSSHCommand(conn, command, SSHCOMMAND_TIMEOUT)) {
                if (waitTillServiceisStopped(conn, service)) {
                    System.out.println("Successfully stopped the service " + service);
                    result = true;
                } else {
                    System.err.println("Failed to stop the service " + service);
                }
            } else {
                System.err.println("Failed in executing the command for stopping service: " + service);
            }

        } else {
            System.err.println("connection is null");
        }
        return result;
    }
}