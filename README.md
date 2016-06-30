# SSLv3-Configuration-Utility-for-VMware-ESXi-5.x
SSLv3 Security protocol configuration utility for VMware ESXi Server 5.x (5.0/5.1/5.5 releases)

### 1. Features
* Automatically modify the configuration files and run esxcli commands to disable\enable SSLv3 on all ESXi Services (Authd, Hostd/Rhttpproxy, SFCBD, Virtual SAN VP)  
* Utility will take backup of configuration files before making any modifications. For example, /etc/sfcb/sfcb.cfg will be saved as /etc/sfcb/sfcb.cfg.bkup in the same directory.  
* Utility has inbuilt scanner intelligence (TestSSLServer) for scanning ports to determine what protocols are already enabled and whether configuration was successful.  
* Utility reverts the configuration changes done, to restore the state as it was before, when there is a failure in doing configuration changes for a particular port.  
* Utility can be used to apply security protocol configuration on selected, multiple ESXi Servers (run through vCenter Server) or single ESXi Server (run directly against ESXi Server), in one go.  
* Utility generates report (csv file) with all ESXi server’s configuration result such as what security protocols were enabled earlier on each port, after configuration what protocols are enabled and etc.  
* Utility provides a way to encrypt and record ESXi server(s) password, before providing it as an input.  

### 2. Different options available with the Utility
* Enable SSLv3 on all ESXi Server Ports
* Disable SSLv3 on all ESXi Server Ports
* Get All ESXi server's details from vCenter Server and record it in a csv file.
* Encrypt plain ESXi password to record ESXi server(s) password in csv file for providing it as an input to the utility later.

### 3. Prerequisites for running Utility
* Java runtime environment /JDK where Java version is 1.7.0_45 or higher.

### 4. How to run the Utility?
##### Run from Dev IDE
* Import files under the src/com/vmware/secprotomgmt folder into your IDE.
* Required libraries are embedded within Runnable-Jar/secprotomgmt.jar, extract & import the libraries into the project.
* Run the utility from 'RunApp' program by providing arguments "--vsphereip <vc/esxi server IP> --username <uname> --password <pwd> [gethosts] [--hostsinfofile <pathToHostsListfile>] [enablessl] [disablessl]"

##### Run from Pre-built Jars
* Copy/Download the secprotomgmt.jar from Runnable-jar folder (from the uploaded file) and unzip on to local drive folder say c:\SecurityProtoMgmt
* Open a command prompt and cd to the folder, lets say
cd SecurityProtoMgmt
* Run a command like shown below to see various usage commands, 
C:\SecurityProtoMgmt>java -jar secprotomgmt.jar --help

REFER TO README DOCUMENT FOR DETAILS ON THIS UTILITY.
