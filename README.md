# Decloaker
#### A shell script for attempting to decloak modern rootkits
![image](https://user-images.githubusercontent.com/49037260/174408044-30d56820-7210-407f-96fa-6e3cd0c02d66.png)
<sub> Note: `liblinear.so`, `libproxy.so`, and `libcrypto.so` are legitimate Shared Object files used for testing purposes only. `liblinux.so` is an actual Symbiote sample.
  
  -----------------------------------------------------------------------------------------------
# Supported rootkits
## Symbiote

During Binary Defense's research of Symbiote, we found some promising methods of detecting its presence. 
The initial research article from Intezer and BlackBerry included a list of files that they had observed being hidden across multiple samples of the malware. We created a shell script that utilizes these artifacts to try to determine if the system is infected with Symbiote. 

1. First, the shell script creates a temporary directory and populates it with files that match the names found in the malware samples.
2. Next, the script lists the content of the temporary directory and counts the number of files within. If the number of files within that directory listing is less than the number of files initially placed in the directory, that could be an indication of the presence of Symbiote. 
    - If `LD_PRELOAD` and/or `/etc/ld.so.preload` are present, it will try to unset/remove them and compare directory listing lengths.
      - They are then restored and the temporary directory is removed.
3. Then, the script also checks the `LD_PRELOAD` environment variable and the `/etc/ld.so.preload` file for the existence of any value, which is extremely uncommon in most scenarios. 
4. Finally, the script determines if there are any processes currently running with the `LD_PRELOAD` environment variable set.

## Syslogk

The basis of the detection of Syslogk is the apparent built in killswitch discovered by researchers at Avast. Simply performing `echo 1>/proc/syslogk` will decloak the rootkit, otherwise that command will result in a write error. If the command goes through with no error that could indicate Syslogk presence. To confirm you can run `lsmod | grep syslogk`. Then removing the module from memory is done with `rmmod syslogk`, and this will reveal the presence of the associated Rekoobe implant whether it be actively listening on some TCP port, or if any decloaked directories in `/etc` were found.
  
1. A listing of `/etc` is saved to compare to later.
2. `echo 1>/proc/syslogk` is performed to attempt to reveal Syslogk.
3. If Syslogk is revealed in `lsmod` it will ask if you'd like to remove the module from memory. Answering yes will execute `rmmod syslogk`, which will reveal Rekoobe artifacts, otherwise they will still be hidden and the script will end.
4. If the Redkoobe is found and listening you will be given the option to kill the process.
5. Whether you decide to kill the process or not, the script will attempt to find the directory housing the payload in `/etc`.
6. If the payload is found, you will be asked if you'd like to remove it.
  

-----------------------------------------------------------------------------------------------------
## Usage
  `$ sudo bash symbload_check.sh`
  
  
 ## Testing
  
  The sample used for testing can be obtained on [MalwareBazaar](https://bazaar.abuse.ch/sample/a0cd554c35dee3fed3d1607dc18debd1296faaee29b5bd77ff83ab6956a6f9d6/) or [VirusTotal](https://www.virustotal.com/gui/file/a0cd554c35dee3fed3d1607dc18debd1296faaee29b5bd77ff83ab6956a6f9d6).

Rename the file to `liblinux.so` on your test system, and place it in `/lib/x86_64-linux-gnu`.

Highly recommended to be performed on a host with no connection to any other hosts.
