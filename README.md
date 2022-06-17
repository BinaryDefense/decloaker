# symbiote-preload-check
A script that attempts to decloak symbiote activity, and some other LD_PRELOAD activity

During Binary Defense's research of Symbiote, we found some promising methods of detecting its presence. The initial research article from Intezer and BlackBerry included a list of files that they had observed being hidden across multiple samples of the malware. We created a shell script that utilizes these artifacts to try to determine if the system is infected with Symbiote. The shell script creates a temporary directory and populates it with files that match the names found in the malware samples. Next, the script lists the content of the temporary directory and counts the number of files within. If the number of files within that directory listing is less than the number of files initially placed in the directory, that could be an indication of the presence of Symbiote. In addition, the script also checks the LD_PRELOAD environment variable and the ‘/etc/ld.so.preload’ file for the existence of any value, which is extremely uncommon in most scenarios. Finally, the script determines if there are any processes currently running with the LD_PRELOAD environment variable set.