# Villainius 

villainius.exe - A benign application used to demonstrate an EDR detection.

        Usage:
          villainius.exe [options]
            Options:
              -h               Print this help.
              -p <seconds>     (optional) Pause the embedded executable for
                               <seconds> before exiting.
              -e <executable>  (required) Embedded executable to be launched:
                                 mimikats      Benign version of Mimikatz
                                 procdump      Benign version of ProcDump
                                 wce           Benign version of WCE
                               Note: Only one may be specified; extras are ignored.
              -l <method>      (required) Method used to launch embedded executable:
                                 createproc    CreateProcess
                                 hollowing     Process hollowing of embedded lsass.exe
                                 psenccmd      PowerShell -EncodedCommand
                                 psstartproc   PowerShell Start-Process
                                 shellex       ShellExecute
                                 shellexa      ShellExecuteExA
                                 stdsystem     std::system
                               Note: One or more <modules> are used for all.
              -m <modules>     (optional) Module names, commands, or parameters used
                               with the official version of the embedded executable.
                               This must be the *final* option.
        Examples:
		  villainius.exe -e mimikats -l createproc -m KEREROS::PTT <username>@krbtgt-<domainname.tld>.kirbi
		  villainius.exe -p 15 -e mimikats -l hollowing -m SEKURLSA::LogonPasswords full
		  villainius.exe -e procdump -l psenccmd -m -ma lsass.exe lsass.dmp
		  villainius.exe -p 15 -e procdump -l psstartproc -m -ma lsass.exe lsass.dmp
		  villainius.exe -e wce -l shellex -m -g <cleartextpassword>
		  villainius.exe -p 15 -e wce -l shellexa -m -s <username>:<domain>:<lmhash>:<nthash>
		  
Villianius performs the following tasks:
1. Extracts from its resources, decodes, and saves to disk several Base64-encoded benign applications named after applications known to have been used for malicious purposes.
2. Extracts from its resources, decodes, and saves to disk a Base64-encoded benign application named lsass.exe that is used for process hollowing.
3. Executes the benign applications using one or more of the launch methods specified methods, passing all command line content after the -m option. 
4. Deletes all of the extracted benign applications.
 
## Binary

A ZIP archive containing villainius.exe may be downloaded from the **distribution** folder.

## Build Environment

Platform: Visual Studio Enterprise 2019 Version 16.9.2  
Platform Toolset: v142  
Language: ISO C++ 17 Standard  
Windows SDK: 10.0.19041.0  

