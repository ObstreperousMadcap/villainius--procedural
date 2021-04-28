# Villainius 

villainius.exe - A benign application used to demonstrate an EDR detection.

    Usage:
        villainius.exe [options]
	    [options]
                -h              Print this help.
                -e <executable> (required) Embedded executable to be launched:
                                  mimikats  Benign version of mimikatz
                                  nbtscan   Benign version of nbtscan
                                  nmap      Benign version of nmap
                                  paexec    Benign version of paexec
                                  procdump  Benign version of procdump
                                  psexec    Benign version of psexec
                                  wce       Benign version of wce
                                  Note: Only one may be specified; extras are ignored.
                -l <method>     (required) Method used to launch embedded executable:
                                  createproc   CreateProcess
                                  hollowing    Process hollowing of embedded lsass.exe
                                  psenccmd     PowerShell -EncodedCommand
                                  psstartproc  PowerShell Start-Process
                                  shellex      ShellExecute
                                  shellexa     ShellExecuteExA
                                  stdsystem    std::system
                                  Note: One or more may be specified; The same
                                  <parameters> are used for all launch methods.
                -p <parameters> Parameters used with the official version of the
                                embedded executable. This must be the *final* option.

    Examples:
        villainius.exe -e mimikats -l createproc -p SEKURLSA::LogonPasswords full
        villainius.exe -e nbtscan -l hollowing -p -vh <ipnetwork>/<maskbits>
        villainius.exe -e nmap -l psenccmd -p <ipnetwork>/<maskbits> --spoof-mac 0
        villainius.exe -e paexec -l psstartproc -p \\\\<ipaddress> --spoof-mac 0 <filename.exe>
        villainius.exe -e procdump -l shellex -p -ma <filename.exe> <filename.dmp>
        villainius.exe -e psexec -l shellexa -p \\\\<ipaddress> <command> -ab
        villainius.exe -e wce -l stdsystem -p -s <username>:<domain>:<lmhash>:<nthash>		

Villianius performs the following tasks:
1. Extracts from its resources, decodes, and saves to disk several Base64-encoded benign applications that are named after applications that could be used for malicious purposes.
2. Executes the benign applications using one or more of the launch methods specified methods, passing all parameters after the -p option. 
3. Deletes all of the extracted applications.

## Binary

A ZIP archive containing villainius.exe may be downloaded from the **distribution** folder.

## Build Environment

Platform: Visual Studio Enterprise 2019 Version 16.9.4	
Platform Toolset: v142	
Language: ISO C++ 17 Standard	
Windows SDK: 10.0.19041.0	

## Roadmap Items
1. nbtscan, nmap, paexec, and psexec may need a bit more code added to ensure detection; additional testing needed.
2. Additional process injection methods need to be added.

## mimikats Parameters

Below are some of the parameters that have been - and may be still - used with mimikatz:

CRYPTO::CAPI  
CRYPTO::Certificates  
CRYPTO::CNG  
CRYPTO::Keys  
KERBEROS::Golden  
KERBEROS::List  
KERBEROS::PTT  
KERBEROS::Purge  
KERBEROS::TGT  
LSADUMP::Cache  
LSADUMP::ChangeNTLM  
LSADUMP::DCShadow  
LSADUMP::DCSync  
LSADUMP::SAM  
LSADUMP::Secrets  
LSADUMP::SetNTLM  
SEKURLSA::DPAPI  
SEKURLSA::EKeys  
SEKURLSA::LogonPasswords  
SEKURLSA::MiniDump  
SEKURLSA::PTH  
SEKURLSA::Tickets  
TOKEN::Elevate  
TOKEN::Revert  
VAULT::Cred  
VAULT::List  
