{{#include ../../banners/hacktricks-training.md}}

# SELinux u kontejnerima

[Uvod i primer iz redhat dokumenata](https://www.redhat.com/sysadmin/privileged-flag-container-engines)

[SELinux](https://www.redhat.com/en/blog/latest-container-exploit-runc-can-be-blocked-selinux) je **sistem** **označavanja**. Svaki **proces** i svaki **objekat** u sistemu datoteka ima **označavanje**. SELinux politike definišu pravila o tome šta **označavanje procesa može da radi sa svim ostalim oznakama** u sistemu.

Kontejnerski motori pokreću **kontejnerske procese sa jednim ograničenim SELinux oznakom**, obično `container_t`, a zatim postavljaju kontejner unutar kontejnera da bude označen kao `container_file_t`. Pravila SELinux politike u suštini kažu da **`container_t` procesi mogu samo da čitaju/pišu/izvršavaju datoteke označene kao `container_file_t`**. Ako kontejnerski proces pobegne iz kontejnera i pokuša da piše u sadržaj na hostu, Linux kernel odbija pristup i dozvoljava kontejnerskom procesu da piše samo u sadržaj označen kao `container_file_t`.
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
# SELinux korisnici

Postoje SELinux korisnici pored običnih Linux korisnika. SELinux korisnici su deo SELinux politike. Svaki Linux korisnik je mapiran na SELinux korisnika kao deo politike. Ovo omogućava Linux korisnicima da naslede ograničenja i sigurnosna pravila i mehanizme postavljene na SELinux korisnike.

{{#include ../../banners/hacktricks-training.md}}
