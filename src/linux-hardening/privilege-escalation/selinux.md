{{#include ../../banners/hacktricks-training.md}}

# SELinux in Containers

[Inleiding en voorbeeld uit die redhat dokumentasie](https://www.redhat.com/sysadmin/privileged-flag-container-engines)

[SELinux](https://www.redhat.com/en/blog/latest-container-exploit-runc-can-be-blocked-selinux) is 'n **etikettering** **stelsel**. Elke **proses** en elke **lêer** stelselaanwyser het 'n **etiket**. SELinux-beleide definieer reëls oor wat 'n **proses etiket mag doen met al die ander etikette** op die stelsel.

Container enjinse begin **container prosesse met 'n enkele beperkte SELinux etiket**, gewoonlik `container_t`, en stel dan die container binne die container in om geëtiketteer te word as `container_file_t`. Die SELinux-beleid reëls sê basies dat die **`container_t` prosesse slegs lêers geëtiketteer as `container_file_t` kan lees/skryf/uitvoer**. As 'n container proses die container ontsnap en probeer om na inhoud op die gasheer te skryf, weier die Linux-kern toegang en laat slegs die container proses toe om na inhoud geëtiketteer as `container_file_t` te skryf.
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
# SELinux Gebruikers

Daar is SELinux gebruikers benewens die gewone Linux gebruikers. SELinux gebruikers is deel van 'n SELinux beleid. Elke Linux gebruiker is aan 'n SELinux gebruiker gekoppel as deel van die beleid. Dit stel Linux gebruikers in staat om die beperkings en sekuriteitsreëls en -meganismes wat op SELinux gebruikers geplaas is, te erf.

{{#include ../../banners/hacktricks-training.md}}
