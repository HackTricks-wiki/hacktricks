{{#include ../../banners/hacktricks-training.md}}

# SELinux katika Mifuko

[Utangulizi na mfano kutoka kwa nyaraka za redhat](https://www.redhat.com/sysadmin/privileged-flag-container-engines)

[SELinux](https://www.redhat.com/en/blog/latest-container-exploit-runc-can-be-blocked-selinux) ni **mfumo wa kuweka lebo**. Kila **mchakato** na kila **kitu** cha mfumo wa faili kina **lebo**. Sera za SELinux zinafafanua sheria kuhusu kile **lebo ya mchakato inaruhusiwa kufanya na lebo nyingine zote** kwenye mfumo.

Mifumo ya mifuko inazindua **michakato ya mfuko yenye lebo moja ya SELinux iliyo na mipaka**, kawaida `container_t`, na kisha kuweka mfuko ndani ya mfuko kuwa na lebo `container_file_t`. Sheria za sera za SELinux kimsingi zinasema kwamba **michakato ya `container_t` inaweza kusoma/kandika/kutekeleza faili zilizo na lebo `container_file_t` pekee**. Ikiwa mchakato wa mfuko unatoroka mfuko na kujaribu kuandika kwenye maudhui kwenye mwenyeji, kernel ya Linux inakataa ufikiaji na inaruhusu tu mchakato wa mfuko kuandika kwenye maudhui yaliyo na lebo `container_file_t`.
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
# Watumiaji wa SELinux

Kuna watumiaji wa SELinux pamoja na watumiaji wa kawaida wa Linux. Watumiaji wa SELinux ni sehemu ya sera ya SELinux. Kila mtumiaji wa Linux ameunganishwa na mtumiaji wa SELinux kama sehemu ya sera. Hii inaruhusu watumiaji wa Linux kurithi vizuizi na sheria za usalama na mifumo iliyowekwa kwa watumiaji wa SELinux.

{{#include ../../banners/hacktricks-training.md}}
