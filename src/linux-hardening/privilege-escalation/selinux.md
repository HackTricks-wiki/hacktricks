{{#include ../../banners/hacktricks-training.md}}

# SELinux nei Contenitori

[Introduzione e esempio dalla documentazione di redhat](https://www.redhat.com/sysadmin/privileged-flag-container-engines)

[SELinux](https://www.redhat.com/en/blog/latest-container-exploit-runc-can-be-blocked-selinux) è un **sistema di etichettatura**. Ogni **processo** e ogni **oggetto** del file system ha un'**etichetta**. Le politiche SELinux definiscono regole su cosa un'**etichetta di processo** è autorizzata a fare con tutte le altre etichette nel sistema.

I motori dei contenitori avviano **processi di contenitore con un'unica etichetta SELinux confinata**, di solito `container_t`, e poi impostano il contenitore all'interno del contenitore per essere etichettato `container_file_t`. Le regole della politica SELinux dicono fondamentalmente che i **processi `container_t` possono solo leggere/scrivere/eseguire file etichettati `container_file_t`**. Se un processo di contenitore sfugge al contenitore e tenta di scrivere contenuti sull'host, il kernel Linux nega l'accesso e consente solo al processo di contenitore di scrivere contenuti etichettati `container_file_t`.
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
# Utenti SELinux

Ci sono utenti SELinux oltre agli utenti Linux regolari. Gli utenti SELinux fanno parte di una politica SELinux. Ogni utente Linux è mappato a un utente SELinux come parte della politica. Questo consente agli utenti Linux di ereditare le restrizioni e le regole di sicurezza e i meccanismi imposti sugli utenti SELinux.

{{#include ../../banners/hacktricks-training.md}}
