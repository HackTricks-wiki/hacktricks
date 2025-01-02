{{#include ../../banners/hacktricks-training.md}}

# SELinux w kontenerach

[Wprowadzenie i przykład z dokumentacji redhat](https://www.redhat.com/sysadmin/privileged-flag-container-engines)

[SELinux](https://www.redhat.com/en/blog/latest-container-exploit-runc-can-be-blocked-selinux) to **system etykietowania**. Każdy **proces** i każdy obiekt systemu plików ma swoją **etykietę**. Polityki SELinux definiują zasady dotyczące tego, co **etykieta procesu może robić z innymi etykietami** w systemie.

Silniki kontenerów uruchamiają **procesy kontenerowe z jedną ograniczoną etykietą SELinux**, zazwyczaj `container_t`, a następnie ustawiają etykietę `container_file_t` dla zawartości wewnątrz kontenera. Zasady polityki SELinux zasadniczo mówią, że **procesy `container_t` mogą tylko odczytywać/zapisywać/wykonywać pliki oznaczone etykietą `container_file_t`**. Jeśli proces kontenera ucieknie z kontenera i spróbuje zapisać zawartość na hoście, jądro Linuxa odmawia dostępu i pozwala procesowi kontenera tylko na zapis do zawartości oznaczonej etykietą `container_file_t`.
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
# Użytkownicy SELinux

Istnieją użytkownicy SELinux oprócz zwykłych użytkowników Linuxa. Użytkownicy SELinux są częścią polityki SELinux. Każdy użytkownik Linuxa jest mapowany na użytkownika SELinux jako część polityki. Umożliwia to użytkownikom Linuxa dziedziczenie ograniczeń oraz zasad i mechanizmów bezpieczeństwa nałożonych na użytkowników SELinux.

{{#include ../../banners/hacktricks-training.md}}
