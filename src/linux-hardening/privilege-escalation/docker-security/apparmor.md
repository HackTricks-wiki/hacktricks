# AppArmor

{{#include ../../../banners/hacktricks-training.md}}

## Informações Básicas

AppArmor é uma **melhoria do kernel projetada para restringir os recursos disponíveis para programas através de perfis por programa**, implementando efetivamente o Controle de Acesso Mandatório (MAC) ao vincular atributos de controle de acesso diretamente a programas em vez de usuários. Este sistema opera **carregando perfis no kernel**, geralmente durante a inicialização, e esses perfis ditam quais recursos um programa pode acessar, como conexões de rede, acesso a soquetes brutos e permissões de arquivo.

Existem dois modos operacionais para os perfis do AppArmor:

- **Modo de Aplicação**: Este modo aplica ativamente as políticas definidas dentro do perfil, bloqueando ações que violam essas políticas e registrando quaisquer tentativas de violá-las através de sistemas como syslog ou auditd.
- **Modo de Reclamação**: Ao contrário do modo de aplicação, o modo de reclamação não bloqueia ações que vão contra as políticas do perfil. Em vez disso, registra essas tentativas como violações de política sem impor restrições.

### Componentes do AppArmor

- **Módulo do Kernel**: Responsável pela aplicação das políticas.
- **Políticas**: Especificam as regras e restrições para o comportamento do programa e acesso a recursos.
- **Analisador**: Carrega políticas no kernel para aplicação ou relatório.
- **Utilitários**: Estes são programas em modo usuário que fornecem uma interface para interagir e gerenciar o AppArmor.

### Caminho dos perfis

Os perfis do AppArmor geralmente são salvos em _**/etc/apparmor.d/**_\
Com `sudo aa-status` você poderá listar os binários que estão restritos por algum perfil. Se você puder trocar o caractere "/" por um ponto no caminho de cada binário listado, você obterá o nome do perfil do AppArmor dentro da pasta mencionada.

Por exemplo, um **perfil do apparmor** para _/usr/bin/man_ estará localizado em _/etc/apparmor.d/usr.bin.man_

### Comandos
```bash
aa-status     #check the current status
aa-enforce    #set profile to enforce mode (from disable or complain)
aa-complain   #set profile to complain mode (from diable or enforcement)
apparmor_parser #to load/reload an altered policy
aa-genprof    #generate a new profile
aa-logprof    #used to change the policy when the binary/program is changed
aa-mergeprof  #used to merge the policies
```
## Criando um perfil

- Para indicar o executável afetado, **caminhos absolutos e curingas** são permitidos (para globbing de arquivos) para especificar arquivos.
- Para indicar o acesso que o binário terá sobre **arquivos**, os seguintes **controles de acesso** podem ser usados:
- **r** (ler)
- **w** (escrever)
- **m** (mapa de memória como executável)
- **k** (bloqueio de arquivo)
- **l** (criação de links duros)
- **ix** (executar outro programa com a nova política herdada)
- **Px** (executar sob outro perfil, após limpar o ambiente)
- **Cx** (executar sob um perfil filho, após limpar o ambiente)
- **Ux** (executar sem restrições, após limpar o ambiente)
- **Variáveis** podem ser definidas nos perfis e podem ser manipuladas de fora do perfil. Por exemplo: @{PROC} e @{HOME} (adicione #include \<tunables/global> ao arquivo de perfil)
- **Regras de negação são suportadas para substituir regras de permissão**.

### aa-genprof

Para começar a criar um perfil facilmente, o apparmor pode ajudar você. É possível fazer com que **apparmor inspecione as ações realizadas por um binário e então deixe você decidir quais ações deseja permitir ou negar**.\
Você só precisa executar:
```bash
sudo aa-genprof /path/to/binary
```
Então, em um console diferente, execute todas as ações que o binário geralmente realizará:
```bash
/path/to/binary -a dosomething
```
Então, no primeiro console pressione "**s**" e depois nas ações gravadas indique se você deseja ignorar, permitir ou qualquer outra coisa. Quando terminar, pressione "**f**" e o novo perfil será criado em _/etc/apparmor.d/path.to.binary_

> [!NOTE]
> Usando as teclas de seta, você pode selecionar o que deseja permitir/negar/qualquer outra coisa

### aa-easyprof

Você também pode criar um modelo de um perfil apparmor de um binário com:
```bash
sudo aa-easyprof /path/to/binary
# vim:syntax=apparmor
# AppArmor policy for binary
# ###AUTHOR###
# ###COPYRIGHT###
# ###COMMENT###

#include <tunables/global>

# No template variables specified

"/path/to/binary" {
#include <abstractions/base>

# No abstractions specified

# No policy groups specified

# No read paths specified

# No write paths specified
}
```
> [!NOTE]
> Note que, por padrão, em um perfil criado, nada é permitido, então tudo é negado. Você precisará adicionar linhas como `/etc/passwd r,` para permitir a leitura do binário `/etc/passwd`, por exemplo.

Você pode então **impor** o novo perfil com
```bash
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
### Modificando um perfil a partir de logs

A ferramenta a seguir irá ler os logs e perguntar ao usuário se ele deseja permitir algumas das ações proibidas detectadas:
```bash
sudo aa-logprof
```
> [!NOTE]
> Usando as teclas de seta, você pode selecionar o que deseja permitir/negar/o que for

### Gerenciando um Perfil
```bash
#Main profile management commands
apparmor_parser -a /etc/apparmor.d/profile.name #Load a new profile in enforce mode
apparmor_parser -C /etc/apparmor.d/profile.name #Load a new profile in complain mode
apparmor_parser -r /etc/apparmor.d/profile.name #Replace existing profile
apparmor_parser -R /etc/apparmor.d/profile.name #Remove profile
```
## Logs

Exemplo de logs **AUDIT** e **DENIED** do _/var/log/audit/audit.log_ do executável **`service_bin`**:
```bash
type=AVC msg=audit(1610061880.392:286): apparmor="AUDIT" operation="getattr" profile="/bin/rcat" name="/dev/pts/1" pid=954 comm="service_bin" requested_mask="r" fsuid=1000 ouid=1000
type=AVC msg=audit(1610061880.392:287): apparmor="DENIED" operation="open" profile="/bin/rcat" name="/etc/hosts" pid=954 comm="service_bin" requested_mask="r" denied_mask="r" fsuid=1000 ouid=0
```
Você também pode obter essas informações usando:
```bash
sudo aa-notify -s 1 -v
Profile: /bin/service_bin
Operation: open
Name: /etc/passwd
Denied: r
Logfile: /var/log/audit/audit.log

Profile: /bin/service_bin
Operation: open
Name: /etc/hosts
Denied: r
Logfile: /var/log/audit/audit.log

AppArmor denials: 2 (since Wed Jan  6 23:51:08 2021)
For more information, please see: https://wiki.ubuntu.com/DebuggingApparmor
```
## Apparmor no Docker

Note como o perfil **docker-profile** do docker é carregado por padrão:
```bash
sudo aa-status
apparmor module is loaded.
50 profiles are loaded.
13 profiles are in enforce mode.
/sbin/dhclient
/usr/bin/lxc-start
/usr/lib/NetworkManager/nm-dhcp-client.action
/usr/lib/NetworkManager/nm-dhcp-helper
/usr/lib/chromium-browser/chromium-browser//browser_java
/usr/lib/chromium-browser/chromium-browser//browser_openjdk
/usr/lib/chromium-browser/chromium-browser//sanitized_helper
/usr/lib/connman/scripts/dhclient-script
docker-default
```
Por padrão, o **perfil docker-default do Apparmor** é gerado a partir de [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor)

**Resumo do perfil docker-default**:

- **Acesso** a toda a **rede**
- **Nenhuma capacidade** é definida (No entanto, algumas capacidades virão da inclusão de regras básicas, ou seja, #include \<abstractions/base>)
- **Escrita** em qualquer arquivo **/proc** **não é permitida**
- Outros **subdiretórios**/**arquivos** de /**proc** e /**sys** têm acesso de leitura/escrita/bloqueio/link/executar **negado**
- **Montagem** **não é permitida**
- **Ptrace** só pode ser executado em um processo que está confinado pelo **mesmo perfil apparmor**

Uma vez que você **execute um contêiner docker**, você deve ver a seguinte saída:
```bash
1 processes are in enforce mode.
docker-default (825)
```
Observe que **o apparmor até bloqueará privilégios de capacidades** concedidos ao contêiner por padrão. Por exemplo, ele será capaz de **bloquear a permissão para escrever dentro de /proc mesmo que a capacidade SYS_ADMIN seja concedida** porque, por padrão, o perfil do apparmor do docker nega esse acesso:
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined ubuntu /bin/bash
echo "" > /proc/stat
sh: 1: cannot create /proc/stat: Permission denied
```
Você precisa **desativar o apparmor** para contornar suas restrições:
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu /bin/bash
```
Note que, por padrão, **AppArmor** também **proibirá o contêiner de montar** pastas de dentro, mesmo com a capacidade SYS_ADMIN.

Note que você pode **adicionar/remover** **capacidades** ao contêiner docker (isso ainda será restrito por métodos de proteção como **AppArmor** e **Seccomp**):

- `--cap-add=SYS_ADMIN` dá a capacidade `SYS_ADMIN`
- `--cap-add=ALL` dá todas as capacidades
- `--cap-drop=ALL --cap-add=SYS_PTRACE` remove todas as capacidades e dá apenas `SYS_PTRACE`

> [!NOTE]
> Normalmente, quando você **descobre** que tem uma **capacidade privilegiada** disponível **dentro** de um **contêiner** **docker**, **mas** alguma parte do **exploit não está funcionando**, isso será porque o **apparmor do docker estará impedindo**.

### Exemplo

(Exemplo de [**aqui**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/))

Para ilustrar a funcionalidade do AppArmor, criei um novo perfil Docker “mydocker” com a seguinte linha adicionada:
```
deny /etc/* w,   # deny write for all files directly in /etc (not in a subdir)
```
Para ativar o perfil, precisamos fazer o seguinte:
```
sudo apparmor_parser -r -W mydocker
```
Para listar os perfis, podemos executar o seguinte comando. O comando abaixo está listando meu novo perfil do AppArmor.
```
$ sudo apparmor_status  | grep mydocker
mydocker
```
Conforme mostrado abaixo, recebemos um erro ao tentar mudar “/etc/” já que o perfil do AppArmor está impedindo o acesso de escrita a “/etc”.
```
$ docker run --rm -it --security-opt apparmor:mydocker -v ~/haproxy:/localhost busybox chmod 400 /etc/hostname
chmod: /etc/hostname: Permission denied
```
### AppArmor Docker Bypass1

Você pode descobrir qual **perfil apparmor está executando um contêiner** usando:
```bash
docker inspect 9d622d73a614 | grep lowpriv
"AppArmorProfile": "lowpriv",
"apparmor=lowpriv"
```
Então, você pode executar a seguinte linha para **encontrar o perfil exato sendo usado**:
```bash
find /etc/apparmor.d/ -name "*lowpriv*" -maxdepth 1 2>/dev/null
```
No caso estranho de você poder **modificar o perfil do docker do apparmor e recarregá-lo.** Você poderia remover as restrições e "contorná-las".

### Bypass2 do AppArmor Docker

**AppArmor é baseado em caminho**, isso significa que mesmo que ele possa estar **protegendo** arquivos dentro de um diretório como **`/proc`**, se você puder **configurar como o contêiner será executado**, você poderia **montar** o diretório proc do host dentro de **`/host/proc`** e ele **não será mais protegido pelo AppArmor**.

### Bypass Shebang do AppArmor

Em [**este bug**](https://bugs.launchpad.net/apparmor/+bug/1911431) você pode ver um exemplo de como **mesmo que você esteja impedindo que o perl seja executado com certos recursos**, se você apenas criar um script shell **especificando** na primeira linha **`#!/usr/bin/perl`** e você **executar o arquivo diretamente**, você poderá executar o que quiser. Ex.:
```perl
echo '#!/usr/bin/perl
use POSIX qw(strftime);
use POSIX qw(setuid);
POSIX::setuid(0);
exec "/bin/sh"' > /tmp/test.pl
chmod +x /tmp/test.pl
/tmp/test.pl
```
{{#include ../../../banners/hacktricks-training.md}}
