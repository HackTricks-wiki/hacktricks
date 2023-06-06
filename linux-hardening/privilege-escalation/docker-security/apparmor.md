## Informações Básicas

**AppArmor** é um aprimoramento do kernel para confinar **programas** a um conjunto **limitado** de **recursos** com **perfis por programa**. Perfis podem **permitir** **capacidades** como acesso à rede, acesso a soquetes brutos e permissão para ler, gravar ou executar arquivos em caminhos correspondentes.

É um Controle de Acesso Obrigatório ou **MAC** que vincula **atributos de controle de acesso** a **programas em vez de usuários**.\
O confinamento do AppArmor é fornecido por meio de **perfis carregados no kernel**, normalmente no boot.\
Os perfis do AppArmor podem estar em um dos **dois modos**:

* **Execução**: Perfis carregados em modo de execução resultarão na **execução da política** definida no perfil **bem como na notificação** de tentativas de violação da política (por meio de syslog ou auditd).
* **Reclamação**: Perfis em modo de reclamação **não executarão a política** mas em vez disso **notificarão** tentativas de **violação** da política.

O AppArmor difere de alguns outros sistemas MAC no Linux: é **baseado em caminho**, permite a mistura de perfis de modo de execução e reclamação, usa arquivos de inclusão para facilitar o desenvolvimento e tem uma barreira muito menor de entrada do que outros sistemas MAC populares.

### Partes do AppArmor

* **Módulo do kernel**: Faz o trabalho real
* **Políticas**: Define o comportamento e contenção
* **Analisador**: Carrega as políticas no kernel
* **Utilitários**: Programas de modo de usuário para interagir com o apparmor

### Caminho dos perfis

Os perfis do Apparmor geralmente são salvos em _**/etc/apparmor.d/**_\
Com `sudo aa-status` você poderá listar os binários que são restritos por algum perfil. Se você puder trocar o caractere "/" por um ponto do caminho de cada binário listado, obterá o nome do perfil do apparmor dentro da pasta mencionada.

Por exemplo, um perfil do **apparmor** para _/usr/bin/man_ estará localizado em _/etc/apparmor.d/usr.bin.man_

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

* Para indicar o executável afetado, são permitidos **caminhos absolutos e curingas** (para globbing de arquivos) para especificar arquivos.
* Para indicar o acesso que o binário terá sobre **arquivos**, os seguintes **controles de acesso** podem ser usados:
  * **r** (leitura)
  * **w** (escrita)
  * **m** (mapeamento de memória como executável)
  * **k** (bloqueio de arquivo)
  * **l** (criação de links rígidos)
  * **ix** (para executar outro programa com a nova política herdada)
  * **Px** (executar sob outro perfil, após limpar o ambiente)
  * **Cx** (executar sob um perfil filho, após limpar o ambiente)
  * **Ux** (executar sem restrições, após limpar o ambiente)
* **Variáveis** podem ser definidas nos perfis e podem ser manipuladas de fora do perfil. Por exemplo: @{PROC} e @{HOME} (adicionar #include \<tunables/global> ao arquivo de perfil)
* **Regras de negação são suportadas para substituir regras de permissão**.

### aa-genprof

Para começar a criar um perfil, o apparmor pode ajudar. É possível fazer com que o **apparmor inspecione as ações executadas por um binário e, em seguida, permita que você decida quais ações deseja permitir ou negar**.\
Basta executar:
```bash
sudo aa-genprof /path/to/binary
```
Em seguida, em um console diferente, execute todas as ações que o binário normalmente executaria:
```bash
/path/to/binary -a dosomething
```
Então, na primeira console, pressione "**s**" e, em seguida, nas ações registradas, indique se deseja ignorar, permitir ou qualquer outra coisa. Quando terminar, pressione "**f**" e o novo perfil será criado em _/etc/apparmor.d/path.to.binary_

{% hint style="info" %}
Usando as teclas de seta, você pode selecionar o que deseja permitir/negar/qualquer coisa
{% endhint %}

### aa-easyprof

Você também pode criar um modelo de perfil apparmor de um binário com:
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
{% hint style="info" %}
Observe que por padrão em um perfil criado nada é permitido, então tudo é negado. Você precisará adicionar linhas como `/etc/passwd r,` para permitir a leitura do binário `/etc/passwd`, por exemplo.
{% endhint %}

Você pode então **aplicar** o novo perfil com
```bash
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
### Modificando um perfil a partir de logs

A seguinte ferramenta lerá os logs e perguntará ao usuário se ele deseja permitir algumas das ações proibidas detectadas:
```bash
sudo aa-logprof
```
{% hint style="info" %}
Usando as teclas de seta, você pode selecionar o que deseja permitir/negar/o que for.
{% endhint %}

### Gerenciando um perfil
```bash
#Main profile management commands
apparmor_parser -a /etc/apparmor.d/profile.name #Load a new profile in enforce mode
apparmor_parser -C /etc/apparmor.d/profile.name #Load a new profile in complain mode
apparmor_parser -r /etc/apparmor.d/profile.name #Replace existing profile
apparmor_parser -R /etc/apparmor.d/profile.name #Remove profile
```
## Registros

Exemplo de registros **AUDIT** e **DENIED** do executável **`service_bin`** no arquivo _/var/log/audit/audit.log_:
```bash
type=AVC msg=audit(1610061880.392:286): apparmor="AUDIT" operation="getattr" profile="/bin/rcat" name="/dev/pts/1" pid=954 comm="service_bin" requested_mask="r" fsuid=1000 ouid=1000
type=AVC msg=audit(1610061880.392:287): apparmor="DENIED" operation="open" profile="/bin/rcat" name="/etc/hosts" pid=954 comm="service_bin" requested_mask="r" denied_mask="r" fsuid=1000 ouid=0
```
Você também pode obter essa informação usando:
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

Observe como o perfil **docker-profile** do docker é carregado por padrão:
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
Por padrão, o perfil **Apparmor docker-default** é gerado a partir de [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor).

Resumo do perfil **docker-default**:

* **Acesso** a toda a **rede**
* **Nenhuma capacidade** é definida (No entanto, algumas capacidades virão da inclusão de regras básicas de base, ou seja, #include \<abstractions/base>)
* **Gravação** em qualquer arquivo **/proc** não é permitida
* Outros **subdiretórios**/**arquivos** de /**proc** e /**sys** são **negados** acesso de leitura/escrita/bloqueio/link/execução
* **Montagem** não é permitida
* **Ptrace** só pode ser executado em um processo que está confinado pelo **mesmo perfil apparmor**

Depois de **executar um contêiner docker**, você deve ver a seguinte saída:
```bash
1 processes are in enforce mode.
   docker-default (825)
```
Observe que o **apparmor bloqueará até mesmo os privilégios de capacidade** concedidos ao contêiner por padrão. Por exemplo, ele será capaz de **bloquear a permissão de escrita dentro de /proc mesmo se a capacidade SYS\_ADMIN for concedida**, porque por padrão o perfil do apparmor do docker nega esse acesso:
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined ubuntu /bin/bash
echo "" > /proc/stat
sh: 1: cannot create /proc/stat: Permission denied
```
Você precisa **desativar o apparmor** para contornar suas restrições:
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu /bin/bash
```
Observe que por padrão o **AppArmor** também **proíbe o contêiner de montar** pastas de dentro, mesmo com a capacidade SYS\_ADMIN.

Observe que você pode **adicionar/remover** **capacidades** ao contêiner docker (isso ainda será restrito por métodos de proteção como **AppArmor** e **Seccomp**):

* `--cap-add=SYS_ADMIN` dá a capacidade `SYS_ADMIN`
* `--cap-add=ALL` dá todas as capacidades
* `--cap-drop=ALL --cap-add=SYS_PTRACE` remove todas as capacidades e dá apenas `SYS_PTRACE`

{% hint style="info" %}
Geralmente, quando você **descobre** que tem uma **capacidade privilegiada** disponível **dentro** de um **contêiner docker, mas** alguma parte do **exploit não está funcionando**, isso ocorrerá porque o **apparmor do docker estará impedindo**.
{% endhint %}

### Exemplo

(Exemplo de [**aqui**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/))

Para ilustrar a funcionalidade do AppArmor, criei um novo perfil Docker "mydocker" com a seguinte linha adicionada:
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
Como mostrado abaixo, obtemos um erro ao tentar mudar “/etc/” já que o perfil do AppArmor está impedindo o acesso de escrita em “/etc”.
```
$ docker run --rm -it --security-opt apparmor:mydocker -v ~/haproxy:/localhost busybox chmod 400 /etc/hostname
chmod: /etc/hostname: Permission denied
```
### Bypass do AppArmor Docker1

Você pode encontrar qual **perfil do apparmor está sendo executado por um container** usando:
```bash
docker inspect 9d622d73a614 | grep lowpriv
        "AppArmorProfile": "lowpriv",
                "apparmor=lowpriv"
```
Então, você pode executar a seguinte linha para **encontrar o perfil exato sendo usado**:
```bash
find /etc/apparmor.d/ -name "*lowpriv*" -maxdepth 1 2>/dev/null
```
No caso improvável em que você possa **modificar o perfil do docker apparmor e recarregá-lo**, você poderia remover as restrições e "burlá-las".

### Bypass do AppArmor Docker 2

O **AppArmor é baseado em caminhos**, o que significa que mesmo que ele esteja **protegendo** arquivos dentro de um diretório como **`/proc`**, se você puder **configurar como o contêiner será executado**, você poderia **montar** o diretório proc do host dentro de **`/host/proc`** e ele **não será mais protegido pelo AppArmor**.

### Bypass do AppArmor Shebang

Neste [**bug**](https://bugs.launchpad.net/apparmor/+bug/1911431), você pode ver um exemplo de como, **mesmo que você esteja impedindo que o perl seja executado com certos recursos**, se você apenas criar um script shell **especificando** na primeira linha **`#!/usr/bin/perl`** e **executar o arquivo diretamente**, você poderá executar o que quiser. Por exemplo:
```perl
echo '#!/usr/bin/perl
use POSIX qw(strftime);
use POSIX qw(setuid);
POSIX::setuid(0);
exec "/bin/sh"' > /tmp/test.pl
chmod +x /tmp/test.pl
/tmp/test.pl
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
