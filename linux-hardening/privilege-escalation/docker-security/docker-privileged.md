## Docker --privileged

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## O que afeta

Quando você executa um contêiner como privilegiado, essas são as proteções que você está desabilitando:

### Montagem /dev

Em um contêiner privilegiado, todos os **dispositivos podem ser acessados em `/dev/`**. Portanto, você pode **escapar** montando o disco do host.

{% tabs %}
{% tab title="Dentro do contêiner padrão" %}
```bash
# docker run --rm -it alpine sh
ls /dev
console  fd       mqueue   ptmx     random   stderr   stdout   urandom
core     full     null     pts      shm      stdin    tty      zero
```
{% endtab %}

{% tab title="Dentro do Container com Privilégios" %}
```bash
# docker run --rm --privileged -it alpine sh
ls /dev
cachefiles       mapper           port             shm              tty24            tty44            tty7
console          mem              psaux            stderr           tty25            tty45            tty8
core             mqueue           ptmx             stdin            tty26            tty46            tty9
cpu              nbd0             pts              stdout           tty27            tty47            ttyS0
[...]
```
### Sistemas de arquivos de kernel somente leitura

Os sistemas de arquivos de kernel fornecem um mecanismo para um processo alterar a maneira como o kernel é executado. Por padrão, não queremos que os processos do contêiner modifiquem o kernel, portanto, montamos os sistemas de arquivos de kernel como somente leitura dentro do contêiner.
```bash
# docker run --rm -it alpine sh
mount | grep '(ro'
sysfs on /sys type sysfs (ro,nosuid,nodev,noexec,relatime)
cpuset on /sys/fs/cgroup/cpuset type cgroup (ro,nosuid,nodev,noexec,relatime,cpuset)
cpu on /sys/fs/cgroup/cpu type cgroup (ro,nosuid,nodev,noexec,relatime,cpu)
cpuacct on /sys/fs/cgroup/cpuacct type cgroup (ro,nosuid,nodev,noexec,relatime,cpuacct)
```
{% endtab %}

{% tab title="Dentro do Container com Privilégios" %}
```bash
# docker run --rm --privileged -it alpine sh
mount  | grep '(ro'
```
### Mascaramento sobre sistemas de arquivos do kernel

O sistema de arquivos **/proc** é consciente de namespace e algumas gravações podem ser permitidas, então não o montamos somente leitura. No entanto, diretórios específicos no sistema de arquivos /proc precisam ser **protegidos contra gravação** e, em alguns casos, **contra leitura**. Nestes casos, os motores de contêineres montam sistemas de arquivos **tmpfs** sobre diretórios potencialmente perigosos, impedindo que processos dentro do contêiner os usem.

{% hint style="info" %}
**tmpfs** é um sistema de arquivos que armazena todos os arquivos na memória virtual. O tmpfs não cria nenhum arquivo no seu disco rígido. Portanto, se você desmontar um sistema de arquivos tmpfs, todos os arquivos nele serão perdidos para sempre.
{% endhint %}

{% tab title="Dentro do contêiner padrão" %}
```bash
# docker run --rm -it alpine sh
mount  | grep /proc.*tmpfs
tmpfs on /proc/acpi type tmpfs (ro,relatime)
tmpfs on /proc/kcore type tmpfs (rw,nosuid,size=65536k,mode=755)
tmpfs on /proc/keys type tmpfs (rw,nosuid,size=65536k,mode=755)
```
{% endtab %}

{% tab title="Dentro do Container com Privilégios" %}
```bash
# docker run --rm --privileged -it alpine sh
mount  | grep /proc.*tmpfs
```
### Capacidades do Linux

Os motores de contêiner lançam os contêineres com um **número limitado de capacidades** para controlar o que acontece dentro do contêiner por padrão. Os **privilegiados** têm **todas** as **capacidades** acessíveis. Para aprender sobre capacidades, leia:

{% content-ref url="../linux-capabilities.md" %}
[linux-capabilities.md](../linux-capabilities.md)
{% endcontent-ref %}

{% tabs %}
{% tab title="Dentro do contêiner padrão" %}
```bash
# docker run --rm -it alpine sh
apk add -U libcap; capsh --print
[...]
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=eip
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
[...]
```
{% endtab %}

{% tab title="Dentro do Container com Privilégios" %}
```bash
# docker run --rm --privileged -it alpine sh
apk add -U libcap; capsh --print
[...]
Current: =eip cap_perfmon,cap_bpf,cap_checkpoint_restore-eip
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read
[...]
```
{% endtab %}
{% tab title="Manipulando capacidades" %}
Você pode manipular as capacidades disponíveis para um contêiner sem executar no modo `--privileged` usando as opções `--cap-add` e `--cap-drop`.

### Seccomp

**Seccomp** é útil para **limitar** as **syscalls** que um contêiner pode chamar. Um perfil seccomp padrão é habilitado por padrão ao executar contêineres do docker, mas no modo privilegiado ele é desativado. Saiba mais sobre o Seccomp aqui:

{% content-ref url="seccomp.md" %}
[seccomp.md](seccomp.md)
{% endcontent-ref %}

{% tabs %}
{% tab title="Dentro do contêiner padrão" %}
```bash
# docker run --rm -it alpine sh
grep Seccomp /proc/1/status
Seccomp:	2
Seccomp_filters:	1
```
{% endtab %}

{% tab title="Dentro do Container com Privilégios" %}
```bash
# docker run --rm --privileged -it alpine sh
grep Seccomp /proc/1/status
Seccomp:	0
Seccomp_filters:	0
```
{% endtab %}
{% endtabs %}
```bash
# You can manually disable seccomp in docker with
--security-opt seccomp=unconfined
```
Também é importante notar que quando o Docker (ou outros CRIs) são usados em um cluster **Kubernetes**, o filtro **seccomp** é desativado por padrão.

### AppArmor

**AppArmor** é um aprimoramento do kernel para confinar **contêineres** a um **conjunto limitado** de **recursos** com **perfis por programa**. Quando você executa com a opção `--privileged`, essa proteção é desativada.

{% content-ref url="apparmor.md" %}
[apparmor.md](apparmor.md)
{% endcontent-ref %}
```bash
# You can manually disable seccomp in docker with
--security-opt apparmor=unconfined
```
### SELinux

Quando você executa com a flag `--privileged`, **as etiquetas SELinux são desabilitadas** e o contêiner é executado com a **etiqueta com a qual o mecanismo do contêiner foi executado**. Essa etiqueta geralmente é `unconfined` e tem **acesso total às etiquetas que o mecanismo do contêiner possui**. No modo sem raiz, o contêiner é executado com `container_runtime_t`. No modo raiz, ele é executado com `spc_t`.

{% content-ref url="../selinux.md" %}
[selinux.md](../selinux.md)
{% endcontent-ref %}
```bash
# You can manually disable selinux in docker with
--security-opt label:disable
```
## O que não afeta

### Namespaces

Os namespaces **NÃO são afetados** pela flag `--privileged`. Mesmo que eles não tenham as restrições de segurança habilitadas, eles **não veem todos os processos no sistema ou na rede do host, por exemplo**. Os usuários podem desabilitar namespaces individuais usando as flags do motor do contêiner **`--pid=host`, `--net=host`, `--ipc=host`, `--uts=host`**.

{% tabs %}
{% tab title="Dentro do contêiner privilegiado padrão" %}
```bash
# docker run --rm --privileged -it alpine sh
ps -ef
PID   USER     TIME  COMMAND
    1 root      0:00 sh
   18 root      0:00 ps -ef
```
{% endtab %}

{% tab title="Dentro do Container --pid=host" %}
```bash
# docker run --rm --privileged --pid=host -it alpine sh
ps -ef
PID   USER     TIME  COMMAND
    1 root      0:03 /sbin/init
    2 root      0:00 [kthreadd]
    3 root      0:00 [rcu_gp]ount | grep /proc.*tmpfs
[...]
```
### Namespace de usuário

Os motores de contêineres **NÃO usam o namespace de usuário por padrão**. No entanto, contêineres sem raiz sempre o usam para montar sistemas de arquivos e usar mais de um UID. No caso sem raiz, o namespace de usuário não pode ser desativado; é necessário executar contêineres sem raiz. Os namespaces de usuário impedem certos privilégios e adicionam considerável segurança.

## Referências

* [https://www.redhat.com/sysadmin/privileged-flag-container-engines](https://www.redhat.com/sysadmin/privileged-flag-container-engines)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
