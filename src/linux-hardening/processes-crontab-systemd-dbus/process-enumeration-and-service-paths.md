# Enumeração de processos e caminhos de serviços

{{#include ../../banners/hacktricks-training.md}}

A pergunta útil é: qual processo privilegiado consome dados ou código que um usuário com menos privilégios pode influenciar? Inspecione a árvore de processos, o ambiente em execução, os arquivos abertos e a unidade ou o script que iniciou cada candidato.

## Mapear processos e propriedade

```bash
ps -eo user,pid,ppid,tty,comm,args --sort=ppid
pstree -alp 2>/dev/null
systemctl list-units --type=service --state=running 2>/dev/null
ss -lntup
```

Uma relação pai-filho entre usuários diferentes pode ser normal, mas uma transição inesperada justifica revisar o comando pai, os argumentos, o executável, o diretório de trabalho e os arquivos referenciados. Use [users and sessions](../user-information/user-and-session-triage.md) para interpretar o proprietário e o contexto de login.

### Consoles de máquinas virtuais locais

Revise as opções `-spice` de um processo QEMU junto com o endereço em que ele está escutando. A [documentação do QEMU](https://www.qemu.org/docs/master/system/qemu-manpage.html) informa que `disable-ticketing` permite que clientes SPICE se conectem sem autenticação. Mesmo um listener vinculado ao loopback pode estar potencialmente acessível a outros usuários locais do host. Confirme o listener ativo, as opções de autenticação e o acesso local antes de considerar a linha de comando um console exposto. O controle do console afeta o **convidado**; obter uma conta no convidado ou alterar seu estado de inicialização exige condições separadas no próprio convidado e não concede root no host de virtualização. Durante a enumeração passiva, leia os argumentos do processo e os metadados do socket sem se conectar ao convidado nem reiniciá-lo.

Uma interface web acessível localmente pode executar código com a conta do serviço, mesmo quando o primeiro shell não consegue acessar os arquivos dessa conta. Por exemplo, a CVE-2023-0297 afetou o tratamento de `/flash/addcrypted2` do pyLoad quando JavaScript não confiável chegava ao Js2Py com imports de Python habilitados; a [correção upstream](https://github.com/pyload/pyload/commit/7d73ba7919e594d783b3411d7ddb87885aea782d) desativou `pyimport`. Correlacione o proprietário do processo em execução, o endereço em que ele escuta, a exposição do endpoint e o patch instalado ou backport do fornecedor antes de considerar um processo pyLoad um caminho para escalação de privilégios. O nome de um processo, uma porta aberta ou a versão de um pacote, por si só, não comprovam exposição; a enumeração passiva não deve enviar um payload de execução.

### Shells de login privilegiados compartilhando um terminal

Um shell interativo privilegiado que executa `su --login <user>` sem um pseudo-terminal independente pode deixar seu terminal compartilhado com o shell de login de menor privilégio. Se o arquivo de inicialização desse usuário puder ser controlado e o código nele puder usar `TIOCSTI` para injetar entrada no terminal, essa entrada poderá chegar ao shell privilegiado quando ele retomar a execução. O [manual do `su` do util-linux](https://man7.org/linux/man-pages/man1/su.1.html#SECURITY_NOTES) descreve o risco do terminal compartilhado e recomenda `su --pty`/`-P` para uso interativo; `su -c` inicia uma sessão separada sem um terminal de controle. O risco depende do shell pai real, da relação com o terminal, do arquivo de inicialização do usuário-alvo e da política do kernel. O nome de um processo ou o argumento `su -l`, por si só, são apenas indicações para revisão.

Inspecione a árvore de processos observada e as colunas TTY; em seguida, verifique o launcher legível e a propriedade/permissões do arquivo de inicialização. No Linux, `/proc/sys/dev/tty/legacy_tiocsti` pode ajudar a interpretar a política, quando presente; sua ausência não comprova segurança. O [manual do `TIOCSTI` do Linux](https://man7.org/linux/man-pages/man2/TIOCSTI.2const.html) observa que, desde o Linux 6.2, a operação pode exigir `CAP_SYS_ADMIN` quando esse sysctl é falso. Não invoque o ioctl apenas para enumerar o host.

Às vezes, uma conta de banco de dados pode alterar o arquivo de inicialização do usuário-alvo sem acesso direto de gravação ao sistema de arquivos. O `COPY ... TO 'filename'` executado no servidor PostgreSQL grava como a conta do sistema operacional do servidor de banco de dados, mas o [PostgreSQL limita](https://www.postgresql.org/docs/current/sql-copy.html) essa forma de arquivo a superusuários do banco de dados ou a funções como `pg_write_server_files`. Confirme tanto a função no banco de dados quanto as permissões de arquivo da conta do sistema operacional do servidor; uma string de conexão da aplicação, por si só, não concede autoridade para gravar arquivos. Ao avaliar a cadeia, trate separadamente o launcher privilegiado e os recursos da conta do banco de dados.

## Inspecionar artefatos de runtime

```bash
readlink /proc/<PID>/exe
tr '\0' ' ' </proc/<PID>/cmdline; echo
ls -l /proc/<PID>/fd 2>/dev/null
lsof -p <PID> 2>/dev/null
lsof +L1 2>/dev/null
```

Executáveis excluídos e arquivos excluídos, mas ainda abertos, continuam referenciados até que seu último descritor seja fechado. Eles podem preservar evidências ou segredos acessíveis. Os ambientes e a memória dos processos podem conter credenciais, mas a leitura de outro processo é condicionada pela propriedade, pelas opções de montagem de `/proc`, pela política Yama ptrace e por outros controles de segurança. Consulte [descritores de arquivo](../main-system-information/filesystem-links-and-file-descriptors.md) e [busca de credenciais pós-exploração](../post-exploitation/README.md) para técnicas relacionadas.

Rastreamentos de chamadas de sistema salvos são outro limite imposto por permissões de arquivo. [`strace` registra os argumentos das chamadas de sistema em um arquivo de saída](https://man7.org/linux/man-pages/man1/strace.1.html), portanto, um rastreamento legível dos [argumentos de `execve`](https://man7.org/linux/man-pages/man2/execve.2.html) pode expor uma senha que um job privilegiado passou na linha de comando. Primeiro, confirme que o usuário atual pode ler o rastreamento específico e que o argumento realmente contém uma credencial; uma transição posterior para uma conta Unix exige uma comprovação separada de que a credencial é aceita nela. Os metadados do arquivo são uma pista passiva útil, sem precisar varrer todos os rastreamentos ou exibir seu conteúdo durante a enumeração de rotina.

## Sockets de automação de escritório privilegiados

LibreOffice e OpenOffice podem expor sua API UNO por meio de um argumento `--accept=socket,host=<host>,port=<port>;urp;`. Um processo de escritório de propriedade do root com um endpoint acessível pode permitir que um usuário local com menos privilégios invoque serviços da API no contexto de segurança desse processo. O serviço `SystemShellExecute` inclui uma operação para executar um comando do sistema. Vincular o socket ao loopback limita o acesso remoto, mas ainda deixa o socket acessível a usuários locais, a menos que outro controle impeça o acesso.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
ps -eo user,args | grep -E '[s]office|[l]ibreoffice|[o]penoffice'
ss -ltn 2>/dev/null
```

Correlacione o proprietário do processo, o argumento exato `--accept` e o endereço e a porta em que está escutando no momento. Um acceptor configurado que não conseguiu fazer bind é apenas uma pista; não se conecte nem invoque a API durante a enumeração passiva. Evite iniciar uma instância privilegiada do office apenas para testar essa condição.

## Memória compartilhada System V consumida por processos privilegiados

Um helper de propriedade do root pode criar um segmento de memória compartilhada System V no qual outro usuário pode escrever. Se o helper posteriormente confiar nos dados desse segmento em um comando de shell ou em outra operação sensível, o segmento cruza uma fronteira de privilégios, mesmo quando o executável e seus arquivos estão protegidos. `shmget()` obtém as permissões de acesso dos nove bits inferiores de suas flags; o modo `0666` permite que outros usuários escrevam, enquanto uma flag `IPC_CREAT` não restringe essas permissões. Inspecione os segmentos ativos passivamente com `ipcs -m` e correlacione seu proprietário, modo e tempo de vida com o processo privilegiado e o tratamento de sua entrada. Um segmento gravável por todos, por si só, não comprova a execução de comandos.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
ipcs -m
```

Os segmentos System V são distintos dos arquivos de memória compartilhada POSIX em `/dev/shm`. Um segmento criado por apenas um instante pode não aparecer em uma única captura de `ipcs`; portanto, uma saída vazia não descarta a possibilidade de um helper usar memória compartilhada. Analise o código-fonte ou o comportamento do binário e qualquer regra de `sudo` que o execute; não invoque o helper privilegiado apenas para fazer um segmento aparecer durante a enumeração. O [guia de namespaces IPC](../containers-namespaces/container-security/protections/namespaces/ipc-namespace.md) explica como os namespaces afetam a visibilidade.<sup>[[2]](#references)[[3]](#references)</sup>

## Verificações de script do agente Consul

O Consul pode executar verificações de integridade por script com a identidade do sistema operacional do agente. Se um agente for executado como root, habilitar `enable_script_checks` e permitir que um usuário com menos privilégios registre um serviço com uma verificação por script por meio da API HTTP local, esse usuário poderá executar comandos como root. Vincular a API apenas a `127.0.0.1` ainda permite que usuários locais a acessem. A configuração `enable_local_script_checks` é mais restrita: ela exclui verificações por script enviadas por meio de registros na API HTTP. Quando as ACLs do Consul estão habilitadas, o registro de serviços exige `service:write`; uma linha `acl.default_policy=allow`, por si só, não prova que um chamador anônimo pode fazer o registro. Analise em conjunto a identidade real do agente, as configurações carregadas, o vínculo da API e a autorização.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

```bash
ps -eo user,args | grep '[c]onsul agent'
ls -l /etc/consul.d 2>/dev/null
```

Siga os argumentos `-config-dir` e `-config-file` do agent em execução até a configuração relevante e inspecione apenas os nomes e as definições dos campos de script-check e ACL. Os arquivos de configuração também podem conter chaves ou tokens de gossip; evite colá-los em logs compartilhados. Não registre um serviço nem execute uma verificação de integridade apenas para enumerar essa condição.

Existe um caminho separado por arquivo local quando um usuário com menos privilégios pode **escrever e pesquisar** o diretório indicado por `-config-dir` de um agent executado como root: uma nova definição de serviço `.hcl` ou `.json` pode ser carregada desse diretório. As permissões de pesquisa e escrita no diretório podem permitir adicionar um arquivo mesmo quando a listagem do diretório é negada. Para executar comandos como root, confirme que o agent realmente carrega esse diretório, que a configuração **efetiva** de script-check permite definições locais, que a definição foi carregada e que o agent mantém os privilégios de root. A [documentação do Consul](https://developer.hashicorp.com/consul/docs/fundamentals/agent#reloadable-configurations) descreve quais configurações e definições de health-check podem ser recarregadas; habilitar script checks pode exigir uma reinicialização, então verifique o comportamento da versão instalada. Quando ACLs protegem o agent, [`consul reload` exige `agent:write`](https://developer.hashicorp.com/consul/api-docs/agent#reload-agent); a permissão de escrita em KV não concede essa permissão. Trate metadados de diretórios graváveis como um indício para análise, não como prova de um reload, uma reinicialização ou uma execução de comando autorizados. Inspecione caminhos, permissões e políticas sem gravar configurações nem chamar a API.

## Siga a cadeia de execução do serviço

```bash
systemctl cat <unit>.service
systemctl show <unit>.service -p User -p Group -p ExecStart -p EnvironmentFiles -p WorkingDirectory
namei -l /path/from/ExecStart
```

Verifique a unidade, os drop-ins, `EnvironmentFile=`, os scripts auxiliares, os comandos relativos, os diretórios graváveis e a ativação por socket. Uma unidade pertencente ao root ainda pode ser insegura se ler um arquivo de configuração ou script gravável por um usuário. A página sobre [escrita arbitrária de arquivos](../interesting-files-permissions/write-to-root.md) aborda caminhos comuns de abuso de serviços e unidades. Monitore jobs de curta duração com [pspy](https://github.com/DominicBreuker/pspy) ou telemetria de auditoria/processos quando uma única listagem de `ps` não os detectar.

Para um serviço **xinetd** personalizado, correlacione as diretivas `server`, `user` e os controles de acesso do bloco habilitado com o listener ativo e o executável exato. A [configuração `user`](https://manpages.debian.org/testing/xinetd/xinetd.conf.5.en.html) define a identidade do processo iniciado, enquanto um bit set-user-ID no executável pode alterar separadamente sua identidade efetiva, se [`execve` permitir essa transição](https://man7.org/linux/man-pages/man2/execve.2.html). Um binário privilegiado acessível que aceite entrada não confiável merece uma análise offline do código-fonte ou da desmontagem em busca de bugs de segurança de memória, como uma conversão de string [`scanf` sem limite](https://www.gnu.org/software/libc/manual/html_node/String-Input-Conversions.html) para um buffer de tamanho fixo. O mapeamento do serviço e os metadados set-user-ID são pistas, não provas de que esse bug existe; não envie entradas que causem falhas nem depure o serviço privilegiado em execução durante a enumeração passiva.

Para um listener privilegiado personalizado com código-fonte legível, revise cada comprimento controlado pelo chamador usado em uma operação de cópia, como [`memcpy`](https://man7.org/linux/man-pages/man3/memcpy.3.html). Verificar apenas se o índice de escrita atual está dentro de um buffer fixo não garante que o **comprimento da cópia** caiba no espaço restante; confirme `copy_length <= capacity - index` depois de verificar que o índice está dentro dos limites e confira o sinal dos valores e possíveis estouros aritméticos. Isso é apenas uma pista de revisão quando a entrada chega a essa operação, o listener está acessível ao usuário com menos privilégios e o processo mantém uma identidade efetiva mais privilegiada. Inspecione o código-fonte e os metadados do processo offline; não envie entradas que causem falhas ao serviço ativo durante a enumeração.

Em sistemas que usam **Upstart**, as definições de jobs do sistema podem estar em `/etc/init/*.conf`. Um arquivo de job gravável pelo usuário atual é relevante quando o daemon init ativo carrega esse arquivo exato, a diretiva `script` ou `exec` é executada com uma identidade mais privilegiada e o usuário pode iniciá-lo por um comando `initctl` permitido ou por outro acionador real. Uma permissão sudo para `initctl`, por si só, não prova que algum arquivo de job seja gravável nem que um job modificado será executado. Verifique as permissões do arquivo de job exato, a configuração efetiva de usuário, o daemon ativo e o acionador, sem editar nem iniciar o job durante a enumeração. Consulte os manuais de [configuração de jobs do Upstart](https://manpages.ubuntu.com/manpages/trusty/man5/init.5.html) e [`initctl`](https://manpages.ubuntu.com/manpages/xenial/man8/initctl.8.html).

Um arquivo de senha de autologin legível, como `/etc/autologin/passwd` em sistemas cujo [job de inicialização lê exatamente esse caminho](https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/master/chromeos-base/autologin/files/init/autologin.conf), é uma pista de exposição de credenciais. Confirme que o job de inicialização está instalado e usa o arquivo; depois, verifique separadamente se a senha é válida para outra conta local ou serviço. O nome do arquivo, por si só, não comprova reutilização da senha; registre o caminho e os metadados de acesso sem incluir a senha na saída de enumeração compartilhada.

A diretiva `ExecStart=` de uma unidade ou um comando agendado pode revelar o caminho exato de um script dentro de um diretório cujo conteúdo não pode ser listado. A [permissão de busca em diretórios](https://man7.org/linux/man-pages/man7/path_resolution.7.html) ainda pode permitir que a identidade atual percorra esse caminho conhecido; confirme a permissão de busca em cada diretório pai e a permissão de leitura no arquivo, em vez de presumir que uma listagem de diretório malsucedida o protege. Um script legível pode conter uma credencial de transferência, mas o acesso a outra conta depende de essa credencial continuar válida e ser aceita de forma independente nela. Registre o caminho e as evidências de permissões sem imprimir valores secretos em logs compartilhados.

Para um script CommonJS do Node.js agendado, examine imports sem caminho, como `require('package')`, mesmo quando o próprio script é somente leitura. [O Node pesquisa `node_modules` ao lado do arquivo que faz o import e, em seguida, nos diretórios ancestrais](https://nodejs.org/api/modules.html#loading-from-node_modules-folders), antes de recorrer aos caminhos globais configurados. Um usuário com menos privilégios que possa **escrever e buscar** em um desses diretórios ancestrais talvez consiga criar um pacote que tenha prioridade na resolução. Confirme que o import exato é alcançado, que o pacote selecionado não é um módulo interno, que o caminho relevante pode ser criado ou alterado, que o módulo é resolvido nesse local pelo runtime instalado e que um job mais privilegiado o carregará em uma execução futura. Metadados de diretório pai gravável são apenas um sinal para revisão; examine o script e o agendador passivamente, sem instalar um módulo nem acionar o job.

Um índice privado de pacotes Python também é uma fronteira de confiança quando um job automatizado instala pacotes sob outra identidade do sistema operacional. Correlacione o job exato e a conta usada para executá-lo com o índice configurado, os nomes dos pacotes selecionados e a possibilidade de um usuário com menos privilégios publicar ou substituir um pacote que o job realmente instalará. A criação de uma distribuição de código-fonte pode executar o backend de build ou o `setup.py` legado com a identidade do instalador; importar o pacote instalado é um caminho de execução separado. Um listener de índice, um hash de senha de upload legível ou apenas o nome de um arquivo de pacote não comprovam essa cadeia. Revise o job, a autorização do índice e a procedência do pacote sem fazer upload nem instalar nada durante a enumeração. Consulte a [interface de build do pip](https://pip.pypa.io/en/stable/reference/build-system/) e as [orientações para instalações seguras](https://pip.pypa.io/en/stable/topics/secure-installs/).

Um agente privilegiado pode consultar uma fila de tarefas gerenciada por um serviço web ou contêiner separado. Se uma identidade com menos confiança puder gravar no banco de dados de tarefas do serviço, determine se essas linhas são realmente disponibilizadas ao agente e se uma tarefa de comando é executada com a identidade do sistema operacional do agente. Confirme separadamente o acesso de gravação ao banco de dados, a sessão ou chave de roteamento de destino, a consulta ativa da fila, a autorização da tarefa e o usuário efetivo do agente. Ser root dentro de um contêiner não implica, por si só, acesso root ao host; a fronteira só é ultrapassada se um consumidor privilegiado no host executar dados de tarefa controlados por um atacante. Inspecione os metadados de processos, arquivos de banco de dados e serviços sem modificar a fila nem enviar uma tarefa durante a enumeração.

Em vez disso, um job recorrente pode ler um comando de uma linha de configuração de banco de dados de uma aplicação. Confirme que a função de banco de dados com menos privilégios pode alterar exatamente essa linha, que o job ativo a lê depois da alteração e que o valor chega a um shell ou executor de comandos equivalente sob uma identidade de sistema operacional mais privilegiada. O acesso de gravação ao banco de dados ou um valor que pareça um comando, por si só, não comprova execução; examine o job e as permissões sem alterar a linha durante a enumeração passiva.

Uma mensagem enfileirada também pode conter uma URL em vez de código. Se um consumidor privilegiado buscar essa URL e carregar a resposta como um plugin executável Lua ou de outra linguagem, verifique a permissão do publicador no exchange e na chave de roteamento exatos, o vínculo com a fila consumida, o caminho de busca e carregamento do plugin e a identidade efetiva do worker. [O RabbitMQ roteia mensagens publicadas por meio de exchanges](https://www.rabbitmq.com/docs/exchanges); um listener do broker ou um login válido, por si só, não comprova que a mensagem será entregue a esse worker. Credenciais de broker em texto claro capturadas são uma pista separada que exige acesso real à captura de pacotes e tráfego legível; elas não comprovam autorização para publicar. Um plugin Lua só pode invocar comandos shell por meio de [`os.execute`](https://www.lua.org/manual/5.4/manual.html#pdf-os.execute) se essa API estiver disponível no runtime. Revise a configuração e o código sem capturar tráfego, publicar mensagens nem buscar um plugin durante a enumeração passiva.

Quando um serviço Python privilegiado expõe um endpoint HTTP ou socket local, um script legível pode revelar um caminho da entrada até a execução de código, mesmo que as permissões do arquivo impeçam sua modificação. Correlacione o processo ativo e a identidade da unidade com o script exato, o listener, a autorização da rota e os campos controlados pelo chamador. Em seguida, acompanhe esses campos durante o parsing e a validação até um ponto de execução dinâmica `eval()` ou `exec()`. Em particular, construir uma nova f-string a partir do texto da requisição e avaliá-la pode interpretar campos de substituição fornecidos pelo atacante como expressões Python ([aviso sobre `eval` do Python](https://docs.python.org/3/library/functions.html#eval); [semântica de f-strings](https://docs.python.org/3/reference/lexical_analysis.html#f-strings)). Encontrar `eval` sem contexto ou um bind em loopback não prova que um chamador não confiável alcance esse ponto; examine o fluxo real dos dados e os controles de acesso sem enviar um payload de teste durante a enumeração.

Uma verificação de requisições assinadas nessa rota exige uma análise própria. Se o código-fonte legível derivar a chave de assinatura de um espaço de saída comprovadamente pequeno ou previsível e o serviço expuser uma amostra válida assinada, a assinatura talvez já não proteja um ponto privilegiado de `eval()`. Verifique a derivação exata da chave e o verificador, a identidade do serviço ativo e o acesso de chamadores locais, além de confirmar se o campo assinado chega ao ponto de execução; um import do módulo [`random` do Python](https://docs.python.org/3/library/random.html) ou uma assinatura de exemplo não comprova nenhuma dessas condições. O Python também alerta que restringir `__builtins__` [não é uma fronteira de segurança para entradas não confiáveis em `eval()`](https://docs.python.org/3/library/functions.html#eval). Analise a chave offline e não envie requisições forjadas durante a enumeração passiva.

Um diretório `/etc/systemd/system/<unit>.service.d` vazio, mas gravável, é relevante mesmo quando o arquivo da unidade e todos os drop-ins existentes estão protegidos: o usuário pode criar uma nova sobrescrita `.conf`. Verifique se a identidade atual pode gravar e buscar nesse diretório, se a unidade está carregada e é executada como root e se haverá um reload do daemon seguido de uma reinicialização. Uma permissão para fazer reload ou reiniciar, um timer ou uma inicialização futura pode efetivar a alteração; o acesso de gravação ao diretório, por si só, não a executa imediatamente.

Para serviços em execução, siga os caminhos literais de `EnvironmentFile=` na seção `[Service]` da unidade, incluindo arquivos cujos nomes não começam com `.env`. Se um usuário com poucos privilégios puder ler um deles, liste nomes de chaves que pareçam credenciais, como `API_TOKEN` ou `APP_SECRET_KEY`, sem imprimir os valores em logs compartilhados. Verifique as sobrescritas de drop-ins e os prefixos opcionais `-` ao avaliar a unidade efetiva. A possibilidade de leitura é uma pista de exposição de credenciais; o valor ainda precisa ser válido para uma ação privilegiada a fim de possibilitar escalada.

### Processamento privilegiado de uploads não confiáveis

Um observador de arquivos executado como root pode encaminhar arquivos de um diretório de uploads gravável por usuários a um parser ou extrator de curta duração. Siga o script pai ou serviço do observador em execução e confirme o diretório exato, quem pode colocar arquivos nele, o comando filho e seus argumentos, além da identidade sob a qual o filho é executado. Uma captura de processos pode mostrar o observador e não detectar o extrator entre uploads. Não coloque um payload de teste nem acione o observador durante a enumeração passiva.

Um exemplo concreto é o modo de extração do Binwalk (`-e`) ao processar dados PFS controlados por um atacante. A [CVE-2022-4510](https://github.com/ReFirmLabs/binwalk/pull/617) permitia que o extrator PFS gravasse fora do diretório pretendido, inclusive em um caminho de plugin que o Binwalk poderia carregar posteriormente. O upstream incluiu a correção na [versão 2.3.4](https://github.com/ReFirmLabs/binwalk/releases/tag/v2.3.4), mas backports de distribuições podem manter uma versão exibida mais antiga; verifique o status de segurança do pacote instalado, como no [rastreador do Debian](https://security-tracker.debian.org/tracker/CVE-2022-4510), antes de avaliar se o problema se aplica. A versão instalada do Binwalk, por si só, não comprova um caminho de escalada de privilégios: a extração precisa ser realmente invocada por um processo mais privilegiado em uma entrada controlável pelo usuário com menos privilégios.

### Builds agendados com dependências locais

Um `cargo run` agendado recompila o código-fonte como o usuário definido para executar o job. Inspecione as dependências locais `{ path = "..." }` do manifesto e as permissões do código-fonte e dos diretórios pai de cada dependência, não apenas as do crate principal. Se um usuário com menos privilégios puder modificar uma dependência que o Cargo compila e o job agendado executar o resultado, o código compilado poderá ser executado como esse usuário definido para o job. Confirme o comando efetivo do agendador, o diretório de trabalho, a resolução das dependências e se ocorrerá uma recompilação; um arquivo-fonte Rust gravável em outro local é apenas uma pista. Ler o manifesto e os metadados dos caminhos é suficiente para a triagem passiva. Consulte a [documentação do Cargo sobre dependências por caminho](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#specifying-path-dependencies).

## Arquivos de framebuffer do Xvfb

`Xvfb -fbdir <directory>` usa arquivos mapeados em memória chamados `Xvfb_screen<n>` para suas telas virtuais. Se um processo Xvfb de outro usuário em execução especificar um diretório cujos arquivos de tela sejam legíveis pelo usuário atual, o framebuffer poderá expor o conteúdo da área de trabalho desse usuário. Confirme o processo, o proprietário dos arquivos e as permissões em conjunto; um arquivo legível, por si só, não prova que há conteúdo útil na tela. Primeiro inspecione os caminhos e metadados, sem copiar dados de imagem para a saída de enumeração compartilhada. O [manual do Xvfb](https://xorg.freedesktop.org/archive/X11R7.5/doc/man/man1/Xvfb.1.html) documenta o comportamento de `-fbdir`.

```bash
pgrep -a -x Xvfb
ls -l /path/from/-fbdir/Xvfb_screen*
```

## References

1. [Manual do Linux `shmget(2)`](https://man7.org/linux/man-pages/man2/shmget.2.html)
2. [Manual do Linux `ipcs(1)`](https://man7.org/linux/man-pages/man1/ipcs.1.html)
3. [Manual do OpenBSD `ipcs(1)`](https://man.openbsd.org/ipcs.1)
4. [Configuração do agente Consul: verificações de script](https://developer.hashicorp.com/consul/docs/reference/agent/configuration-file/general)
5. [API de registro de serviços do agente Consul](https://developer.hashicorp.com/consul/api-docs/agent/service)
6. [Configuração de ACL do Consul](https://developer.hashicorp.com/consul/docs/reference/agent/configuration-file/acl)
7. [Ajuda do LibreOffice: abrir um socket para clientes externos da API](https://help.libreoffice.org/latest/en-US/text/sbasic/shared/03/sf_intro.html)
8. [SDK do LibreOffice: `XSystemShellExecute`](https://api.libreoffice.org/docs/idl/ref/interfacecom_1_1sun_1_1star_1_1system_1_1XSystemShellExecute.html)

{{#include ../../banners/hacktricks-training.md}}
