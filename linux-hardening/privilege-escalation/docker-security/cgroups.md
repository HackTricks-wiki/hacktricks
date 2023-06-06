## Informações Básicas

Os **grupos de controle do Linux**, também conhecidos como cgroups, são um recurso do kernel do Linux que permite **limitar**, policiar e priorizar **recursos do sistema** para uma coleção de processos. Os cgroups fornecem uma maneira de **gerenciar e isolar o uso de recursos** (CPU, memória, E/S de disco, rede, etc.) de grupos de processos em um sistema. Isso pode ser útil para muitos propósitos, como limitar os recursos disponíveis para um grupo específico de processos, isolar certos tipos de cargas de trabalho de outros ou priorizar o uso de recursos do sistema entre diferentes grupos de processos.

Existem **duas versões de cgroups**, 1 e 2, e ambas estão atualmente em uso e podem ser configuradas simultaneamente em um sistema. A **diferença mais significativa** entre a versão 1 e a **versão 2** dos cgroups é que esta última introduziu uma nova organização hierárquica para os cgroups, onde os grupos podem ser organizados em uma estrutura semelhante a uma árvore com relacionamentos pai-filho. Isso permite um controle mais flexível e refinado sobre a alocação de recursos entre diferentes grupos de processos.

Além da nova organização hierárquica, a versão 2 dos cgroups também introduziu **várias outras mudanças e melhorias**, como suporte a **novos controladores de recursos**, melhor suporte para aplicativos legados e melhor desempenho.

Em geral, a versão 2 dos cgroups oferece mais recursos e melhor desempenho do que a versão 1, mas esta última ainda pode ser usada em determinados cenários em que a compatibilidade com sistemas mais antigos é uma preocupação.

Você pode listar os cgroups v1 e v2 para qualquer processo olhando para o arquivo cgroup em /proc/\<pid>. Você pode começar olhando para os cgroups do seu shell com este comando:
```shell-session
$ cat /proc/self/cgroup
12:rdma:/
11:net_cls,net_prio:/
10:perf_event:/
9:cpuset:/
8:cpu,cpuacct:/user.slice
7:blkio:/user.slice
6:memory:/user.slice 5:pids:/user.slice/user-1000.slice/session-2.scope 4:devices:/user.slice
3:freezer:/
2:hugetlb:/testcgroup
1:name=systemd:/user.slice/user-1000.slice/session-2.scope
0::/user.slice/user-1000.slice/session-2.scope
```
Não se preocupe se a saída for significativamente mais curta no seu sistema; isso apenas significa que você provavelmente tem apenas cgroups v2. Cada linha de saída aqui começa com um número e é um cgroup diferente. Aqui estão algumas dicas sobre como lê-lo:

* Os números 2-12 são para cgroups v1. Os controladores para esses são listados ao lado do número.
* O número 1 também é para a versão 1, mas não tem um controlador. Este cgroup é apenas para fins de gerenciamento (neste caso, o systemd o configurou).
* A última linha, número 0, é para cgroups v2. Nenhum controlador é visível aqui. Em um sistema que não possui cgroups v1, esta será a única linha de saída.
* Os nomes são hierárquicos e parecem partes de caminhos de arquivos. Você pode ver neste exemplo que alguns dos cgroups são nomeados /user.slice e outros /user.slice/user-1000.slice/session-2.scope.
* O nome /testcgroup foi criado para mostrar que, em cgroups v1, os cgroups para um processo podem ser completamente independentes.
* Nomes sob user.slice que incluem sessão são sessões de login, atribuídas pelo systemd. Você os verá ao olhar para os cgroups de um shell. Os cgroups para seus serviços do sistema estarão sob system.slice.

### Visualizando cgroups

Os cgroups são normalmente acessados através do sistema de arquivos. Isso é em contraste com a interface de chamada de sistema Unix tradicional para interagir com o kernel.\
Para explorar a configuração de cgroups de um shell, você pode olhar no arquivo `/proc/self/cgroup` para encontrar o cgroup do shell e, em seguida, navegar até o diretório `/sys/fs/cgroup` (ou `/sys/fs/cgroup/unified`) e procurar um diretório com o mesmo nome do cgroup. Mudar para este diretório e olhar ao redor permitirá que você veja as várias configurações e informações de uso de recursos para o cgroup.

<figure><img src="../../../.gitbook/assets/image (10).png" alt=""><figcaption></figcaption></figure>

Entre os muitos arquivos que podem estar aqui, os principais arquivos de interface do cgroup começam com `cgroup`. Comece olhando para `cgroup.procs` (usando cat está bem), que lista os processos no cgroup. Um arquivo semelhante, `cgroup.threads`, também inclui threads.

<figure><img src="../../../.gitbook/assets/image (1) (1) (5).png" alt=""><figcaption></figcaption></figure>

A maioria dos cgroups usados para shells tem esses dois controladores, que podem controlar a quantidade de memória usada e o número total de processos no cgroup. Para interagir com um controlador, procure os arquivos que correspondem ao prefixo do controlador. Por exemplo, se você quiser ver o número de threads em execução no cgroup, consulte pids.current:

<figure><img src="../../../.gitbook/assets/image (3) (5).png" alt=""><figcaption></figcaption></figure>

Um valor de max significa que este cgroup não tem limite específico, mas porque os cgroups são hierárquicos, um cgroup de volta na cadeia de subdiretórios pode limitá-lo.

### Manipulando e Criando cgroups

Para colocar um processo em um cgroup, escreva seu PID no arquivo `cgroup.procs` como root:
```shell-session
# echo pid > cgroup.procs
```
Assim é como as mudanças em cgroups funcionam. Por exemplo, se você quiser **limitar o número máximo de PIDs de um cgroup** (para, digamos, 3.000 PIDs), faça o seguinte:
```shell-session
# echo 3000 > pids.max
```
**Criar cgroups é mais complicado**. Tecnicamente, é tão fácil quanto criar um subdiretório em algum lugar na árvore de cgroups; quando você faz isso, o kernel cria automaticamente os arquivos de interface. Se um cgroup não tiver processos, você pode remover o cgroup com rmdir mesmo com os arquivos de interface presentes. O que pode te confundir são as regras que regem os cgroups, incluindo:

* Você só pode colocar **processos em cgroups de nível externo ("folha")**. Por exemplo, se você tiver cgroups chamados /meu-cgroup e /meu-cgroup/meu-subgrupo, você não pode colocar processos em /meu-cgroup, mas /meu-cgroup/meu-subgrupo está ok. (Uma exceção é se os cgroups não tiverem controladores, mas não vamos nos aprofundar nisso.)
* Um cgroup **não pode ter um controlador que não esteja em seu cgroup pai**.
* Você deve **especificar explicitamente controladores para cgroups filhos**. Você faz isso através do arquivo `cgroup.subtree_control`; por exemplo, se você quiser que um cgroup filho tenha os controladores cpu e pids, escreva +cpu +pids neste arquivo.

Uma exceção a essas regras é o **cgroup raiz** encontrado na parte inferior da hierarquia. Você pode **colocar processos neste cgroup**. Uma razão pela qual você pode querer fazer isso é para desvincular um processo do controle do systemd.

Mesmo sem controladores habilitados, você pode ver o uso da CPU de um cgroup olhando para o arquivo cpu.stat:

<figure><img src="../../../.gitbook/assets/image (2) (6) (3).png" alt=""><figcaption></figcaption></figure>

Como este é o uso acumulado da CPU ao longo de toda a vida útil do cgroup, você pode ver como um serviço consome tempo do processador mesmo se ele gerar muitos subprocessos que eventualmente terminam.
