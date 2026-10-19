# Triagem de Rede Local e Sockets

{{#include ../../banners/hacktricks-training.md}}

Após obter um shell em um host Linux, os alvos de rede mais úteis geralmente não estão expostos externamente. Serviços acessíveis apenas via loopback, redes veth, sockets Unix, listeners temporários, capturas de pacotes e regras de firewall locais podem expor credenciais ou superfícies de ataque acessíveis apenas localmente.

Esta página se concentra em técnicas práticas de post-exploitation local, não em pentesting de rede remota em geral.

## Enumeração de Loopback e Serviços Locais

Comece identificando os serviços em escuta, seus endereços de bind e o processo proprietário, quando as permissões permitirem.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
ss -lntup
ss -lnx
ip addr
ip route
```

Padrões importantes:

- `127.0.0.1:<port>` ou `[::1]:<port>`: acessível apenas pelo host por padrão.<sup>[[3]](#references)[[4]](#references)</sup>
- `0.0.0.0:<port>`: acessível em todas as interfaces IPv4, a menos que haja filtragem.<sup>[[3]](#references)</sup>
- `10.0.0.0/8`, `172.16.0.0/12` ou `192.168.0.0/16` em `veth*`, `docker*`, `br-*`, `cni*`: provavelmente redes de contêineres ou laboratórios locais.<sup>[[23]](#references)[[24]](#references)</sup>
- Sockets Unix em `/run`, `/var/run`, `/tmp` ou diretórios de aplicações: superfícies locais de IPC.<sup>[[5]](#references)</sup>

Para o problema histórico de parsing de socket do [snapd, CVE-2019-7304](https://ubuntu.com/security/vulnerabilities/snap-socket-parsing), inspecione o daemon em execução, seu socket de API local e a revisão do pacote ou snap instalado, comparando-os com a correção para essa distribuição. O bug estava na validação do endereço de socket de um peer pelo snapd, não no `snap-confine`; um arquivo `snap-confine` com set-user-ID ou apenas uma string de versão upstream não bastam para determinar se há exposição. O Ubuntu disponibilizou correções em versões de pacote específicas de cada release, e o snapd pode ter sido atualizado por meio de um snap independentemente do pacote da distribuição. Confirme a build em execução e a acessibilidade do socket local antes de avaliar o limite da API privilegiada. A enumeração passiva não deve enviar uma solicitação de socket criada para esse fim nem instalar um snap.

Um listener de loopback iniciado por [`socat` com `EXEC`](https://man7.org/linux/man-pages/man1/socat.1.html) pode encaminhar a entrada de um cliente local para outro programa. Correlacione o comando do listener, o caminho do executável, a identidade efetiva do processo filho, a acessibilidade local e a autenticação antes de considerar um serviço personalizado pertencente ao root como uma possível via de escalonamento de privilégios. Uma falha de segurança de memória ou um caminho inseguro entre a entrada e um comando exige evidências do binário e da build específicos; o número da porta, o processo `socat` ou o proprietário root, por si só, não comprovam isso. A enumeração passiva deve se limitar aos metadados de processos, sockets e arquivos, sem enviar entrada ao serviço.

Um master local do Salt pode escutar nas portas TCP 4505 e 4506, inclusive em loopback ou em uma porta do host publicada por um contêiner. As [notas de lançamento da versão 3000.2 do Salt](https://docs.saltproject.io/en/latest/topics/releases/3000.2.html) descrevem uma falha de acesso a métodos sem autenticação, CVE-2020-11651, corrigida nas versões upstream 2019.2.4 e 3000.2. Correlacione o listener com o processo `salt-master` real, a interface acessível, o pacote instalado e as correções do fornecedor, além da identidade efetiva do contêiner ou do host, antes de considerá-lo uma possível via de escalonamento; uma porta ou versão upstream, por si só, não é prova. Se um master estiver em execução dentro de um contêiner, o impacto como root no host é um limite separado: confirme se um socket utilizável da API do runtime do host está montado e acessível nesse contêiner. A enumeração passiva não deve consultar o servidor de solicitações do Salt nem criar um contêiner para determinar a exposição. Consulte a [documentação de portas do Salt](https://docs.saltproject.io/salt/install-guide/en/latest/topics/before-you-start/check-network-ports.html) e a [triagem da API do runtime](../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md).

Mapeie portas locais com sondas leves.<sup>[[6]](#references)[[7]](#references)</sup>

```bash
for p in 80 443 8000 8080 8081 9000 5000; do
  timeout 1 bash -c "echo >/dev/tcp/127.0.0.1/$p" 2>/dev/null && echo "open: $p"
done
```

Use `nmap` localmente quando disponível.<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>

```bash
nmap -sT -Pn -p- 127.0.0.1
nmap -sT -Pn --open 127.0.0.1
```

## Sub-redes ocultas de veth e contêineres

Ambientes em contêineres ou de laboratório frequentemente expõem serviços apenas em uma bridge ou sub-rede veth. Enumere as interfaces e rotas antes de presumir que um serviço está inacessível.<sup>[[2]](#references)</sup>

```bash
ip -br addr
ip route
ip neigh
```

Encontre sub-redes locais prováveis.<sup>[[2]](#references)</sup>

```bash
ip -o -4 addr show | awk '{print $2, $4}'
```

Investigue cuidadosamente uma sub-rede descoberta.<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>

```bash
nmap -sT -Pn --open 172.17.0.0/24
nmap -sT -Pn -p 80,443,8000,8080,9000 172.17.0.0/24
```

A técnica é útil quando um painel web, endpoint de debug ou serviço auxiliar fica oculto de varreduras externas, mas pode ser acessado pelo host comprometido ou pela rede do container.

## Tokens de serviços Notebook entre limites de usuário

Um serviço Notebook vinculado ao loopback pode autenticar usando um token de inicialização exibido na saída do processo. Se essa saída for redirecionada para um log legível por outra conta local, o token pode atravessar um limite entre usuários e permitir execução de código na conta do servidor Notebook. Antes de considerar um caminho de log como uma pista de escalada, correlacione o proprietário do processo que está escutando, o destino e as permissões do log, a configuração atual do token e os controles de acesso ao Notebook. Durante a enumeração passiva, liste os metadados do log; não exiba tokens nem se conecte ao serviço apenas para classificar o host.

Um serviço Jupyter Lab também pode expor seu token em um `ExecStart` do systemd legível ou na linha de comando do processo em execução (`ps auxww`), em vez de apenas nos logs de inicialização. No exemplo relatado, `User=analyst` e `--ServerApp.token` identificavam tanto a credencial quanto a conta por trás de um listener em `127.0.0.1:8888`. Com acesso ao host, o token e `ssh -L 8888:127.0.0.1:8888 user@host` permitiram acessar o Terminal do Jupyter Lab como esse usuário do serviço. Verifique em conjunto o usuário efetivo da unit, os argumentos do processo, o listener e a validade do token; o vínculo ao loopback, por si só, não é um limite de autorização.<sup>[[28]](#references)</sup>

## Pivot local com socat ou SSH

Se um serviço estiver vinculado ao loopback, exponha-o por um canal permitido em vez de alterar o próprio serviço.

Encaminhe um serviço HTTP disponível apenas localmente com SSH.<sup>[[11]](#references)</sup>

```bash
ssh -L 8080:127.0.0.1:8080 user@target
```

Faça a ponte de uma porta local com `socat` quando você já tiver acesso ao shell.<sup>[[12]](#references)</sup>

```bash
socat TCP-LISTEN:18080,fork,reuseaddr TCP:127.0.0.1:8080
```

Encaminhe um socket Unix para TCP para testes locais.<sup>[[5]](#references)[[12]](#references)</sup>

```bash
socat TCP-LISTEN:18081,fork,reuseaddr UNIX-CONNECT:/run/app/app.sock
```

Isso não explora nada por si só. Torna uma superfície disponível apenas localmente acessível pelas suas ferramentas, para que você possa interagir com ela como faria com um serviço normal.

## Banner Grabbing e protocolos simples

Nem todo serviço usa HTTP. Muitos serviços locais vazam informações suficientes por meio de um banner ou de um protocolo de uma linha.

Sondagens básicas.<sup>[[13]](#references)</sup>

```bash
nc -nv 127.0.0.1 9000
printf 'help\n' | nc -nv 127.0.0.1 9000
printf 'version\n' | nc -nv 127.0.0.1 9000
```

Verificação HTTP sem um navegador.<sup>[[13]](#references)[[14]](#references)</sup>

```bash
printf 'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' | nc -nv 127.0.0.1 8080
curl -i http://127.0.0.1:8080/
```

Para TLS.<sup>[[14]](#references)[[15]](#references)</sup>

```bash
openssl s_client -connect 127.0.0.1:8443 -servername localhost
curl -k -i https://127.0.0.1:8443/
```

O objetivo é identificar o protocolo, o esquema de autenticação, a versão e se o serviço confia em clientes locais.

Para um listener aiohttp, verifique sua configuração de rotas estáticas e também sua versão. A CVE-2024-23334 afeta versões do aiohttp anteriores à 3.9.2 quando uma rota estática habilita `follow_symlinks=True`: requisições a essa rota podem ler arquivos fora da raiz estática. Se o serviço for executado como root, ele poderá expor arquivos que podem ser lidos pelo root, desde que a rota esteja acessível. Um banner de versão ou um bind em loopback, por si só, não comprova que a configuração vulnerável esteja ativa nem que os arquivos possam ser acessados.<sup>[[27]](#references)</sup>

## Captura de tráfego loopback

O tráfego local pode expor cabeçalhos, tokens bearer, credenciais de Basic Auth ou segredos específicos da aplicação.<sup>[[17]](#references)[[25]](#references)</sup> Faça capturas apenas em ambientes autorizados.

Capture o tráfego HTTP de loopback.<sup>[[16]](#references)</sup>

```bash
sudo tcpdump -i lo -A -s0 'tcp port 80 or tcp port 8080'
```

Capture um serviço local específico.<sup>[[16]](#references)</sup>

```bash
sudo tcpdump -i lo -w /tmp/loopback.pcap 'tcp port 8080'
```

Decodifique Basic Auth de um cabeçalho capturado ou registrado.<sup>[[17]](#references)[[18]](#references)</sup>

```bash
printf '%s' 'dXNlcjpwYXNz' | base64 -d
```

Strings úteis para procurar em capturas de texto:

```bash
grep -Ei 'Authorization:|Cookie:|Bearer|Basic|token|api[_-]?key|password' /tmp/capture.txt
```

## Registro de chaves TLS

Se você puder controlar o ambiente do processo cliente em um laboratório, `SSLKEYLOGFILE` pode permitir descriptografar sessões TLS no Wireshark ou em ferramentas compatíveis.<sup>[[19]](#references)[[20]](#references)</sup> Isso é útil para entender o tráfego HTTPS local sem atacar o próprio TLS.

Execute um cliente com o registro de chaves habilitado.<sup>[[19]](#references)[[20]](#references)</sup>

```bash
export SSLKEYLOGFILE=/tmp/sslkeys.log
curl -k https://127.0.0.1:8443/
ls -l /tmp/sslkeys.log
```

Capture o tráfego ao mesmo tempo.<sup>[[16]](#references)</sup>

```bash
sudo tcpdump -i lo -w /tmp/tls.pcap 'tcp port 8443'
```

Em seguida, carregue `/tmp/tls.pcap` e `/tmp/sslkeys.log` no Wireshark. Isso só funciona quando a biblioteca cliente oferece suporte ao registro de chaves no estilo NSS e você pode definir o ambiente antes de estabelecer a conexão.<sup>[[20]](#references)[[21]](#references)</sup>

## Interação com Unix Sockets e Command Injection

Unix sockets são endpoints locais de IPC.<sup>[[5]](#references)</sup> Eles podem expor APIs HTTP, protocolos personalizados ou handlers de comandos inseguros.<sup>[[12]](#references)[[14]](#references)</sup>

Um socket de propriedade do root com permissão de escrita para o grupo define um limite de autorização, mas não é, por si só, uma vulnerabilidade. Compare o grupo e as permissões com a conta atual, identifique o processo que está escutando e analise o que esse processo aceita dos clientes antes de avaliar o risco. Em particular, um serviço privilegiado que executa PHP enviado pelo cliente pode cruzar um segundo limite se também confiar em um caminho de `php.ini` escolhido pelo cliente ou permitir que ele altere `disable_functions` ou `open_basedir`; inspecione a configuração efetiva e o caminho de validação do serviço. O [guia de configuração do PHP](../../network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass/README.md) explica essas diretivas. Os metadados do socket, por si só, não comprovam execução de código.

Encontre sockets.<sup>[[1]](#references)[[5]](#references)</sup>

```bash
ss -lnx
find /run /var/run /tmp -type s -ls 2>/dev/null
```

Interaja com HTTP por meio de um socket Unix.<sup>[[14]](#references)</sup>

```bash
curl --unix-socket /run/app/app.sock http://localhost/
curl --unix-socket /run/app/app.sock -i http://localhost/admin
```

Interaja com um raw socket.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
printf 'status\n' | socat - UNIX-CONNECT:/run/app/app.sock
printf 'help\n' | nc -U /run/app/app.sock
```

Se o input de socket controlado pelo usuário for passado a um shell ou helper privilegiado, isso pode levar a command injection.<sup>[[26]](#references)</sup> Para um exemplo específico, consulte [Socket Command Injection](socket-command-injection.md).

## Revisão do nftables e alterações autorizadas nas regras

As regras locais de firewall podem explicar por que um serviço está visível localmente, mas bloqueado remotamente, ou por que uma porta alta parece inacessível por uma interface.<sup>[[22]](#references)</sup>

Revise as regras.<sup>[[22]](#references)</sup>

```bash
sudo nft list ruleset
sudo nft list tables
sudo nft list chains
```

Procure drops que afetem uma porta-alvo.<sup>[[22]](#references)</sup>

```bash
sudo nft list ruleset | grep -Ei 'drop|reject|dport|tcp|udp'
```

Em um laboratório autorizado, remova uma regra de bloqueio específica usando seu handle.<sup>[[22]](#references)</sup>

```bash
sudo nft -a list chain inet filter input
sudo nft delete rule inet filter input handle <handle>
```

Prefira excluir o handle exato em vez de limpar tabelas inteiras. A técnica consiste em identificar o filtro preciso que causa o comportamento e alterar somente essa regra.<sup>[[22]](#references)</sup>

## Quick Workflow

```bash
ss -lntup
ss -lnx
ip -br addr
ip route
nmap -sT -Pn --open 127.0.0.1
find /run /var/run /tmp -type s -ls 2>/dev/null
sudo nft list ruleset 2>/dev/null | head -n 80
```

Priorize serviços disponíveis apenas localmente, executados por um usuário com mais privilégios, que exponham funções administrativas/de depuração ou confiem em clientes de loopback/rede de contêineres.

## References

- [1] [ss(8) — página de manual do Linux](https://man7.org/linux/man-pages/man8/ss.8.html)
- [2] [ip(8) — página de manual do Linux](https://man7.org/linux/man-pages/man8/ip.8.html)
- [3] [ip(7) — página de manual do Linux](https://man7.org/linux/man-pages/man7/ip.7.html)
- [4] [RFC 4291: Arquitetura de endereçamento da versão 6 do IP](https://www.rfc-editor.org/info/rfc4291/)
- [5] [unix(7) — página de manual do Linux](https://man7.org/linux/man-pages/man7/unix.7.html)
- [6] [Redirecionamentos (Manual de referência do Bash)](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
- [7] [invocação de timeout (GNU Coreutils)](https://www.gnu.org/s/coreutils/timeout)
- [8] [Técnicas de varredura de portas (Guia de referência do Nmap)](https://nmap.org/book/man-port-scanning-techniques.html)
- [9] [Descoberta de hosts (Guia de referência do Nmap)](https://nmap.org/book/man-host-discovery.html)
- [10] [Especificação de portas e ordem de varredura (Guia de referência do Nmap)](https://nmap.org/book/man-port-specification.html)
- [11] [ssh(1) — página de manual do Linux](https://man7.org/linux/man-pages/man1/ssh.1.html)
- [12] [socat(1) — página de manual do Linux](https://www.man7.org/linux/man-pages/man1/socat.1.html)
- [13] [nc(1) — página de manual do OpenBSD](https://man.openbsd.org/nc.1)
- [14] [Manual da ferramenta de linha de comando curl](https://curl.se/docs/manpage.html?category=23)
- [15] [openssl-s_client — documentação do OpenSSL](https://docs.openssl.org/3.0/man1/openssl-s_client/)
- [16] [tcpdump(8) — página de manual do Linux](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
- [17] [RFC 7617: Esquema de autenticação HTTP 'Basic'](https://www.rfc-editor.org/rfc/rfc7617.html)
- [18] [invocação de base64 (GNU Coreutils)](https://www.gnu.org/software/coreutils/manual/html_node/base64-invocation.html)
- [19] [openssl-env — documentação do OpenSSL](https://docs.openssl.org/master/man7/openssl-env/)
- [20] [TLS — Wiki do Wireshark](https://wiki.wireshark.org/tls)
- [21] [Guia do usuário do Wireshark](https://www.wireshark.org/docs/wsug_html/)
- [22] [Manual do nftables](https://netfilter.org/projects/nftables/manpage.html)
- [23] [Alocação de endereços para redes privadas (RFC 1918)](https://www.rfc-editor.org/rfc/rfc1918.html)
- [24] [ip-link(8) — página de manual do Linux](https://man7.org/linux/man-pages/man8/ip-link.8.html)
- [25] [A estrutura de autorização OAuth 2.0: uso de tokens Bearer (RFC 6750)](https://www.rfc-editor.org/rfc/rfc6750.html)
- [26] [CWE-78: Neutralização inadequada de elementos especiais usados em um comando do SO](https://cwe.mitre.org/data/definitions/78.html)
- [27] [Aviso do mantenedor do aiohttp: traversal de rota estática com follow_symlinks](https://github.com/aio-libs/aiohttp/security/advisories/GHSA-5h86-8mv2-jq9f)
- [28] [HTB: DevHub — token do Jupyter exposto por meio do systemd e de argumentos de processo](https://0xdf.gitlab.io/2026/10/10/htb-devhub.html)
{{#include ../../banners/hacktricks-training.md}}
