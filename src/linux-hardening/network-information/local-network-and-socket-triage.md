# Triagem de Rede Local e Sockets

{{#include ../../banners/hacktricks-training.md}}

Após obter um shell em um host Linux, os alvos de rede mais úteis geralmente não estão expostos externamente. Serviços disponíveis apenas via loopback, redes veth, sockets Unix, listeners temporários, packet captures e regras de firewall locais podem expor credenciais ou superfícies de ataque disponíveis apenas localmente.

Esta página se concentra em técnicas práticas de post-exploitation local, não em pentesting geral de redes remotas.

## Enumeração de Serviços Locais e de Loopback

Comece identificando os serviços em escuta, seus endereços de bind e o processo proprietário quando as permissões permitirem.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
ss -lntup
ss -lnx
ip addr
ip route
```
Padrões importantes:

- `127.0.0.1:<port>` ou `[::1]:<port>`: acessível somente pelo host por padrão.<sup>[[3]](#references)[[4]](#references)</sup>
- `0.0.0.0:<port>`: acessível em todas as interfaces IPv4, a menos que seja filtrado.<sup>[[3]](#references)</sup>
- `10.0.0.0/8`, `172.16.0.0/12` ou `192.168.0.0/16` em `veth*`, `docker*`, `br-*`, `cni*`: provavelmente redes de containers ou laboratórios locais.<sup>[[23]](#references)[[24]](#references)</sup>
- Unix sockets em `/run`, `/var/run`, `/tmp` ou diretórios de aplicações: superfícies locais de IPC.<sup>[[5]](#references)</sup>

Mapeie as portas locais com probes leves.<sup>[[6]](#references)[[7]](#references)</sup>
```bash
for p in 80 443 8000 8080 8081 9000 5000; do
timeout 1 bash -c "echo >/dev/tcp/127.0.0.1/$p" 2>/dev/null && echo "open: $p"
done
```
Use o `nmap` localmente quando disponível.<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>
```bash
nmap -sT -Pn -p- 127.0.0.1
nmap -sT -Pn --open 127.0.0.1
```
## Sub-redes veth e de Contêineres

Ambientes conteinerizados ou de laboratório frequentemente expõem serviços apenas em uma bridge ou sub-rede veth. Enumere as interfaces e as rotas antes de presumir que um serviço esteja inacessível.<sup>[[2]](#references)</sup>
```bash
ip -br addr
ip route
ip neigh
```
Encontre prováveis sub-redes locais.<sup>[[2]](#references)</sup>
```bash
ip -o -4 addr show | awk '{print $2, $4}'
```
Sonde cuidadosamente uma sub-rede descoberta.<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>
```bash
nmap -sT -Pn --open 172.17.0.0/24
nmap -sT -Pn -p 80,443,8000,8080,9000 172.17.0.0/24
```
A técnica é útil quando um painel web, endpoint de debug ou serviço auxiliar está oculto de scans externos, mas pode ser acessado a partir do host comprometido ou da rede do container.

## Pivot Local Com socat ou SSH

Se um serviço estiver vinculado ao loopback, exponha-o por meio de um canal permitido em vez de alterar o próprio serviço.

Encaminhe um serviço HTTP local com SSH.<sup>[[11]](#references)</sup>
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
Isso não explora nada por si só. Ele torna uma superfície acessível apenas localmente alcançável pelas suas ferramentas, para que você possa interagir com ela como um serviço normal.

## Banner Grabbing and Simple Protocols

Nem todo serviço é HTTP. Muitos serviços locais fazem leak de informações suficientes por meio de um banner ou de um protocolo de uma linha.

Probes básicos.<sup>[[13]](#references)</sup>
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

## Capturing Loopback Traffic

O tráfego local pode expor cabeçalhos, bearer tokens, credenciais de Basic Auth ou secrets específicos da aplicação.<sup>[[17]](#references)[[25]](#references)</sup> Capture somente em ambientes autorizados.

Capture tráfego HTTP de loopback.<sup>[[16]](#references)</sup>
```bash
sudo tcpdump -i lo -A -s0 'tcp port 80 or tcp port 8080'
```
Capture um serviço local específico.<sup>[[16]](#references)</sup>
```bash
sudo tcpdump -i lo -w /tmp/loopback.pcap 'tcp port 8080'
```
Decodifique a autenticação Basic de um header capturado ou registrado.<sup>[[17]](#references)[[18]](#references)</sup>
```bash
printf '%s' 'dXNlcjpwYXNz' | base64 -d
```
Strings úteis para procurar em capturas de texto:
```bash
grep -Ei 'Authorization:|Cookie:|Bearer|Basic|token|api[_-]?key|password' /tmp/capture.txt
```
## TLS Key Logging

Se você puder controlar o ambiente do processo cliente em um lab, `SSLKEYLOGFILE` pode tornar as sessões TLS descriptografáveis no Wireshark ou em ferramentas compatíveis.<sup>[[19]](#references)[[20]](#references)</sup> Isso é útil para entender o tráfego HTTPS local sem atacar o próprio TLS.

Execute um cliente com o key logging habilitado.<sup>[[19]](#references)[[20]](#references)</sup>
```bash
export SSLKEYLOGFILE=/tmp/sslkeys.log
curl -k https://127.0.0.1:8443/
ls -l /tmp/sslkeys.log
```
Capture o tráfego ao mesmo tempo.<sup>[[16]](#references)</sup>
```bash
sudo tcpdump -i lo -w /tmp/tls.pcap 'tcp port 8443'
```
Em seguida, carregue `/tmp/tls.pcap` e `/tmp/sslkeys.log` no Wireshark. Isso só funciona quando a biblioteca cliente oferece suporte ao key logging no estilo NSS e você pode definir o ambiente antes que a conexão seja estabelecida.<sup>[[20]](#references)[[21]](#references)</sup>

## Interação com Unix Sockets e Command Injection

Unix sockets são endpoints locais de IPC.<sup>[[5]](#references)</sup> Eles podem expor APIs HTTP, protocolos personalizados ou handlers de comandos inseguros.<sup>[[12]](#references)[[14]](#references)</sup>

Encontre os sockets.<sup>[[1]](#references)[[5]](#references)</sup>
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
Se a entrada de socket controlada pelo usuário for passada para um shell ou helper privilegiado, isso pode se tornar command injection.<sup>[[26]](#references)</sup> Para um exemplo focado, consulte [Socket Command Injection](socket-command-injection.md).

## Revisão do nftables e alterações autorizadas nas regras

As regras do firewall local podem explicar por que um serviço está visível localmente, mas bloqueado remotamente, ou por que uma porta alta parece inacessível a partir de uma interface.<sup>[[22]](#references)</sup>

Revise as regras.<sup>[[22]](#references)</sup>
```bash
sudo nft list ruleset
sudo nft list tables
sudo nft list chains
```
Procure por descartes que afetem uma porta de destino.<sup>[[22]](#references)</sup>
```bash
sudo nft list ruleset | grep -Ei 'drop|reject|dport|tcp|udp'
```
Em um laboratório autorizado, remova uma regra de bloqueio específica pelo handle.<sup>[[22]](#references)</sup>
```bash
sudo nft -a list chain inet filter input
sudo nft delete rule inet filter input handle <handle>
```
Prefira excluir o handle exato em vez de limpar tabelas inteiras. A técnica consiste em identificar o filtro preciso que está causando o comportamento e alterar apenas essa regra.<sup>[[22]](#references)</sup>

## Fluxo rápido
```bash
ss -lntup
ss -lnx
ip -br addr
ip route
nmap -sT -Pn --open 127.0.0.1
find /run /var/run /tmp -type s -ls 2>/dev/null
sudo nft list ruleset 2>/dev/null | head -n 80
```
Priorize serviços que sejam apenas locais, executados por um usuário com mais privilégios, exponham funções de administração/debug ou confiem em clientes de loopback/rede de containers.

## References

- [1] [ss(8) — página do manual do Linux](https://man7.org/linux/man-pages/man8/ss.8.html)
- [2] [ip(8) — página do manual do Linux](https://man7.org/linux/man-pages/man8/ip.8.html)
- [3] [ip(7) — página do manual do Linux](https://man7.org/linux/man-pages/man7/ip.7.html)
- [4] [RFC 4291: Arquitetura de endereçamento do IP versão 6](https://www.rfc-editor.org/info/rfc4291/)
- [5] [unix(7) — página do manual do Linux](https://man7.org/linux/man-pages/man7/unix.7.html)
- [6] [Redirecionamentos (Manual de Referência do Bash)](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
- [7] [invocação de timeout (GNU Coreutils)](https://www.gnu.org/s/coreutils/timeout)
- [8] [Técnicas de Port Scanning (Guia de Referência do Nmap)](https://nmap.org/book/man-port-scanning-techniques.html)
- [9] [Descoberta de Hosts (Guia de Referência do Nmap)](https://nmap.org/book/man-host-discovery.html)
- [10] [Especificação de Portas e Ordem de Scanning (Guia de Referência do Nmap)](https://nmap.org/book/man-port-specification.html)
- [11] [ssh(1) — página do manual do Linux](https://man7.org/linux/man-pages/man1/ssh.1.html)
- [12] [socat(1) — página do manual do Linux](https://www.man7.org/linux/man-pages/man1/socat.1.html)
- [13] [nc(1) — página do manual do OpenBSD](https://man.openbsd.org/nc.1)
- [14] [manual da ferramenta de linha de comando curl](https://curl.se/docs/manpage.html?category=23)
- [15] [openssl-s_client — documentação do OpenSSL](https://docs.openssl.org/3.0/man1/openssl-s_client/)
- [16] [tcpdump(8) — página do manual do Linux](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
- [17] [RFC 7617: O esquema de autenticação HTTP 'Basic'](https://www.rfc-editor.org/rfc/rfc7617.html)
- [18] [invocação de base64 (GNU Coreutils)](https://www.gnu.org/software/coreutils/manual/html_node/base64-invocation.html)
- [19] [openssl-env — documentação do OpenSSL](https://docs.openssl.org/master/man7/openssl-env/)
- [20] [TLS — Wiki do Wireshark](https://wiki.wireshark.org/tls)
- [21] [Guia do Usuário do Wireshark](https://www.wireshark.org/docs/wsug_html/)
- [22] [manual do nftables](https://netfilter.org/projects/nftables/manpage.html)
- [23] [Alocação de Endereços para Internets Privadas (RFC 1918)](https://www.rfc-editor.org/rfc/rfc1918.html)
- [24] [ip-link(8) — página do manual do Linux](https://man7.org/linux/man-pages/man8/ip-link.8.html)
- [25] [O Framework de Autorização OAuth 2.0: Uso de Bearer Tokens (RFC 6750)](https://www.rfc-editor.org/rfc/rfc6750.html)
- [26] [CWE-78: Neutralização inadequada de elementos especiais usados em um comando do SO](https://cwe.mitre.org/data/definitions/78.html)
{{#include ../../banners/hacktricks-training.md}}
