# Triagem de Rede Local e Sockets

{{#include ../../banners/hacktricks-training.md}}

Após obter um shell em um host Linux, os alvos de rede mais úteis geralmente não estão expostos externamente. Serviços disponíveis apenas via loopback, redes veth, sockets Unix, listeners temporários, capturas de pacotes e regras de firewall locais podem expor credenciais ou superfícies de ataque acessíveis somente localmente.

Esta página concentra-se em técnicas práticas de post-exploitation local, não em pentesting geral de redes remotas.

## Enumeração de Loopback e Serviços Locais

Comece identificando os serviços em modo listening, seus endereços de bind e o processo proprietário, quando as permissões permitirem:
```bash
ss -lntup
ss -lnx
ip addr
ip route
```
Padrões importantes:

- `127.0.0.1:<port>` ou `[::1]:<port>`: acessíveis somente a partir do host por padrão.
- `0.0.0.0:<port>`: acessível em todas as interfaces IPv4, a menos que seja filtrado.
- `172.x`, `10.x` ou `192.168.x` em `veth*`, `docker*`, `br-*`, `cni*`: provavelmente redes de containers ou laboratórios locais.
- Unix sockets em `/run`, `/var/run`, `/tmp` ou diretórios de aplicações: superfícies locais de IPC.

Mapeie as portas locais com sondas leves:
```bash
for p in 80 443 8000 8080 8081 9000 5000; do
timeout 1 bash -c "echo >/dev/tcp/127.0.0.1/$p" 2>/dev/null && echo "open: $p"
done
```
Use o `nmap` localmente quando disponível:
```bash
nmap -sT -Pn -p- 127.0.0.1
nmap -sT -Pn --open 127.0.0.1
```
## veth Ocultos e Sub-redes de Containers

Ambientes conteinerizados ou de laboratório frequentemente expõem serviços apenas em uma bridge ou sub-rede veth. Enumere as interfaces e as rotas antes de presumir que um serviço está inacessível:
```bash
ip -br addr
ip route
ip neigh
```
Encontre as prováveis sub-redes locais:
```bash
ip -o -4 addr show | awk '{print $2, $4}'
```
Sonde cuidadosamente uma sub-rede descoberta:
```bash
nmap -sT -Pn --open 172.17.0.0/24
nmap -sT -Pn -p 80,443,8000,8080,9000 172.17.0.0/24
```
A técnica é útil quando um painel web, um endpoint de debug ou um serviço auxiliar está oculto para varreduras externas, mas pode ser acessado a partir do host comprometido ou da rede do container.

## Pivot local com socat ou SSH

Se um serviço estiver vinculado ao loopback, exponha-o por meio de um canal permitido em vez de alterar o próprio serviço.

Encaminhe um serviço HTTP acessível apenas localmente com SSH:
```bash
ssh -L 8080:127.0.0.1:8080 user@target
```
Faça a ponte de uma porta local com `socat` quando você já tiver acesso ao shell:
```bash
socat TCP-LISTEN:18080,fork,reuseaddr TCP:127.0.0.1:8080
```
Encaminhe um socket Unix para TCP para testes locais:
```bash
socat TCP-LISTEN:18081,fork,reuseaddr UNIX-CONNECT:/run/app/app.sock
```
Isso não explora nada por si só. Ele torna uma superfície disponível apenas localmente acessível às suas ferramentas, para que você possa interagir com ela como um serviço normal.

## Banner Grabbing e Protocolos Simples

Nem todo serviço é HTTP. Muitos serviços locais fazem leak de informações suficientes por meio de um banner ou de um protocolo de uma linha.

Probes básicos:
```bash
nc -nv 127.0.0.1 9000
printf 'help\n' | nc -nv 127.0.0.1 9000
printf 'version\n' | nc -nv 127.0.0.1 9000
```
Verificação HTTP sem um navegador:
```bash
printf 'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' | nc -nv 127.0.0.1 8080
curl -i http://127.0.0.1:8080/
```
Para TLS:
```bash
openssl s_client -connect 127.0.0.1:8443 -servername localhost
curl -k -i https://127.0.0.1:8443/
```
O objetivo é identificar o protocolo, o esquema de autenticação, a versão e se o serviço confia em clientes locais.

## Capturando tráfego de Loopback

O tráfego local pode expor cabeçalhos, bearer tokens, credenciais de Basic Auth ou secrets específicos da aplicação. Capture somente em ambientes autorizados.

Capture tráfego HTTP de loopback:
```bash
sudo tcpdump -i lo -A -s0 'tcp port 80 or tcp port 8080'
```
Capturar um serviço local específico:
```bash
sudo tcpdump -i lo -w /tmp/loopback.pcap 'tcp port 8080'
```
Decodifique o Basic Auth de um header capturado ou registrado:
```bash
printf '%s' 'dXNlcjpwYXNz' | base64 -d
```
Strings úteis para procurar em capturas de texto:
```bash
grep -Ei 'Authorization:|Cookie:|Bearer|Basic|token|api[_-]?key|password' /tmp/capture.txt
```
## TLS Key Logging

Se você puder controlar o ambiente do processo cliente em um laboratório, `SSLKEYLOGFILE` poderá tornar as sessões TLS descriptografáveis no Wireshark ou em ferramentas compatíveis. Isso é útil para entender o tráfego HTTPS local sem atacar o próprio TLS.

Execute um cliente com o registro de chaves habilitado:
```bash
export SSLKEYLOGFILE=/tmp/sslkeys.log
curl -k https://127.0.0.1:8443/
ls -l /tmp/sslkeys.log
```
Capture o tráfego ao mesmo tempo:
```bash
sudo tcpdump -i lo -w /tmp/tls.pcap 'tcp port 8443'
```
Em seguida, carregue `/tmp/tls.pcap` e `/tmp/sslkeys.log` no Wireshark. Isso só funciona quando a biblioteca cliente oferece suporte ao key logging no estilo NSS e quando você pode definir o ambiente antes que a conexão seja estabelecida.

## Unix Socket Interaction and Command Injection

Unix sockets são endpoints locais de IPC. Eles podem expor APIs HTTP, protocolos personalizados ou manipuladores de comandos inseguros.

Encontre sockets:
```bash
ss -lnx
find /run /var/run /tmp -type s -ls 2>/dev/null
```
Interagir com HTTP por meio de um socket Unix:
```bash
curl --unix-socket /run/app/app.sock http://localhost/
curl --unix-socket /run/app/app.sock -i http://localhost/admin
```
Interaja com um raw socket:
```bash
printf 'status\n' | socat - UNIX-CONNECT:/run/app/app.sock
printf 'help\n' | nc -U /run/app/app.sock
```
Se a entrada de socket controlada pelo usuário for passada a um shell ou a um helper privilegiado, ela poderá resultar em command injection. Para um exemplo específico, consulte [Socket Command Injection](socket-command-injection.md).

## Revisão do nftables e Alterações Autorizadas nas Regras

As regras do firewall local podem explicar por que um serviço está visível localmente, mas bloqueado remotamente, ou por que uma porta alta parece inacessível a partir de uma interface.

Revise as regras:
```bash
sudo nft list ruleset
sudo nft list tables
sudo nft list chains
```
Procure por drops que afetem uma porta de destino:
```bash
sudo nft list ruleset | grep -Ei 'drop|reject|dport|tcp|udp'
```
Em um laboratório autorizado, remova uma regra de bloqueio específica pelo handle:
```bash
sudo nft -a list chain inet filter input
sudo nft delete rule inet filter input handle <handle>
```
Prefira excluir o handle exato em vez de limpar tabelas inteiras. A técnica consiste em identificar o filtro preciso que está causando o comportamento e alterar apenas essa regra.

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
Priorize serviços apenas locais, executados por um usuário mais privilegiado, que exponham funções de administração/depuração ou confiem em clientes de loopback/rede de contêineres.
