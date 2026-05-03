# Wireshark tricks

{{#include ../../../banners/hacktricks-training.md}}

## Melhore suas habilidades em Wireshark

### Tutorials

Os seguintes tutorials são incríveis para aprender alguns truques básicos legais:

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Analysed Information

**Expert Information**

Clicando em _**Analyze** --> **Expert Information**_ você terá uma **visão geral** do que está acontecendo nos pacotes **analisados**:

![](<../../../images/image (256).png>)

**Resolved Addresses**

Em _**Statistics --> Resolved Addresses**_ você pode encontrar várias **informações** que foram "**resolvidas**" pelo wireshark, como porta/transporte para protocolo, MAC para o fabricante, etc. É interessante saber o que está envolvido na comunicação.

![](<../../../images/image (893).png>)

**Protocol Hierarchy**

Em _**Statistics --> Protocol Hierarchy**_ você pode encontrar os **protocolos** **envolvidos** na comunicação e dados sobre eles.

![](<../../../images/image (586).png>)

**Conversations**

Em _**Statistics --> Conversations**_ você pode encontrar um **resumo das conversas** na comunicação e dados sobre elas.

![](<../../../images/image (453).png>)

**Endpoints**

Em _**Statistics --> Endpoints**_ você pode encontrar um **resumo dos endpoints** na comunicação e dados sobre cada um deles.

![](<../../../images/image (896).png>)

**DNS info**

Em _**Statistics --> DNS**_ você pode encontrar estatísticas sobre a requisição DNS capturada.

![](<../../../images/image (1063).png>)

**I/O Graph**

Em _**Statistics --> I/O Graph**_ você pode encontrar um **gráfico da comunicação.**

![](<../../../images/image (992).png>)

### Filters

Aqui você pode encontrar filtros do wireshark dependendo do protocolo: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
Na versão atual do Wireshark use `tls.*` em vez dos antigos nomes de filtro `ssl.*`.\
Outros filtros interessantes:

- `(http.request or tls.handshake.type == 1) and !(udp.port eq 1900)`
- HTTP and initial HTTPS traffic
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
- HTTP and initial HTTPS traffic + TCP SYN
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
- HTTP and initial HTTPS traffic + TCP SYN + DNS requests
- `tls.handshake.extensions_server_name contains "example.com"`
- Pivot on the SNI sent in the ClientHello even when you cannot decrypt the payload
- `tls.handshake.extensions_alpn_str == "h2" or tls.handshake.extensions_alpn_str == "h3"`
- Split classic HTTPS, HTTP/2 and HTTP/3 capable sessions quickly
- `quic or http3`
- Find modern UDP/443 traffic that will be missed if you only review TCP conversations

### Search

Se você quiser **buscar** por **conteúdo** dentro dos **pacotes** das sessões, pressione _CTRL+f_. Você pode adicionar novas camadas à barra principal de informações (No., Time, Source, etc.) pressionando o botão direito e depois edit column.

### Following multiplexed streams

Versões recentes do Wireshark conseguem seguir streams `TLS`, `HTTP/2` e `QUIC` diretamente. Em capturas ruidosas isso normalmente é mais rápido do que usar apenas `Follow TCP Stream`, especialmente quando várias requisições compartilham a mesma conexão.

### Free pcap labs

**Pratique com os desafios gratuitos de:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Identifying Domains

Você pode adicionar uma coluna que mostra o cabeçalho Host HTTP:

![](<../../../images/image (639).png>)

E uma coluna que adiciona o Server name de uma conexão HTTPS inicial (**tls.handshake.type == 1**):

![](<../../../images/image (408) (1).png>)

Se a captura estiver majoritariamente criptografada, adicionar esses campos como colunas vai acelerar muito a triagem:

- `tls.handshake.extensions_server_name`
- `tls.handshake.extensions_alpn_str`
- `tls.handshake.ja3`
- `tls.handshake.ja4` (Wireshark 4.2+)

Isso permite agrupar sessões por hostname, ALPN (`http/1.1`, `h2`, `h3`, etc.) e fingerprint do cliente mesmo quando o payload em si permanece criptografado. Para capturas HTTP/2 e HTTP/3 descriptografadas, também é útil adicionar `http2.header.value` ou `http3.headers.header.value` como colunas e pivotar em paths, authorities e outros metadados interessantes.
```bash
tshark -r capture.pcapng -Y "tls.handshake.type == 1" -T fields \
-e frame.number -e ip.src -e ip.dst \
-e tls.handshake.extensions_server_name \
-e tls.handshake.extensions_alpn_str \
-e tls.handshake.ja3 -e tls.handshake.ja4
```
## Identifying local hostnames

### From DHCP

No Wireshark atual, em vez de `bootp` você precisa procurar por `DHCP`

![](<../../../images/image (1013).png>)

### From NBNS

![](<../../../images/image (1003).png>)

## Decrypting TLS

### Decrypting https traffic with server private key

_edit > preferences > protocols > tls >_

![](<../../../images/image (1103).png>)

Press _Edit_ e adicione todos os dados do servidor e da private key (_IP, Port, Protocol, Key file e password_)

Este método só funciona em um número limitado de casos. Para tráfego atual TLS 1.3 / ECDHE, o método de session key log abaixo geralmente é a opção prática.

### Decrypting https traffic with symmetric session keys

Tanto Firefox quanto Chrome têm a capacidade de registrar TLS session keys, que podem ser usadas com Wireshark para decrypt TLS traffic. Isso permite uma análise aprofundada das secure communications. Mais detalhes sobre como realizar esse decrypt podem ser encontrados em um guia no [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/). Este também é o caminho normal para decrypting capturas modernas de TLS 1.3 e QUIC/HTTP/3.

Para detectar isso, procure no ambiente pela variável `SSLKEYLOGFILE`

Um arquivo de shared keys ficará assim:

![](<../../../images/image (820).png>)

Se a captura for `pcapng`, verifique se ela já contém embedded decryption secrets antes de vasculhar o filesystem do host:
```bash
editcap --extract-secrets capture.pcapng tls-secrets.txt
```
Para importar isso no wireshark vá para \_edit > preferences > protocols > tls > e importe em (Pre)-Master-Secret log filename:

![](<../../../images/image (989).png>)

## Comunicação ADB

Extraia um APK de uma comunicação ADB onde o APK foi enviado:
```python
from scapy.all import *

pcap = rdpcap("final2.pcapng")

def rm_data(data):
splitted = data.split(b"DATA")
if len(splitted) == 1:
return data
else:
return splitted[0]+splitted[1][4:]

all_bytes = b""
for pkt in pcap:
if Raw in pkt:
a = pkt[Raw]
if b"WRTE" == bytes(a)[:4]:
all_bytes += rm_data(bytes(a)[24:])
else:
all_bytes += rm_data(bytes(a))
print(all_bytes)

f = open('all_bytes.data', 'w+b')
f.write(all_bytes)
f.close()
```
## Referências

- [Wireshark TLS wiki](https://wiki.wireshark.org/TLS)
- [Decrypting and parsing HTTP/3 traffic in Wireshark](https://blog.elmo.sg/posts/parsing-decrypted-quic-traffic-in-wireshark/)

{{#include ../../../banners/hacktricks-training.md}}
