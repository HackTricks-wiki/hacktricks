# Truques do Wireshark

{{#include ../../../banners/hacktricks-training.md}}

## Aprimore suas habilidades com o Wireshark

### Tutoriais

Os tutoriais a seguir são excelentes para aprender alguns truques básicos:

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Informações analisadas

**Expert Information**

Ao clicar em _**Analyze** --> **Expert Information**_, você terá uma **visão geral** do que está acontecendo nos pacotes **analisados**:

![Tutoriais - Informações analisadas: ao clicar em Analyze -- Expert Information, você terá uma visão geral do que está acontecendo nos pacotes analisados](<../../../images/image (256).png>)

**Resolved Addresses**

Em _**Statistics --> Resolved Addresses**_, você pode encontrar várias **informações** que foram "**resolvidas**" pelo Wireshark, como porta/transporte para protocolo, MAC para o fabricante etc. É interessante saber o que está envolvido na comunicação.

![Tutoriais - Informações analisadas: em Statistics -- Resolved Addresses, você pode encontrar várias informações que foram " resolvidas " pelo Wireshark, como porta/transporte para protocolo, MAC para o fabricante etc.](<../../../images/image (893).png>)

**Protocol Hierarchy**

Em _**Statistics --> Protocol Hierarchy**_, você pode encontrar os **protocolos** **envolvidos** na comunicação e dados sobre eles.

![Tutoriais - Informações analisadas: em Statistics -- Protocol Hierarchy, você pode encontrar os protocolos envolvidos na comunicação e dados sobre eles](<../../../images/image (586).png>)

**Conversations**

Em _**Statistics --> Conversations**_, você pode encontrar um **resumo das conversas** na comunicação e dados sobre elas.

![Tutoriais - Informações analisadas: em Statistics -- Conversations, você pode encontrar um resumo das conversas na comunicação e dados sobre elas](<../../../images/image (453).png>)

**Endpoints**

Em _**Statistics --> Endpoints**_, você pode encontrar um **resumo dos endpoints** na comunicação e dados sobre cada um deles.

![Tutoriais - Informações analisadas: em Statistics -- Endpoints, você pode encontrar um resumo dos endpoints na comunicação e dados sobre cada um deles](<../../../images/image (896).png>)

**DNS info**

Em _**Statistics --> DNS**_, você pode encontrar estatísticas sobre a solicitação DNS capturada.

![Tutoriais - Informações analisadas: em Statistics -- DNS, você pode encontrar estatísticas sobre a solicitação DNS capturada](<../../../images/image (1063).png>)

**I/O Graph**

Em _**Statistics --> I/O Graph**_, você pode encontrar um **gráfico da comunicação.**

![Tutoriais - Informações analisadas: em Statistics -- I/O Graph, você pode encontrar um gráfico da comunicação](<../../../images/image (992).png>)

### Filtros

Aqui você pode encontrar filtros do Wireshark dependendo do protocolo: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
Nas versões atuais do Wireshark, use `tls.*` em vez dos nomes antigos de filtros `ssl.*`.\
Outros filtros interessantes:

- `(http.request or tls.handshake.type == 1) and !(udp.port eq 1900)`
- Tráfego HTTP e HTTPS inicial
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
- Tráfego HTTP e HTTPS inicial + TCP SYN
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
- Tráfego HTTP e HTTPS inicial + TCP SYN + solicitações DNS
- `tls.handshake.extensions_server_name contains "example.com"`
- Fazer pivot com base no SNI enviado no ClientHello mesmo quando você não pode descriptografar o payload
- `tls.handshake.extensions_alpn_str == "h2" or tls.handshake.extensions_alpn_str == "h3"`
- Separar rapidamente sessões compatíveis com HTTPS clássico, HTTP/2 e HTTP/3
- `quic or http3`
- Encontrar tráfego UDP/443 moderno que não será identificado se você revisar apenas as conversas TCP

### Pesquisa

Se quiser **pesquisar** **conteúdo** dentro dos **pacotes** das sessões, pressione _CTRL+f_. Você pode adicionar novas camadas à barra principal de informações (No., Time, Source etc.) pressionando o botão direito e, em seguida, editando a coluna.

### Seguindo streams multiplexados

As versões recentes do Wireshark podem seguir streams `TLS`, `HTTP/2` e `QUIC` diretamente. Em capturas ruidosas, isso geralmente é mais rápido do que usar apenas `Follow TCP Stream`, especialmente quando várias solicitações compartilham a mesma conexão.

### Labs gratuitos de pcap

**Pratique com os desafios gratuitos de:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Identificando Domínios

Você pode adicionar uma coluna que mostre o cabeçalho HTTP Host:

![Labs gratuitos de pcap - Identificando Domínios: você pode adicionar uma coluna que mostre o cabeçalho HTTP Host](<../../../images/image (639).png>)

E uma coluna que adicione o nome do Server de uma conexão HTTPS inicial (**tls.handshake.type == 1**):

![Labs gratuitos de pcap - Identificando Domínios: e uma coluna que adicione o nome do Server de uma conexão HTTPS inicial ( tls.handshake.type == 1 )](<../../../images/image (408) (1).png>)

Se a captura estiver principalmente criptografada, adicionar estes campos como colunas acelerará bastante a triagem:

- `tls.handshake.extensions_server_name`
- `tls.handshake.extensions_alpn_str`
- `tls.handshake.ja3`
- `tls.handshake.ja4` (Wireshark 4.2+)

Isso permite agrupar sessões por hostname, ALPN (`http/1.1`, `h2`, `h3` etc.) e fingerprint do cliente, mesmo quando o próprio payload permanece criptografado. Para capturas HTTP/2 e HTTP/3 descriptografadas, também é útil adicionar `http2.header.value` ou `http3.headers.header.value` como colunas e fazer pivot com base em paths, authorities e outros metadados interessantes.<sup>[[2]](#references)</sup>
```bash
tshark -r capture.pcapng -Y "tls.handshake.type == 1" -T fields \
-e frame.number -e ip.src -e ip.dst \
-e tls.handshake.extensions_server_name \
-e tls.handshake.extensions_alpn_str \
-e tls.handshake.ja3 -e tls.handshake.ja4
```
## Identificando hostnames locais

### De DHCP

No Wireshark atual, em vez de `bootp`, você precisa pesquisar por `DHCP`

![Identificando hostnames locais - De DHCP: No Wireshark atual, em vez de bootp, você precisa pesquisar por DHCP](<../../../images/image (1013).png>)

### De NBNS

![De DHCP - De NBNS: No Wireshark atual, em vez de bootp, você precisa pesquisar por DHCP](<../../../images/image (1003).png>)

## Descriptografando TLS

### Descriptografando tráfego https com a chave privada do servidor

_editar > preferências > protocolos > tls >_

![Descriptografando TLS - Descriptografando tráfego https com a chave privada do servidor: Descriptografando tráfego https com a chave privada do servidor](<../../../images/image (1103).png>)

Pressione _Editar_ e adicione todos os dados do servidor e da chave privada (_IP, Porta, Protocolo, Arquivo da chave e senha_)

Este método funciona apenas em um número limitado de casos. Para o tráfego TLS 1.3 / ECDHE atual, o método de registro da chave da sessão abaixo geralmente é a opção prática.<sup>[[1]](#references)</sup>

### Descriptografando tráfego https com chaves de sessão simétricas

Firefox e Chrome têm a capacidade de registrar chaves de sessão TLS, que podem ser usadas com o Wireshark para descriptografar o tráfego TLS. Isso permite uma análise detalhada de comunicações seguras. Mais detalhes sobre como realizar essa descriptografia podem ser encontrados em um guia da [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/).<sup>[[3]](#references)</sup> Essa também é a forma normal de descriptografar capturas modernas de TLS 1.3 e QUIC/HTTP/3.<sup>[[2]](#references)</sup>

Para detectar isso, pesquise no ambiente pela variável `SSLKEYLOGFILE`

Um arquivo de chaves compartilhadas terá esta aparência:

![Descriptografando tráfego https com a chave privada do servidor - Descriptografando tráfego https com chaves de sessão simétricas: Um arquivo de chaves compartilhadas terá esta aparência](<../../../images/image (820).png>)

Se a captura for `pcapng`, verifique se ela já contém secrets de descriptografia incorporados antes de procurar no sistema de arquivos do host:<sup>[[1]](#references)</sup>
```bash
editcap --extract-secrets capture.pcapng tls-secrets.txt
```
Para importar isso no Wireshark, acesse \_edit > preferences > protocols > tls > e importe-o em (Pre)-Master-Secret log filename:

![Decrypting https traffic with server private key - Decrypting https traffic with symmetric session keys: editcap --extract-secrets capture.pcapng tls-secrets.txt](<../../../images/image (989).png>)

## Comunicação ADB

Extraia um APK de uma comunicação ADB na qual o APK foi enviado:
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

- [1] [wiki de TLS do Wireshark](https://wiki.wireshark.org/TLS)
- [2] [Descriptografando e analisando tráfego HTTP/3 no Wireshark](https://blog.elmo.sg/posts/parsing-decrypted-quic-traffic-in-wireshark/)
- [3] [Descriptografando tráfego TLS do navegador com o Wireshark – o jeito fácil!](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/)

{{#include ../../../banners/hacktricks-training.md}}
