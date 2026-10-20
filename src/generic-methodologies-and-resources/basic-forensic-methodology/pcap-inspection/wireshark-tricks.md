# Truques do Wireshark

{{#include ../../../banners/hacktricks-training.md}}

## Aprimore suas habilidades com o Wireshark

### Tutoriais

Os tutoriais a seguir são ótimos para aprender alguns truques básicos:

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Informações analisadas

**Informações para especialistas**

Ao clicar em _**Analyze** --> **Expert Information**_, você terá uma **visão geral** do que está acontecendo nos pacotes **analisados**:

![Tutoriais - Informações analisadas: ao clicar em Analyze -- Expert Information, você terá uma visão geral do que está acontecendo nos pacotes analisados](<../../../images/image (256).png>)

**Endereços resolvidos**

Em _**Statistics --> Resolved Addresses**_, você encontra várias **informações** que foram "**resolvidas**" pelo Wireshark, como porta/transporte para protocolo, MAC para fabricante etc. É interessante saber o que está envolvido na comunicação.

![Tutoriais - Informações analisadas: em Statistics -- Resolved Addresses, você encontra várias informações que foram " resolvidas " pelo Wireshark, como porta/transporte para protocolo, MAC para...](<../../../images/image (893).png>)

**Hierarquia de protocolos**

Em _**Statistics --> Protocol Hierarchy**_, você encontra os **protocolos** **envolvidos** na comunicação e dados sobre eles.

![Tutoriais - Informações analisadas: em Statistics -- Protocol Hierarchy, você encontra os protocolos envolvidos na comunicação e dados sobre eles](<../../../images/image (586).png>)

**Conversas**

Em _**Statistics --> Conversations**_, você encontra um **resumo das conversas** na comunicação e dados sobre elas.

![Tutoriais - Informações analisadas: em Statistics -- Conversations, você encontra um resumo das conversas na comunicação e dados sobre elas](<../../../images/image (453).png>)

**Endpoints**

Em _**Statistics --> Endpoints**_, você encontra um **resumo dos endpoints** na comunicação e dados sobre cada um deles.

![Tutoriais - Informações analisadas: em Statistics -- Endpoints, você encontra um resumo dos endpoints na comunicação e dados sobre cada um deles](<../../../images/image (896).png>)

**Informações de DNS**

Em _**Statistics --> DNS**_, você encontra estatísticas sobre as solicitações DNS capturadas.

![Tutoriais - Informações analisadas: em Statistics -- DNS, você encontra estatísticas sobre as solicitações DNS capturadas](<../../../images/image (1063).png>)

**Gráfico de I/O**

Em _**Statistics --> I/O Graph**_, você encontra um **gráfico da comunicação.**

![Tutoriais - Informações analisadas: em Statistics -- I/O Graph, você encontra um gráfico da comunicação](<../../../images/image (992).png>)

### Filtros

Aqui você encontra filtros do Wireshark organizados por protocolo: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
Nas versões atuais do Wireshark, use `tls.*` em vez dos nomes antigos de filtros `ssl.*`.<sup>[[1]](#references)</sup>\
Outros filtros interessantes:

- `(http.request or tls.handshake.type == 1) and !(udp.port eq 1900)`
  - Tráfego HTTP e HTTPS inicial
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
  - Tráfego HTTP e HTTPS inicial + TCP SYN
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
  - Tráfego HTTP e HTTPS inicial + TCP SYN + solicitações DNS
- `tls.handshake.extensions_server_name contains "example.com"`
  - Use o SNI enviado no ClientHello como ponto de partida, mesmo quando não for possível descriptografar o payload
- `tls.handshake.extensions_alpn_str == "h2" or tls.handshake.extensions_alpn_str == "h3"`
  - Separe rapidamente sessões HTTPS clássico, HTTP/2 e compatíveis com HTTP/3
- `quic or http3`
  - Encontre tráfego moderno UDP/443 que não será detectado se você analisar apenas conversas TCP

### Pesquisa

Para **pesquisar** **conteúdo** nos **pacotes** das sessões, pressione _CTRL+f_. Você pode adicionar novas colunas à barra principal de informações (No., Time, Source etc.) clicando com o botão direito e, em seguida, selecionando a edição de colunas.

### Acompanhar fluxos multiplexados

O Wireshark pode acompanhar diretamente fluxos `TLS`, `HTTP/2` e `QUIC`. As janelas de HTTP/2 e QUIC mostram seletores de conexão e subfluxo, ajudando a isolar fluxos multiplexados que compartilham a mesma conexão de nível inferior.<sup>[[4]](#references)</sup>

Com as chaves de sessão disponíveis, primeiro identifique o ID do fluxo da solicitação e, em seguida, acompanhe esse subfluxo em vez de toda a conversa TCP ou UDP. O exemplo `0,1` seleciona o ID de fluxo HTTP/2 1 no fluxo TCP 0; para QUIC, use `follow,quic,utf-8,<connection-number>,<stream-id>`. Acompanhar apenas uma tupla de cinco elementos pode misturar solicitações independentes ou fazer com que uma conexão QUIC após uma migração não seja detectada.<sup>[[6]](#references)[[7]](#references)[[9]](#references)</sup>

```bash
tshark -r capture.pcapng -o tls.keylog_file:keys.log \
  -Y 'http2.headers.authority || http3.headers.authority' -T fields \
  -e tcp.stream -e http2.streamid -e quic.connection.number \
  -e quic.stream.stream_id -e http2.headers.authority \
  -e http3.headers.authority
tshark -r capture.pcapng -o tls.keylog_file:keys.log \
  -q -z 'follow,http2,utf-8,0,1'
```

### Laboratórios gratuitos de pcap

**Pratique com os desafios gratuitos de:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Identificando domínios

Você pode adicionar uma coluna que mostra o cabeçalho HTTP Host:

![Laboratórios gratuitos de pcap - Identificando domínios: Você pode adicionar uma coluna que mostra o cabeçalho HTTP Host](<../../../images/image (639).png>)

E uma coluna que adiciona o nome do servidor de uma conexão HTTPS iniciadora (**tls.handshake.type == 1**):

![Laboratórios gratuitos de pcap - Identificando domínios: E uma coluna que adiciona o nome do servidor de uma conexão HTTPS iniciadora ( tls.handshake.type == 1 )](<../../../images/image (408) (1).png>)

Se a captura estiver majoritariamente criptografada, adicionar estes campos como colunas agilizará muito a triagem:

- `tls.handshake.extensions_server_name`
- `tls.handshake.extensions_alpn_str`
- `tls.handshake.ja3`
- `tls.handshake.ja4` (Wireshark 4.2+)

Isso permite agrupar sessões por nome de host, ALPN (`http/1.1`, `h2`, `h3` etc.) e fingerprint do cliente, mesmo quando o payload permanece criptografado. Para capturas de HTTP/2 e HTTP/3 descriptografadas, também é útil adicionar `http2.header.value` ou `http3.headers.header.value` como colunas e analisar caminhos, autoridades e outros metadados interessantes.<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

```bash
tshark -r capture.pcapng -Y "tls.handshake.type == 1" -T fields \
  -e frame.number -e ip.src -e ip.dst \
  -e tls.handshake.extensions_server_name \
  -e tls.handshake.extensions_alpn_str \
  -e tls.handshake.ja3 -e tls.handshake.ja4
```

### ECH: não confunda o SNI externo com a origem

O Encrypted ClientHello (ECH) pode colocar um nome público de cobertura no SNI externo visível enquanto criptografa o nome interno. Portanto, um inventário de domínios baseado apenas em SNI pode atribuir o tráfego ECH à origem errada. A extensão ECH, por si só, não prova que o ECH foi bem-sucedido: os clientes podem enviar uma extensão GREASE ECH. No Wireshark 4.2+, encontre ofertas ECH externas com o filtro a seguir e trate o SNI informado como um possível nome de cobertura, não como o site solicitado.<sup>[[5]](#references)[[8]](#references)</sup>

```bash
tshark -r capture.pcapng \
  -Y 'tls.handshake.type == 1 && tls.ech.client_hello_type == 0' \
  -T fields -e frame.number -e ip.dst \
  -e tls.handshake.extensions_server_name -e tls.ech.config_id
```

Se você tiver as chaves de sessão correspondentes do cliente, inspecione a autoridade/Host HTTP descriptografada em vez de inferir a origem pelo SNI externo. Sem as chaves, verifique outras evidências de origem capturadas, como DNS em texto claro, mas não equipare o SNI externo ao nome oculto.<sup>[[1]](#references)[[6]](#references)[[7]](#references)[[8]](#references)</sup>

```bash
tshark -r capture.pcapng -o tls.keylog_file:keys.log \
  -Y 'http.host || http2.headers.authority || http3.headers.authority' \
  -T fields -e ip.dst -e http.host \
  -e http2.headers.authority -e http3.headers.authority
```

## Identificação de nomes de host locais

### Via DHCP

Nas versões atuais do Wireshark, em vez de `bootp`, você precisa pesquisar por `DHCP`

![Identificação de nomes de host locais - Via DHCP: Nas versões atuais do Wireshark, em vez de bootp, você precisa pesquisar por DHCP](<../../../images/image (1013).png>)

### Via NBNS

![Via DHCP - Via NBNS: Nas versões atuais do Wireshark, em vez de bootp, você precisa pesquisar por DHCP](<../../../images/image (1003).png>)

## Descriptografando TLS

A descriptografia da camada de enlace Wi-Fi é separada da descriptografia de sessões TLS; consulte [Análise de PCAP de Wi-Fi](wifi-pcap-analysis.md) para ver os pré-requisitos de chave e handshake.

### Descriptografando tráfego https com a chave privada do servidor

_editar > preferências > protocolos > tls >_

![Descriptografando TLS - Descriptografando tráfego https com a chave privada do servidor: Descriptografando tráfego https com a chave privada do servidor](<../../../images/image (1103).png>)

Pressione _Editar_ e adicione todos os dados do servidor e da chave privada (_IP, porta, protocolo, arquivo da chave e senha_).

Esse método funciona apenas em um número limitado de casos. Para tráfego TLS 1.3 / ECDHE atual, o método de registro de chaves de sessão abaixo geralmente é a opção mais prática.<sup>[[1]](#references)</sup>

### Descriptografando tráfego https com chaves de sessão simétricas

Tanto o Firefox quanto o Chrome podem registrar chaves de sessão TLS, que podem ser usadas com o Wireshark para descriptografar o tráfego TLS. Isso permite uma análise detalhada das comunicações seguras. Mais detalhes sobre como realizar essa descriptografia estão disponíveis neste guia da [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/).<sup>[[3]](#references)</sup> Essa também é a forma habitual de descriptografar capturas modernas de TLS 1.3 e QUIC/HTTP/3.<sup>[[2]](#references)</sup>

Para detectar isso, pesquise a variável `SSLKEYLOGFILE` no ambiente.

Um arquivo de chaves compartilhadas será semelhante a este:

![Descriptografando tráfego https com a chave privada do servidor - Descriptografando tráfego https com chaves de sessão simétricas: Um arquivo de chaves compartilhadas será semelhante a este](<../../../images/image (820).png>)

Se a captura estiver no formato `pcapng`, verifique se ela já contém segredos de descriptografia incorporados antes de procurar no sistema de arquivos do host:<sup>[[1]](#references)</sup>

```bash
editcap --extract-secrets capture.pcapng tls-secrets.txt
```

Para importar isso no Wireshark, vá para \_editar > preferências > protocolos > tls > e importe-o em Pre-(Master)-Secret log filename:

![Descriptografando tráfego https com a chave privada do servidor - Descriptografando tráfego https com chaves de sessão simétricas: editcap --extract-secrets capture.pcapng tls-secrets.txt](<../../../images/image (989).png>)

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

## References

- [1] [Wiki TLS do Wireshark](https://wiki.wireshark.org/TLS)
- [2] [Descriptografando e analisando tráfego HTTP/3 no Wireshark](https://blog.elmo.sg/posts/parsing-decrypted-quic-traffic-in-wireshark/)
- [3] [Descriptografando o tráfego TLS do navegador com o Wireshark — do jeito fácil!](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/)
- [4] [Seguindo fluxos de protocolos](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvFollowStreamSection.html)
- [5] [Referência de filtros de exibição: Transport Layer Security](https://www.wireshark.org/docs/dfref/t/tls.html)
- [6] [Referência de filtros de exibição: HyperText Transfer Protocol 2](https://www.wireshark.org/docs/dfref/h/http2.html)
- [7] [Referência de filtros de exibição: Hypertext Transfer Protocol Version 3](https://www.wireshark.org/docs/dfref/h/http3.html)
- [8] [RFC 9849: Client Hello criptografado por TLS](https://www.rfc-editor.org/rfc/rfc9849.html)
- [9] [Manual do TShark](https://www.wireshark.org/docs/man-pages/tshark.html)
{{#include ../../../banners/hacktricks-training.md}}
