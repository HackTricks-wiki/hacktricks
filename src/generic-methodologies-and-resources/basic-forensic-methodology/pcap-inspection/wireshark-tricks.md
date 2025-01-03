# Truques do Wireshark

{{#include ../../../banners/hacktricks-training.md}}

## Melhore suas habilidades no Wireshark

### Tutoriais

Os seguintes tutoriais são incríveis para aprender alguns truques básicos legais:

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Informações Analisadas

**Informações de Especialista**

Clicando em _**Analisar** --> **Informações de Especialista**_ você terá uma **visão geral** do que está acontecendo nos pacotes **analisados**:

![](<../../../images/image (256).png>)

**Endereços Resolvidos**

Em _**Estatísticas --> Endereços Resolvidos**_ você pode encontrar várias **informações** que foram "**resolvidas**" pelo wireshark, como porta/transporte para protocolo, MAC para o fabricante, etc. É interessante saber o que está implicado na comunicação.

![](<../../../images/image (893).png>)

**Hierarquia de Protocolos**

Em _**Estatísticas --> Hierarquia de Protocolos**_ você pode encontrar os **protocolos** **envolvidos** na comunicação e dados sobre eles.

![](<../../../images/image (586).png>)

**Conversas**

Em _**Estatísticas --> Conversas**_ você pode encontrar um **resumo das conversas** na comunicação e dados sobre elas.

![](<../../../images/image (453).png>)

**Pontos Finais**

Em _**Estatísticas --> Pontos Finais**_ você pode encontrar um **resumo dos pontos finais** na comunicação e dados sobre cada um deles.

![](<../../../images/image (896).png>)

**Informações DNS**

Em _**Estatísticas --> DNS**_ você pode encontrar estatísticas sobre a solicitação DNS capturada.

![](<../../../images/image (1063).png>)

**Gráfico I/O**

Em _**Estatísticas --> Gráfico I/O**_ você pode encontrar um **gráfico da comunicação.**

![](<../../../images/image (992).png>)

### Filtros

Aqui você pode encontrar filtros do wireshark dependendo do protocolo: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
Outros filtros interessantes:

- `(http.request or ssl.handshake.type == 1) and !(udp.port eq 1900)`
- Tráfego HTTP e HTTPS inicial
- `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
- Tráfego HTTP e HTTPS inicial + TCP SYN
- `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
- Tráfego HTTP e HTTPS inicial + TCP SYN + solicitações DNS

### Pesquisa

Se você quiser **pesquisar** por **conteúdo** dentro dos **pacotes** das sessões, pressione _CTRL+f_. Você pode adicionar novas camadas à barra de informações principal (No., Hora, Origem, etc.) pressionando o botão direito e depois a opção de editar coluna.

### Laboratórios pcap gratuitos

**Pratique com os desafios gratuitos de:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Identificando Domínios

Você pode adicionar uma coluna que mostra o cabeçalho Host HTTP:

![](<../../../images/image (639).png>)

E uma coluna que adiciona o nome do Servidor de uma conexão HTTPS iniciada (**ssl.handshake.type == 1**):

![](<../../../images/image (408) (1).png>)

## Identificando nomes de host locais

### Do DHCP

No Wireshark atual, em vez de `bootp`, você precisa procurar por `DHCP`

![](<../../../images/image (1013).png>)

### Do NBNS

![](<../../../images/image (1003).png>)

## Descriptografando TLS

### Descriptografando tráfego https com a chave privada do servidor

_edit>preference>protocol>ssl>_

![](<../../../images/image (1103).png>)

Pressione _Editar_ e adicione todos os dados do servidor e a chave privada (_IP, Porta, Protocolo, Arquivo de chave e senha_)

### Descriptografando tráfego https com chaves de sessão simétricas

Tanto o Firefox quanto o Chrome têm a capacidade de registrar chaves de sessão TLS, que podem ser usadas com o Wireshark para descriptografar tráfego TLS. Isso permite uma análise aprofundada das comunicações seguras. Mais detalhes sobre como realizar essa descriptografia podem ser encontrados em um guia em [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/).

Para detectar isso, procure dentro do ambiente pela variável `SSLKEYLOGFILE`

Um arquivo de chaves compartilhadas terá a seguinte aparência:

![](<../../../images/image (820).png>)

Para importar isso no wireshark, vá para \_editar > preferência > protocolo > ssl > e importe-o no nome do arquivo de log (Pre)-Master-Secret:

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
{{#include ../../../banners/hacktricks-training.md}}
