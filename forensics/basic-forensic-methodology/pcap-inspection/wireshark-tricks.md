# Dicas do Wireshark

## Dicas do Wireshark

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas dicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Melhore suas habilidades no Wireshark

### Tutoriais

Os seguintes tutoriais são incríveis para aprender alguns truques básicos legais:

* [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
* [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
* [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
* [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Informações analisadas

**Informação de especialista**

Clicando em _**Analisar** --> **Informação de especialista**_ você terá uma **visão geral** do que está acontecendo nos pacotes **analisados**:

![](<../../../.gitbook/assets/image (570).png>)

**Endereços resolvidos**

Em _**Estatísticas --> Endereços resolvidos**_ você pode encontrar várias **informações** que foram "**resolvidas**" pelo wireshark, como porta/transporte para protocolo, MAC para o fabricante, etc. É interessante saber o que está implicado na comunicação.

![](<../../../.gitbook/assets/image (571).png>)

**Hierarquia de protocolo**

Em _**Estatísticas --> Hierarquia de protocolo**_ você pode encontrar os **protocolos** **envolvidos** na comunicação e dados sobre eles.

![](<../../../.gitbook/assets/image (572).png>)

**Conversas**

Em _**Estatísticas --> Conversas**_ você pode encontrar um **resumo das conversas** na comunicação e dados sobre elas.

![](<../../../.gitbook/assets/image (573).png>)

**Pontos finais**

Em _**Estatísticas --> Pontos finais**_ você pode encontrar um **resumo dos pontos finais** na comunicação e dados sobre cada um deles.

![](<../../../.gitbook/assets/image (575).png>)

**Informações DNS**

Em _**Estatísticas --> DNS**_ você pode encontrar estatísticas sobre a solicitação DNS capturada.

![](<../../../.gitbook/assets/image (577).png>)

**Gráfico de E/S**

Em _**Estatísticas --> Gráfico de E/S**_ você pode encontrar um **gráfico da comunicação**.

![](<../../../.gitbook/assets/image (574).png>)

### Filtros

Aqui você pode encontrar filtros do wireshark dependendo do protocolo: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
Outros filtros interessantes:

* `(http.request or ssl.handshake.type == 1) and !(udp.port eq 1900)`
  * Tráfego HTTP e HTTPS inicial
* `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
  * Tráfego HTTP e HTTPS inicial + TCP SYN
* `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
  * Tráfego HTTP e HTTPS inicial + TCP SYN + solicitações DNS

### Busca

Se você quiser **procurar** por **conteúdo** dentro dos **pacotes** das sessões, pressione _CTRL+f_. Você pode adicionar novas camadas à barra de informações principais (No., Hora, Origem, etc.) pressionando o botão direito e, em seguida, a edição da coluna.

Prática: [https://www.malware-traffic-analysis.net/](https://www.malware-traffic-analysis.net)

## Identificando Domínios

Você pode adicionar uma coluna que mostra o cabeçalho Host HTTP:

![](<../../../.gitbook/assets/image (403).png>)

E uma coluna que adiciona o nome do servidor de uma conexão HTTPS iniciada (**ssl.handshake.type == 1**):

![](<../../../.gitbook/assets/image (408) (1).png>)

## Identificando nomes de host locais

### Do DHCP

No Wireshark atual, em vez de `bootp`, você precisa procurar por `DHCP`

![](<../../../.gitbook/assets/image (404).png>)

### Do NBNS

![](<../../../.gitbook/assets/image (405).png>)

## Descriptografando TLS

### Descriptografando tráfego https com chave privada do servidor

_editar>preferência>protocolo>ssl>_

![](<../../../.gitbook/assets/image (98).png>)

Pressione _Editar_ e adicione todos os dados do servidor e a chave privada (_IP, Porta, Protocolo, Arquivo de chave e senha_)

### Descriptografando tráfego https com chaves de sessão simétricas

Acontece que o Firefox e o Chrome suportam o registro da chave de sessão simétrica usada para criptografar o tráfego TLS em um arquivo. Você pode então apontar o Wireshark para esse arquivo e pronto! tráfego TLS descriptografado. Mais em: [https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/)\
Para detectar isso, procure dentro do ambiente pela variável `SSLKEYLOGFILE`

Um arquivo de chaves compartilhadas parecerá com isso:

![](<../../../.gitbook/assets/image (99).png>)

Para importar isso no wireshark, vá para \_editar > preferência > protocolo > ssl > e importe-o em (Pre)-Master-Secret log filename:

![](<../../../.gitbook/assets/image (100).png>)

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
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
