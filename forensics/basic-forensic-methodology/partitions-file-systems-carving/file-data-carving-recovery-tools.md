<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!

- Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)

- **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>


# Ferramentas de Carving e Recuperação

Mais ferramentas em [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

## Autopsy

A ferramenta mais comum usada em forense para extrair arquivos de imagens é o [**Autopsy**](https://www.autopsy.com/download/). Baixe-o, instale-o e faça com que ele ingira o arquivo para encontrar arquivos "ocultos". Note que o Autopsy é construído para suportar imagens de disco e outros tipos de imagens, mas não arquivos simples.

## Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** é uma ferramenta para procurar arquivos binários como imagens e arquivos de áudio para arquivos e dados incorporados.\
Ele pode ser instalado com `apt`, no entanto, a [fonte](https://github.com/ReFirmLabs/binwalk) pode ser encontrada no github.\
**Comandos úteis**:
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
## Foremost

Outra ferramenta comum para encontrar arquivos ocultos é o **foremost**. Você pode encontrar o arquivo de configuração do foremost em `/etc/foremost.conf`. Se você quiser procurar apenas por alguns arquivos específicos, descomente-os. Se você não descomentar nada, o foremost procurará pelos tipos de arquivo configurados por padrão.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
## **Scalpel**

**Scalpel** é outra ferramenta que pode ser usada para encontrar e extrair **arquivos embutidos em um arquivo**. Neste caso, você precisará descomentar do arquivo de configuração (_/etc/scalpel/scalpel.conf_) os tipos de arquivos que deseja extrair.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
## Bulk Extractor

Esta ferramenta vem incluída no kali, mas você também pode encontrá-la aqui: [https://github.com/simsong/bulk\_extractor](https://github.com/simsong/bulk\_extractor)

Esta ferramenta pode escanear uma imagem e **extrair pcaps** dentro dela, **informações de rede (URLs, domínios, IPs, MACs, e-mails)** e mais **arquivos**. Você só precisa fazer:
```
bulk_extractor memory.img -o out_folder
```
Navegue por **todas as informações** que a ferramenta coletou (senhas?), **analise** os **pacotes** (leia [**Análise de Pcaps**](../pcap-inspection/)), procure por **domínios estranhos** (domínios relacionados a **malware** ou **inexistentes**).

## PhotoRec

Você pode encontrá-lo em [https://www.cgsecurity.org/wiki/TestDisk\_Download](https://www.cgsecurity.org/wiki/TestDisk\_Download)

Ele vem com versões GUI e CLI. Você pode selecionar os **tipos de arquivos** que deseja que o PhotoRec pesquise.

![](<../../../.gitbook/assets/image (524).png>)

## binvis

Verifique o [código](https://code.google.com/archive/p/binvis/) e a [página da web da ferramenta](https://binvis.io/#/).

### Recursos do BinVis

* Visualizador de **estrutura** visual e ativo
* Vários gráficos para diferentes pontos de foco
* Focando em porções de uma amostra
* **Vendo cadeias e recursos**, em executáveis PE ou ELF, por exemplo.
* Obtendo **padrões** para criptanálise em arquivos
* **Detectando** algoritmos de compactação ou codificação
* **Identificar** esteganografia por padrões
* **Visualização** de diferenças binárias

BinVis é um ótimo **ponto de partida para se familiarizar com um alvo desconhecido** em um cenário de caixa preta.

# Ferramentas Específicas de Recuperação de Dados

## FindAES

Procura por chaves AES pesquisando em suas agendas de chaves. Capaz de encontrar chaves de 128, 192 e 256 bits, como as usadas pelo TrueCrypt e BitLocker.

Baixe [aqui](https://sourceforge.net/projects/findaes/).

# Ferramentas complementares

Você pode usar o [**viu** ](https://github.com/atanunq/viu)para ver imagens do terminal.\
Você pode usar a ferramenta de linha de comando do linux **pdftotext** para transformar um pdf em texto e lê-lo.


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!

- Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)

- **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
