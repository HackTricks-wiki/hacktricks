# Volatility - CheatSheet

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Você quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​[**RootedCON**](https://www.rootedcon.com/) é o evento de cibersegurança mais relevante na **Espanha** e um dos mais importantes na **Europa**. Com **a missão de promover o conhecimento técnico**, este congresso é um ponto de encontro fervilhante para profissionais de tecnologia e cibersegurança em todas as disciplinas.

{% embed url="https://www.rootedcon.com/" %}

Se você quer algo **rápido e louco** que lançará vários plugins do Volatility em paralelo, você pode usar: [https://github.com/carlospolop/autoVolatility](https://github.com/carlospolop/autoVolatility)
```bash
python autoVolatility.py -f MEMFILE -d OUT_DIRECTORY -e /home/user/tools/volatility/vol.py # It will use the most important plugins (could use a lot of space depending on the size of the memory)
```
## Instalação

### volatility3
```bash
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
python3 setup.py install
python3 vol.py —h
```
### volatility2

{% tabs %}
{% tab title="Método1" %} 

#### Comandos básicos

- `volatility2 -f <archivo> imageinfo`: muestra información sobre el archivo de memoria.
- `volatility2 -f <archivo> pslist`: muestra una lista de procesos.
- `volatility2 -f <archivo> pstree`: muestra un árbol de procesos.
- `volatility2 -f <archivo> psscan`: muestra una lista de procesos utilizando el escaneo de proceso.
- `volatility2 -f <archivo> netscan`: muestra una lista de conexiones de red.
- `volatility2 -f <archivo> connscan`: muestra una lista de conexiones de red utilizando el escaneo de conexión.
- `volatility2 -f <archivo> filescan`: muestra una lista de archivos abiertos.
- `volatility2 -f <archivo> hivelist`: muestra una lista de claves del registro.
- `volatility2 -f <archivo> printkey -K <clave>`: muestra el contenido de una clave del registro.
- `volatility2 -f <archivo> dumpregistry -K <clave> -D <directorio>`: guarda el contenido de una clave del registro en un archivo.
- `volatility2 -f <archivo> malfind`: busca malware en la memoria.
- `volatility2 -f <archivo> apihooks`: muestra los hooks de API.
- `volatility2 -f <archivo> dlllist`: muestra una lista de DLL cargadas.
- `volatility2 -f <archivo> handles`: muestra una lista de handles abiertos.
- `volatility2 -f <archivo> mutantscan`: muestra una lista de objetos mutantes.
- `volatility2 -f <archivo> svcscan`: muestra una lista de servicios.
- `volatility2 -f <archivo> driverirp`: muestra una lista de IRP manejados por los drivers.
- `volatility2 -f <archivo> devicetree`: muestra una lista de dispositivos.
- `volatility2 -f <archivo> modscan`: muestra una lista de módulos cargados.
- `volatility2 -f <archivo> moddump -D <directorio> -n <nombre>`: guarda el contenido de un módulo en un archivo.
- `volatility2 -f <archivo> memdump -p <pid> -D <directorio>`: guarda el contenido de un proceso en un archivo.
- `volatility2 -f <archivo> memdump -b <dirección> -s <tamaño> -D <directorio>`: guarda un bloque de memoria en un archivo.

#### Plugins adicionales

- `volatility2 -f <archivo> windows.handles`: muestra una lista de handles abiertos con información adicional.
- `volatility2 -f <archivo> windows.verinfo`: muestra información sobre la versión del sistema operativo.
- `volatility2 -f <archivo> windows.pslist`: muestra una lista de procesos con información adicional.
- `volatility2 -f <archivo> windows.pstree`: muestra un árbol de procesos con información adicional.
- `volatility2 -f <archivo> windows.filescan`: muestra una lista de archivos abiertos con información adicional.
- `volatility2 -f <archivo> windows.netscan`: muestra una lista de conexiones de red con información adicional.
- `volatility2 -f <archivo> windows.connscan`: muestra una lista de conexiones de red utilizando el escaneo de conexión con información adicional.
- `volatility2 -f <archivo> windows.registry.hivelist`: muestra una lista de claves del registro con información adicional.
- `volatility2 -f <archivo> windows.registry.printkey -K <clave>`: muestra el contenido de una clave del registro con información adicional.
- `volatility2 -f <archivo> windows.registry.dumpregistry -K <clave> -D <directorio>`: guarda el contenido de una clave del registro en un archivo con información adicional.
- `volatility2 -f <archivo> windows.malfind`: busca malware en la memoria con información adicional.
- `volatility2 -f <archivo> windows.apihooks`: muestra los hooks de API con información adicional.
- `volatility2 -f <archivo> windows.dlldump -D <directorio> -n <nombre>`: guarda el contenido de una DLL en un archivo con información adicional.
- `volatility2 -f <archivo> windows.svcscan`: muestra una lista de servicios con información adicional.
- `volatility2 -f <archivo> windows.driverirp`: muestra una lista de IRP manejados por los drivers con información adicional.
- `volatility2 -f <archivo> windows.devicetree`: muestra una lista de dispositivos con información adicional.
- `volatility2 -f <archivo> windows.moddump -D <directorio> -n <nombre>`: guarda el contenido de un módulo en un archivo con información adicional.
- `volatility2 -f <archivo> windows.memdump -p <pid> -D <directorio>`: guarda el contenido de un proceso en un archivo con información adicional.
- `volatility2 -f <archivo> windows.memdump -b <dirección> -s <tamaño> -D <directorio>`: guarda un bloque de memoria en un archivo con información adicional.

{% endtab %}
{% endtabs %}
```
Download the executable from https://www.volatilityfoundation.org/26
```
{% endtab %}

{% tab title="Método 2" %}
```bash
git clone https://github.com/volatilityfoundation/volatility.git
cd volatility
python setup.py install
```
{% endtab %}
{% endtabs %}

## Comandos do Volatility

Acesse a documentação oficial em [Referência de comandos do Volatility](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference#kdbgscan)

### Uma nota sobre plugins "list" vs. "scan"

O Volatility tem duas abordagens principais para plugins, que às vezes são refletidas em seus nomes. Plugins "list" tentarão navegar pelas estruturas do Kernel do Windows para recuperar informações como processos (localizar e percorrer a lista vinculada de estruturas `_EPROCESS` na memória), alças do SO (localizar e listar a tabela de alças, desreferenciando quaisquer ponteiros encontrados, etc). Eles mais ou menos se comportam como a API do Windows se solicitado, por exemplo, para listar processos.

Isso torna os plugins "list" bastante rápidos, mas tão vulneráveis quanto a API do Windows à manipulação por malware. Por exemplo, se o malware usa DKOM para desvincular um processo da lista vinculada `_EPROCESS`, ele não aparecerá no Gerenciador de Tarefas e nem no pslist.

Os plugins "scan", por outro lado, adotarão uma abordagem semelhante à escultura da memória para coisas que podem fazer sentido quando desreferenciadas como estruturas específicas. `psscan`, por exemplo, lerá a memória e tentará fazer objetos `_EPROCESS` com ela (ele usa a varredura de pool-tag, que está procurando por strings de 4 bytes que indicam a presença de uma estrutura de interesse). A vantagem é que ele pode desenterrar processos que saíram e, mesmo que o malware manipule a lista vinculada `_EPROCESS`, o plugin ainda encontrará a estrutura deitada na memória (já que ainda precisa existir para o processo ser executado). A desvantagem é que os plugins "scan" são um pouco mais lentos que os plugins "list" e às vezes podem produzir falsos positivos (um processo que saiu há muito tempo e teve partes de sua estrutura sobrescritas por outras operações).

De: [http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/](http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/)

## Perfis de SO

### Volatility3

Como explicado no readme, você precisa colocar a **tabela de símbolos do SO** que deseja suportar dentro de _volatility3/volatility/symbols_.\
Os pacotes de tabela de símbolos para vários sistemas operacionais estão disponíveis para **download** em:

* [https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip)
* [https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip)
* [https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip)

### Volatility2

#### Perfil externo

Você pode obter a lista de perfis suportados fazendo:
```bash
./volatility_2.6_lin64_standalone --info | grep "Profile"
```
Se você deseja usar um **novo perfil que você baixou** (por exemplo, um perfil linux), você precisa criar em algum lugar a seguinte estrutura de pastas: _plugins/overlays/linux_ e colocar dentro desta pasta o arquivo zip contendo o perfil. Em seguida, obtenha o número de perfis usando:
```bash
./vol --plugins=/home/kali/Desktop/ctfs/final/plugins --info
Volatility Foundation Volatility Framework 2.6


Profiles
--------
LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64 - A Profile for Linux CentOS7_3.10.0-123.el7.x86_64_profile x64
VistaSP0x64                                   - A Profile for Windows Vista SP0 x64
VistaSP0x86                                   - A Profile for Windows Vista SP0 x86
```
Você pode **baixar perfis do Linux e Mac** em [https://github.com/volatilityfoundation/profiles](https://github.com/volatilityfoundation/profiles)

No trecho anterior, você pode ver que o perfil é chamado `LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64`, e você pode usá-lo para executar algo como:
```bash
./vol -f file.dmp --plugins=. --profile=LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64 linux_netscan
```
#### Descobrir Perfil
```
volatility imageinfo -f file.dmp
volatility kdbgscan -f file.dmp
```
#### **Diferenças entre imageinfo e kdbgscan**

Ao contrário do imageinfo, que simplesmente fornece sugestões de perfil, o **kdbgscan** é projetado para identificar positivamente o perfil correto e o endereço KDBG correto (se houver vários). Este plugin procura as assinaturas KDBGHeader vinculadas aos perfis do Volatility e aplica verificações de integridade para reduzir falsos positivos. A verbosidade da saída e o número de verificações de integridade que podem ser realizadas dependem se o Volatility pode encontrar um DTB, portanto, se você já conhece o perfil correto (ou se tem uma sugestão de perfil do imageinfo), certifique-se de usá-lo (de [aqui](https://www.andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/)).

Sempre dê uma olhada no **número de processos que o kdbgscan encontrou**. Às vezes, o imageinfo e o kdbgscan podem encontrar **mais de um perfil adequado**, mas apenas o **válido terá alguma relação com processos** (isso ocorre porque o endereço KDBG correto é necessário para extrair processos).
```bash
# GOOD
PsActiveProcessHead           : 0xfffff800011977f0 (37 processes)
PsLoadedModuleList            : 0xfffff8000119aae0 (116 modules)
```

```bash
# BAD
PsActiveProcessHead           : 0xfffff800011947f0 (0 processes)
PsLoadedModuleList            : 0xfffff80001197ac0 (0 modules)
```
#### KDBG

O **bloco de depuração do kernel** (chamado de KdDebuggerDataBlock do tipo \_KDDEBUGGER\_DATA64, ou **KDBG** pelo Volatility) é importante para muitas coisas que o Volatility e os depuradores fazem. Por exemplo, ele tem uma referência ao PsActiveProcessHead, que é a cabeça da lista de todos os processos necessários para a listagem de processos.

## Informações do SO
```bash
#vol3 has a plugin to give OS information (note that imageinfo from vol2 will give you OS info)
./vol.py -f file.dmp windows.info.Info
```
O plugin `banners.Banners` pode ser usado no **vol3 para tentar encontrar banners do linux** no dump.

## Hashes/Senhas

Extraia hashes SAM, [credenciais em cache do domínio](../../../windows-hardening/stealing-credentials/credentials-protections.md#cached-credentials) e [segredos lsa](../../../windows-hardening/authentication-credentials-uac-and-efs.md#lsa-secrets).

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.hashdump.Hashdump #Grab common windows hashes (SAM+SYSTEM)
./vol.py -f file.dmp windows.cachedump.Cachedump #Grab domain cache hashes inside the registry
./vol.py -f file.dmp windows.lsadump.Lsadump #Grab lsa secrets
```
{% endtab %}

{% tab title="volatility-cheatsheet" %}
# Folha de dicas do Volatility

## Comandos básicos

### Análise de imagem

- `volatility -f <file> imageinfo`: exibe informações sobre a imagem de memória
- `volatility -f <file> profileinfo`: exibe informações sobre o perfil da imagem de memória
- `volatility -f <file> pslist`: exibe a lista de processos em execução
- `volatility -f <file> pstree`: exibe a árvore de processos em execução
- `volatility -f <file> psscan`: exibe a lista de processos em execução usando o scanner de processo
- `volatility -f <file> dlllist -p <pid>`: exibe a lista de DLLs carregadas por um processo
- `volatility -f <file> handles -p <pid>`: exibe a lista de handles abertos por um processo
- `volatility -f <file> filescan`: exibe a lista de arquivos abertos
- `volatility -f <file> netscan`: exibe a lista de conexões de rede

### Análise de processo

- `volatility -f <file> procdump -p <pid> -D <output_directory>`: cria um dump de memória de um processo
- `volatility -f <file> memdump -p <pid> -D <output_directory>`: cria um dump de memória de um processo (alternativa ao procdump)
- `volatility -f <file> cmdline -p <pid>`: exibe a linha de comando usada para iniciar um processo
- `volatility -f <file> consoles -p <pid>`: exibe a lista de consoles usados por um processo
- `volatility -f <file> getsids -p <pid>`: exibe a lista de SIDs associados a um processo
- `volatility -f <file> envars -p <pid>`: exibe a lista de variáveis de ambiente usadas por um processo
- `volatility -f <file> malfind -p <pid> -D <output_directory>`: procura por código malicioso em um processo

### Análise de sistema de arquivos

- `volatility -f <file> hivelist`: exibe a lista de arquivos de registro carregados
- `volatility -f <file> printkey -o <offset>`: exibe o conteúdo de uma chave de registro
- `volatility -f <file> dumpregistry -o <offset> -D <output_directory>`: cria um dump de uma chave de registro
- `volatility -f <file> filescan`: exibe a lista de arquivos abertos
- `volatility -f <file> dumpfiles -Q <file_path_regex> -D <output_directory>`: cria dumps de arquivos correspondentes a um regex de caminho

### Análise de rede

- `volatility -f <file> connscan`: exibe a lista de conexões de rede
- `volatility -f <file> connscan -s`: exibe a lista de conexões de rede com informações de socket
- `volatility -f <file> sockets`: exibe a lista de sockets abertos
- `volatility -f <file> sockscan`: exibe a lista de sockets abertos usando o scanner de socket

## Plugins adicionais

### Análise de malware

- `volatility -f <file> malfind`: procura por código malicioso em processos e módulos
- `volatility -f <file> malprocfind`: procura por processos maliciosos
- `volatility -f <file> malfind`: procura por arquivos maliciosos na memória
- `volatility -f <file> apihooks`: exibe a lista de ganchos de API instalados
- `volatility -f <file> svcscan`: exibe a lista de serviços em execução
- `volatility -f <file> svcscan -v`: exibe a lista de serviços em execução com informações detalhadas
- `volatility -f <file> driverirp`: exibe a lista de IRPs (pacotes de solicitação de entrada/saída) manipulados por drivers
- `volatility -f <file> callbacks`: exibe a lista de callbacks registrados

### Análise de memória

- `volatility -f <file> memmap`: exibe o mapa de memória
- `volatility -f <file> memdump`: cria um dump de memória
- `volatility -f <file> memdump -p <pid> -D <output_directory>`: cria um dump de memória de um processo
- `volatility -f <file> memstrings`: procura por strings na memória
- `volatility -f <file> memdump --dump-dir <output_directory> --dump-headers -p <pid>`: cria um dump de memória de um processo com cabeçalhos

### Análise de sistema de arquivos

- `volatility -f <file> filescan`: exibe a lista de arquivos abertos
- `volatility -f <file> dumpfiles -Q <file_path_regex> -D <output_directory>`: cria dumps de arquivos correspondentes a um regex de caminho
- `volatility -f <file> dumpregistry -o <offset> -D <output_directory>`: cria um dump de uma chave de registro

### Análise de rede

- `volatility -f <file> connscan`: exibe a lista de conexões de rede
- `volatility -f <file> connscan -s`: exibe a lista de conexões de rede com informações de socket
- `volatility -f <file> sockets`: exibe a lista de sockets abertos
- `volatility -f <file> sockscan`: exibe a lista de sockets abertos usando o scanner de socket

## Referências

- [Volatility Cheat Sheet](https://github.com/JamesHabben/volatility-cheatsheet) por James Habben
- [Volatility Command Reference](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference) no wiki do Volatility Foundation
{% endtab %}
```bash
volatility --profile=Win7SP1x86_23418 hashdump -f file.dmp #Grab common windows hashes (SAM+SYSTEM)
volatility --profile=Win7SP1x86_23418 cachedump -f file.dmp #Grab domain cache hashes inside the registry
volatility --profile=Win7SP1x86_23418 lsadump -f file.dmp #Grab lsa secrets
```
## Despejo de Memória

O despejo de memória de um processo irá **extrair tudo** do estado atual do processo. O módulo **procdump** irá apenas **extrair** o **código**.
```
volatility -f file.dmp --profile=Win7SP1x86 memdump -p 2168 -D conhost/
```
<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​[**RootedCON**](https://www.rootedcon.com/) é o evento de cibersegurança mais relevante na **Espanha** e um dos mais importantes na **Europa**. Com **a missão de promover o conhecimento técnico**, este congresso é um ponto de encontro fervilhante para profissionais de tecnologia e cibersegurança em todas as disciplinas.

{% embed url="https://www.rootedcon.com/" %}

## Processos

### Listar processos

Tente encontrar processos **suspeitos** (por nome) ou **inesperados** processos filhos (por exemplo, um cmd.exe como filho de iexplorer.exe).\
Pode ser interessante **comparar** o resultado do pslist com o de psscan para identificar processos ocultos.
```bash
python3 vol.py -f file.dmp windows.pstree.PsTree # Get processes tree (not hidden)
python3 vol.py -f file.dmp windows.pslist.PsList # Get process list (EPROCESS)
python3 vol.py -f file.dmp windows.psscan.PsScan # Get hidden process list(malware)
```
{% endtab %}

{% tab title="volatility-cheatsheet.md" %}
# Folha de dicas do Volatility

## Comandos básicos

### Análise de imagem

- `volatility -f <file> imageinfo`: exibe informações sobre a imagem de memória
- `volatility -f <file> kdbgscan`: procura pelo valor do depurador do kernel (KDBG) na imagem de memória
- `volatility -f <file> pslist`: lista os processos em execução na imagem de memória
- `volatility -f <file> psscan`: lista os processos em execução na imagem de memória (busca em todos os processos)
- `volatility -f <file> pstree`: exibe a árvore de processos na imagem de memória
- `volatility -f <file> dlllist -p <pid>`: lista as DLLs carregadas por um processo específico
- `volatility -f <file> handles -p <pid>`: lista os handles abertos por um processo específico
- `volatility -f <file> filescan`: lista os arquivos abertos na imagem de memória
- `volatility -f <file> netscan`: lista as conexões de rede na imagem de memória
- `volatility -f <file> connscan`: lista as conexões de rede na imagem de memória (busca em todos os processos)
- `volatility -f <file> hivelist`: lista os arquivos de registro na imagem de memória
- `volatility -f <file> printkey -K <key>`: exibe o conteúdo de uma chave de registro específica
- `volatility -f <file> dumpregistry -D <output_directory> -K <key>`: extrai uma chave de registro específica para um diretório de saída

### Análise de processo

- `volatility -f <file> memdump -p <pid> -D <output_directory>`: extrai o espaço de endereço virtual de um processo específico para um diretório de saída
- `volatility -f <file> procdump -p <pid> -D <output_directory>`: extrai o arquivo executável de um processo específico para um diretório de saída
- `volatility -f <file> malfind -p <pid> -D <output_directory>`: procura por código malicioso na memória de um processo específico e extrai-o para um diretório de saída

### Análise de sistema de arquivos

- `volatility -f <file> hivelist`: lista os arquivos de registro na imagem de memória
- `volatility -f <file> printkey -K <key>`: exibe o conteúdo de uma chave de registro específica
- `volatility -f <file> dumpregistry -D <output_directory> -K <key>`: extrai uma chave de registro específica para um diretório de saída
- `volatility -f <file> filescan`: lista os arquivos abertos na imagem de memória
- `volatility -f <file> dumpfiles -D <output_directory> --name <filename>`: extrai um arquivo específico para um diretório de saída

### Outros comandos úteis

- `volatility -f <file> hashdump -y <profile>`: extrai as hashes de senha da imagem de memória
- `volatility -f <file> truecryptpassphrase`: extrai a senha do TrueCrypt da imagem de memória
- `volatility -f <file> clipboard`: exibe o conteúdo da área de transferência da imagem de memória
- `volatility -f <file> shellbags`: exibe as informações de shellbags da imagem de memória

## Plugins adicionais

### Análise de malware

- `volatility -f <file> malfind`: procura por código malicioso na imagem de memória
- `volatility -f <file> malprocfind`: procura por processos maliciosos na imagem de memória
- `volatility -f <file> maldriverscan`: procura por drivers maliciosos na imagem de memória
- `volatility -f <file> apihooks`: exibe os ganchos de API na imagem de memória

### Análise de rede

- `volatility -f <file> connscan`: lista as conexões de rede na imagem de memória (busca em todos os processos)
- `volatility -f <file> sockets`: lista os sockets abertos na imagem de memória
- `volatility -f <file> sockscan`: lista os sockets abertos na imagem de memória (busca em todos os processos)

### Análise de sistema de arquivos

- `volatility -f <file> shimcache`: exibe as informações do cache de compatibilidade do aplicativo da imagem de memória
- `volatility -f <file> usnjrnl`: exibe as informações do diário de alterações do NTFS da imagem de memória
- `volatility -f <file> mftparser`: exibe as informações do arquivo de tabela mestre do NTFS da imagem de memória
- `volatility -f <file> mftparser -D <output_directory>`: extrai o arquivo de tabela mestre do NTFS para um diretório de saída
- `volatility -f <file> filescan`: lista os arquivos abertos na imagem de memória
- `volatility -f <file> dumpfiles -D <output_directory> --name <filename>`: extrai um arquivo específico para um diretório de saída

### Análise de memória

- `volatility -f <file> memmap`: exibe o mapa de memória da imagem de memória
- `volatility -f <file> memdump`: extrai a imagem de memória completa para um arquivo
- `volatility -f <file> memdump --dump-dir <output_directory>`: extrai a imagem de memória completa para um diretório de saída
- `volatility -f <file> memdump -p <pid> -D <output_directory>`: extrai o espaço de endereço virtual de um processo específico para um diretório de saída
- `volatility -f <file> memdump --offset <offset> --length <length> -D <output_directory>`: extrai uma região específica da imagem de memória para um diretório de saída

## Referências

- [Volatility Cheat Sheet](https://github.com/JamesHabben/volatility-cheatsheet) por James Habben
- [The Art of Memory Forensics: Detecting Malware and Threats in Windows, Linux, and Mac Memory](https://www.amazon.com/Art-Memory-Forensics-Detecting-Malware/dp/1118825098) por Michael Hale Ligh, Andrew Case, Jamie Levy e Aaron Walters
{% endtab %}
```bash
volatility --profile=PROFILE pstree -f file.dmp # Get process tree (not hidden)
volatility --profile=PROFILE pslist -f file.dmp # Get process list (EPROCESS)
volatility --profile=PROFILE psscan -f file.dmp # Get hidden process list(malware)
volatility --profile=PROFILE psxview -f file.dmp # Get hidden process list
```
### Dump de processos

{% tabs %}
{% tab title="vol3" %}

Para despejar um processo específico, use o comando `procdump`:

```bash
procdump -p <pid> -d <dump_directory>
```

Para despejar um processo que atenda a um determinado critério, use o comando `procdump` com a opção `-ma`:

```bash
procdump -ma -t -n 3 -s 5 -d <dump_directory> <image_name>
```

O comando acima despejará o processo que atenda aos seguintes critérios:

- Nome da imagem: `<image_name>`
- CPU média superior a 5%: `-s 5`
- Utilização da CPU superior a 3%: `-n 3`
- Tempo de espera de 10 segundos: `-t`

Para despejar todos os processos em execução, use o comando `procdump` com a opção `-a`:

```bash
procdump -a -d <dump_directory>
```

{% endtab %}
{% endtabs %}
```bash
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --pid <pid> #Dump the .exe and dlls of the process in the current directory
```
{% endtab %}

{% tab title="volatility-cheatsheet" %}
# Folha de dicas do Volatility

## Comandos básicos

### Análise de imagem

- `volatility -f <file> imageinfo`: exibe informações sobre a imagem de memória
- `volatility -f <file> profileinfo`: exibe informações sobre o perfil da imagem de memória
- `volatility -f <file> pslist`: exibe a lista de processos em execução
- `volatility -f <file> pstree`: exibe a árvore de processos em execução
- `volatility -f <file> psscan`: exibe a lista de processos em execução usando o scanner de processo
- `volatility -f <file> dlllist -p <pid>`: exibe a lista de DLLs carregadas por um processo
- `volatility -f <file> handles -p <pid>`: exibe a lista de handles abertos por um processo
- `volatility -f <file> filescan`: exibe a lista de arquivos abertos
- `volatility -f <file> netscan`: exibe a lista de conexões de rede

### Análise de processo

- `volatility -f <file> procdump -p <pid> -D <output_directory>`: cria um dump de memória de um processo
- `volatility -f <file> memdump -p <pid> -D <output_directory>`: cria um dump de memória de um processo (alternativa ao procdump)
- `volatility -f <file> cmdline -p <pid>`: exibe a linha de comando usada para iniciar um processo
- `volatility -f <file> consoles -p <pid>`: exibe a lista de consoles usados por um processo
- `volatility -f <file> getsids -p <pid>`: exibe a lista de SIDs associados a um processo
- `volatility -f <file> envars -p <pid>`: exibe a lista de variáveis de ambiente usadas por um processo
- `volatility -f <file> malfind -p <pid> -D <output_directory>`: procura por código malicioso em um processo

### Análise de sistema de arquivos

- `volatility -f <file> hivelist`: exibe a lista de arquivos de registro carregados
- `volatility -f <file> printkey -o <offset>`: exibe o conteúdo de uma chave de registro
- `volatility -f <file> dumpregistry -o <offset> -D <output_directory>`: cria um dump de uma chave de registro
- `volatility -f <file> filescan`: exibe a lista de arquivos abertos
- `volatility -f <file> dumpfiles -Q <file_path_regex> -D <output_directory>`: cria dumps de arquivos correspondentes a um regex de caminho

### Análise de rede

- `volatility -f <file> connscan`: exibe a lista de conexões de rede
- `volatility -f <file> connscan -s`: exibe a lista de conexões de rede com informações de socket
- `volatility -f <file> sockets`: exibe a lista de sockets abertos
- `volatility -f <file> sockscan`: exibe a lista de sockets abertos usando o scanner de socket

## Plugins adicionais

### Análise de malware

- `volatility -f <file> malfind`: procura por código malicioso em processos e módulos
- `volatility -f <file> malprocfind`: procura por processos maliciosos
- `volatility -f <file> malfind`: procura por arquivos maliciosos na memória
- `volatility -f <file> apihooks`: exibe a lista de ganchos de API instalados
- `volatility -f <file> svcscan`: exibe a lista de serviços em execução
- `volatility -f <file> svcscan -v`: exibe a lista de serviços em execução com informações detalhadas
- `volatility -f <file> driverirp`: exibe a lista de IRPs (pacotes de solicitação de entrada/saída) manipulados por drivers
- `volatility -f <file> callbacks`: exibe a lista de callbacks registrados

### Análise de memória

- `volatility -f <file> memmap`: exibe o mapa de memória
- `volatility -f <file> memdump`: cria um dump de memória
- `volatility -f <file> memdump -p <pid> -D <output_directory>`: cria um dump de memória de um processo
- `volatility -f <file> memstrings`: procura por strings na memória
- `volatility -f <file> memdump --dump-dir <output_directory> --dump-headers -p <pid>`: cria um dump de memória de um processo com cabeçalhos

### Análise de sistema de arquivos

- `volatility -f <file> filescan`: exibe a lista de arquivos abertos
- `volatility -f <file> dumpfiles -Q <file_path_regex> -D <output_directory>`: cria dumps de arquivos correspondentes a um regex de caminho
- `volatility -f <file> printkey -o <offset>`: exibe o conteúdo de uma chave de registro
- `volatility -f <file> dumpregistry -o <offset> -D <output_directory>`: cria um dump de uma chave de registro

### Análise de rede

- `volatility -f <file> connscan`: exibe a lista de conexões de rede
- `volatility -f <file> connscan -s`: exibe a lista de conexões de rede com informações de socket
- `volatility -f <file> sockets`: exibe a lista de sockets abertos
- `volatility -f <file> sockscan`: exibe a lista de sockets abertos usando o scanner de socket

## Referências

- [Volatility Cheat Sheet](https://github.com/JamesHabben/volatility-cheatsheet) por James Habben
- [Volatility Command Reference](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference) no wiki do Volatility Foundation
{% endtab %}
```bash
volatility --profile=Win7SP1x86_23418 procdump --pid=3152 -n --dump-dir=. -f file.dmp
```
### Linha de comando

Alguma coisa suspeita foi executada? 

{% tabs %}
{% tab title="vol3" %}
```bash
python3 vol.py -f file.dmp windows.cmdline.CmdLine #Display process command-line arguments
```
{% endtab %}

{% tab title="volatility-cheatsheet.md" %}
# Folha de dicas do Volatility

## Comandos básicos

### Análise de imagem

- `volatility -f <file> imageinfo`: exibe informações sobre a imagem de memória
- `volatility -f <file> kdbgscan`: procura pelo valor do depurador do kernel (KDBG) na imagem de memória
- `volatility -f <file> pslist`: lista os processos em execução na imagem de memória
- `volatility -f <file> psscan`: lista os processos em execução na imagem de memória (busca em todos os processos)
- `volatility -f <file> pstree`: exibe a árvore de processos na imagem de memória
- `volatility -f <file> dlllist -p <pid>`: lista as DLLs carregadas por um processo específico
- `volatility -f <file> handles -p <pid>`: lista os handles abertos por um processo específico
- `volatility -f <file> filescan`: lista os arquivos abertos na imagem de memória
- `volatility -f <file> netscan`: lista as conexões de rede na imagem de memória
- `volatility -f <file> connscan`: lista as conexões de rede na imagem de memória (busca em todos os processos)
- `volatility -f <file> hivelist`: lista os arquivos de registro na imagem de memória
- `volatility -f <file> printkey -K <key>`: exibe o conteúdo de uma chave de registro específica
- `volatility -f <file> dumpregistry -D <output_directory> -K <key>`: extrai uma chave de registro específica para um diretório de saída

### Análise de processo

- `volatility -f <file> memdump -p <pid> -D <output_directory>`: extrai o espaço de endereço virtual de um processo específico para um diretório de saída
- `volatility -f <file> procdump -p <pid> -D <output_directory>`: extrai o arquivo executável de um processo específico para um diretório de saída
- `volatility -f <file> malfind -p <pid> -D <output_directory>`: procura por código malicioso na memória de um processo específico e extrai-o para um diretório de saída

### Análise de sistema de arquivos

- `volatility -f <file> hivelist`: lista os arquivos de registro na imagem de memória
- `volatility -f <file> printkey -K <key>`: exibe o conteúdo de uma chave de registro específica
- `volatility -f <file> dumpregistry -D <output_directory> -K <key>`: extrai uma chave de registro específica para um diretório de saída
- `volatility -f <file> filescan`: lista os arquivos abertos na imagem de memória
- `volatility -f <file> dumpfiles -D <output_directory> --name <filename>`: extrai um arquivo específico para um diretório de saída

### Análise de rede

- `volatility -f <file> netscan`: lista as conexões de rede na imagem de memória
- `volatility -f <file> connscan`: lista as conexões de rede na imagem de memória (busca em todos os processos)
- `volatility -f <file> sockets`: lista os sockets abertos na imagem de memória
- `volatility -f <file> sockscan`: lista os sockets abertos na imagem de memória (busca em todos os processos)

## Plugins adicionais

### Malware

- `volatility -f <file> malfind`: procura por código malicioso na imagem de memória
- `volatility -f <file> malprocfind`: procura por processos maliciosos na imagem de memória
- `volatility -f <file> maldriverscan`: procura por drivers maliciosos na imagem de memória
- `volatility -f <file> apihooks`: lista os ganchos de API na imagem de memória

### Análise de rede

- `volatility -f <file> connscan`: lista as conexões de rede na imagem de memória (busca em todos os processos)
- `volatility -f <file> sockets`: lista os sockets abertos na imagem de memória
- `volatility -f <file> sockscan`: lista os sockets abertos na imagem de memória (busca em todos os processos)

### Análise de sistema de arquivos

- `volatility -f <file> filescan`: lista os arquivos abertos na imagem de memória
- `volatility -f <file> dumpfiles -D <output_directory> --name <filename>`: extrai um arquivo específico para um diretório de saída
- `volatility -f <file> shimcache`: lista as entradas do cache de compatibilidade do aplicativo na imagem de memória

### Análise de processo

- `volatility -f <file> memdump`: extrai o espaço de endereço virtual de um processo específico para um arquivo
- `volatility -f <file> procdump`: extrai o arquivo executável de um processo específico para um arquivo
- `volatility -f <file> vadinfo`: exibe informações sobre as regiões de memória alocadas para um processo específico
- `volatility -f <file> vadtree`: exibe a árvore de regiões de memória alocadas para um processo específico
- `volatility -f <file> dlldump -p <pid> -D <output_directory>`: extrai uma DLL carregada por um processo específico para um diretório de saída
- `volatility -f <file> handles -p <pid>`: lista os handles abertos por um processo específico
- `volatility -f <file> deskscan`: lista as janelas de desktop na imagem de memória
- `volatility -f <file> getsids`: lista os SIDs (identificadores de segurança) na imagem de memória
- `volatility -f <file> getsid -p <pid>`: exibe o SID (identificador de segurança) de um processo específico
- `volatility -f <file> envars -p <pid>`: lista as variáveis de ambiente de um processo específico

### Análise de usuário

- `volatility -f <file> hivelist`: lista os arquivos de registro na imagem de memória
- `volatility -f <file> printkey -K <key>`: exibe o conteúdo de uma chave de registro específica
- `volatility -f <file> dumpregistry -D <output_directory> -K <key>`: extrai uma chave de registro específica para um diretório de saída
- `volatility -f <file> userassist`: lista as entradas do UserAssist na imagem de memória
- `volatility -f <file> shellbags`: lista as entradas do ShellBags na imagem de memória
- `volatility -f <file> chromehistory`: lista o histórico de navegação do Google Chrome na imagem de memória
- `volatility -f <file> chromecookies`: lista os cookies do Google Chrome na imagem de memória
- `volatility -f <file> firefoxhistory`: lista o histórico de navegação do Mozilla Firefox na imagem de memória
- `volatility -f <file> firefoxcookies`: lista os cookies do Mozilla Firefox na imagem de memória
- `volatility -f <file> iehistory`: lista o histórico de navegação do Internet Explorer na imagem de memória
- `volatility -f <file> iecookies`: lista os cookies do Internet Explorer na imagem de memória
- `volatility -f <file> pslist -u`: lista os processos em execução na imagem de memória, exibindo informações do usuário
- `volatility -f <file> getsids`: lista os SIDs (identificadores de segurança) na imagem de memória
- `volatility -f <file> getsid -u <user>`: lista os processos em execução na imagem de memória para um usuário específico
- `volatility -f <file> envars -u <user>`: lista as variáveis de ambiente para um usuário específico

## Referências

- [Volatility Cheat Sheet](https://github.com/JamesHabben/volatility-cheatsheet) por James Habben
- [The Art of Memory Forensics: Detecting Malware and Threats in Windows, Linux, and Mac Memory](https://www.wiley.com/en-us/The+Art+of+Memory+Forensics%3A+Detecting+Malware+and+Threats+in+Windows%2C+Linux%2C+and+Mac+Memory-p-9781118825099) por Michael Hale Ligh, Andrew Case, Jamie Levy e Aaron Walters
{% endtab %}
```bash
volatility --profile=PROFILE cmdline -f file.dmp #Display process command-line arguments
volatility --profile=PROFILE consoles -f file.dmp #command history by scanning for _CONSOLE_INFORMATION
```
{% endtab %}
{% tab title="Portuguese" %}
Os comandos inseridos no cmd.exe são processados pelo conhost.exe (csrss.exe antes do Windows 7). Então, mesmo que um invasor tenha conseguido matar o cmd.exe antes de obtermos um dump de memória, ainda há uma boa chance de recuperar o histórico da sessão da linha de comando da memória do conhost.exe. Se você encontrar algo estranho (usando os módulos do console), tente fazer o dump da memória do processo associado ao conhost.exe e procurar por strings dentro dele para extrair as linhas de comando.

### Ambiente

Obtenha as variáveis de ambiente de cada processo em execução. Pode haver alguns valores interessantes.
```bash
python3 vol.py -f file.dmp windows.envars.Envars [--pid <pid>] #Display process environment variables
```
{% endtab %}

{% tab title="volatility-cheatsheet.md" %}
# Folha de dicas do Volatility

## Comandos básicos

### Análise de imagem

- `volatility -f <file> imageinfo`: exibe informações sobre a imagem de memória
- `volatility -f <file> kdbgscan`: procura pelo valor do depurador do kernel (KDBG) na imagem de memória
- `volatility -f <file> pslist`: lista os processos em execução na imagem de memória
- `volatility -f <file> pstree`: exibe uma árvore de processos em execução na imagem de memória
- `volatility -f <file> psscan`: procura por processos na imagem de memória
- `volatility -f <file> dlllist -p <pid>`: lista as DLLs carregadas por um processo específico
- `volatility -f <file> filescan`: procura por arquivos abertos na imagem de memória
- `volatility -f <file> netscan`: procura por conexões de rede na imagem de memória
- `volatility -f <file> connections`: exibe informações sobre as conexões de rede na imagem de memória
- `volatility -f <file> connscan`: procura por conexões de rede na imagem de memória
- `volatility -f <file> hivelist`: lista as chaves do registro presentes na imagem de memória
- `volatility -f <file> printkey -K <key>`: exibe o conteúdo de uma chave do registro na imagem de memória
- `volatility -f <file> hashdump -y <offset>`: extrai hashes de senha da imagem de memória

### Análise de processo

- `volatility -f <file> memdump -p <pid> -D <output_directory>`: cria um dump de memória de um processo específico
- `volatility -f <file> procdump -p <pid> -D <output_directory>`: cria um dump de processo de um processo específico
- `volatility -f <file> malfind -p <pid> -D <output_directory>`: procura por malwares na memória de um processo específico
- `volatility -f <file> apihooks -p <pid>`: exibe informações sobre os hooks de API em um processo específico
- `volatility -f <file> vadinfo -p <pid>`: exibe informações sobre as regiões de memória alocadas para um processo específico
- `volatility -f <file> vadtree -p <pid>`: exibe uma árvore das regiões de memória alocadas para um processo específico
- `volatility -f <file> handles -p <pid>`: lista os handles abertos por um processo específico
- `volatility -f <file> cmdscan -p <pid>`: procura por comandos executados por um processo específico
- `volatility -f <file> consoles -p <pid>`: exibe informações sobre as consoles alocadas para um processo específico
- `volatility -f <file> getsids -p <pid>`: exibe informações sobre os SIDs associados a um processo específico
- `volatility -f <file> envars -p <pid>`: exibe as variáveis de ambiente definidas para um processo específico

## Plugins adicionais

### Análise de malware

- `volatility -f <file> yarascan -Y <rules_file>`: procura por malwares usando regras YARA
- `volatility -f <file> malfind`: procura por malwares na imagem de memória
- `volatility -f <file> malfind --dump-dir <output_directory>`: procura por malwares na imagem de memória e cria dumps dos arquivos encontrados
- `volatility -f <file> malfind --dump-dir <output_directory> --disassemble`: procura por malwares na imagem de memória, cria dumps dos arquivos encontrados e desmonta o código

### Análise de rede

- `volatility -f <file> connscan`: procura por conexões de rede na imagem de memória
- `volatility -f <file> netscan`: procura por conexões de rede na imagem de memória
- `volatility -f <file> sockets`: exibe informações sobre os sockets na imagem de memória
- `volatility -f <file> sockscan`: procura por sockets na imagem de memória

### Análise de registro

- `volatility -f <file> hivelist`: lista as chaves do registro presentes na imagem de memória
- `volatility -f <file> printkey -K <key>`: exibe o conteúdo de uma chave do registro na imagem de memória
- `volatility -f <file> printkey -K <key> --output-file <output_file>`: exibe o conteúdo de uma chave do registro na imagem de memória e salva em um arquivo
- `volatility -f <file> userassist`: exibe informações sobre as entradas do UserAssist no registro
- `volatility -f <file> shimcache`: exibe informações sobre as entradas do ShimCache no registro
- `volatility -f <file> ldrmodules`: exibe informações sobre os módulos carregados na imagem de memória
- `volatility -f <file> ldrmodules -p <pid>`: exibe informações sobre os módulos carregados por um processo específico
- `volatility -f <file> printkey -K "Software\Microsoft\Windows\CurrentVersion\Run"`: exibe as entradas de inicialização do registro
- `volatility -f <file> printkey -K "Software\Microsoft\Windows\CurrentVersion\RunOnce"`: exibe as entradas de inicialização única do registro

### Análise de sistema de arquivos

- `volatility -f <file> filescan`: procura por arquivos abertos na imagem de memória
- `volatility -f <file> dumpfiles -Q <address>`: cria um dump de um arquivo específico
- `volatility -f <file> dumpfiles -Q <address> --dump-dir <output_directory>`: cria um dump de um arquivo específico e salva em um diretório
- `volatility -f <file> dumpfiles -Q <address> --dump-dir <output_directory> --name <filename>`: cria um dump de um arquivo específico, salva em um diretório e renomeia o arquivo
- `volatility -f <file> mftparser`: exibe informações sobre o Master File Table (MFT)
- `volatility -f <file> usnjrnl`: exibe informações sobre o USN Journal
- `volatility -f <file> usnjrnl -o <offset>`: exibe informações sobre o USN Journal a partir de um determinado offset
- `volatility -f <file> usnjrnl -U <usn_number>`: exibe informações sobre o USN Journal a partir de um determinado número USN

### Análise de virtualização

- `volatility -f <file> vboxinfo`: exibe informações sobre as máquinas virtuais do VirtualBox
- `volatility -f <file> vboxguestinfo -p <pid>`: exibe informações sobre o processo do Guest Additions do VirtualBox
- `volatility -f <file> vmwareinfo`: exibe informações sobre as máquinas virtuais do VMware
- `volatility -f <file> vmwarecheck`: verifica se a imagem de memória é de uma máquina virtual do VMware
- `volatility -f <file> xeninfo`: exibe informações sobre as máquinas virtuais do Xen
- `volatility -f <file> xenpmap`: exibe informações sobre o mapeamento de memória do Xen

### Análise de memória física

- `volatility -f <file> hibernateinfo`: exibe informações sobre o arquivo de hibernação
- `volatility -f <file> hiberfilscan`: procura por arquivos de hibernação na imagem de memória
- `volatility -f <file> windowspcap`: exibe informações sobre os pacotes capturados pelo WinPcap
- `volatility -f <file> physmap`: exibe informações sobre o mapeamento de memória física
- `volatility -f <file> memmap`: exibe informações sobre o mapeamento de memória virtual e física

## Referências

- [Volatility Cheat Sheet](https://github.com/413x90/volatility-cheatsheet) por 413x90
- [Volatility Command Reference](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference) no GitHub do Volatility Foundation
{% endtab %}
```bash
volatility --profile=PROFILE envars -f file.dmp [--pid <pid>] #Display process environment variables

volatility --profile=PROFILE -f file.dmp linux_psenv [-p <pid>] #Get env of process. runlevel var means the runlevel where the proc is initated 
```
### Privilégios de token

Verifique os tokens de privilégios em serviços inesperados.\
Pode ser interessante listar os processos que usam algum token privilegiado.
```bash
#Get enabled privileges of some processes
python3 vol.py -f file.dmp windows.privileges.Privs [--pid <pid>]
#Get all processes with interesting privileges
python3 vol.py -f file.dmp windows.privileges.Privs | grep "SeImpersonatePrivilege\|SeAssignPrimaryPrivilege\|SeTcbPrivilege\|SeBackupPrivilege\|SeRestorePrivilege\|SeCreateTokenPrivilege\|SeLoadDriverPrivilege\|SeTakeOwnershipPrivilege\|SeDebugPrivilege"
```
{% endtab %}

{% tab title="volatility-cheatsheet.md" %}
# Folha de dicas do Volatility

## Comandos básicos

### Análise de imagem

- `volatility -f <file> imageinfo`: exibe informações sobre a imagem de memória
- `volatility -f <file> kdbgscan`: procura pelo valor do depurador do kernel (KDBG) na imagem de memória
- `volatility -f <file> pslist`: lista os processos em execução na imagem de memória
- `volatility -f <file> psscan`: lista os processos em execução na imagem de memória (busca em todos os processos)
- `volatility -f <file> pstree`: exibe a árvore de processos na imagem de memória
- `volatility -f <file> dlllist -p <pid>`: lista as DLLs carregadas por um processo específico
- `volatility -f <file> handles -p <pid>`: lista os handles abertos por um processo específico
- `volatility -f <file> filescan`: lista os arquivos abertos na imagem de memória
- `volatility -f <file> netscan`: lista as conexões de rede na imagem de memória
- `volatility -f <file> connscan`: lista as conexões de rede na imagem de memória (busca em todos os processos)
- `volatility -f <file> hivelist`: lista os arquivos de registro na imagem de memória
- `volatility -f <file> printkey -K <key>`: exibe o conteúdo de uma chave de registro específica
- `volatility -f <file> dumpregistry -D <output_directory> -K <key>`: extrai uma chave de registro específica para um diretório de saída

### Análise de processo

- `volatility -f <file> memdump -p <pid> -D <output_directory>`: extrai o espaço de endereço virtual de um processo específico para um diretório de saída
- `volatility -f <file> procdump -p <pid> -D <output_directory>`: extrai o arquivo executável de um processo específico para um diretório de saída
- `volatility -f <file> malfind -p <pid> -D <output_directory>`: procura por código malicioso na memória de um processo específico e extrai-o para um diretório de saída

### Análise de sistema de arquivos

- `volatility -f <file> hivelist`: lista os arquivos de registro na imagem de memória
- `volatility -f <file> printkey -K <key>`: exibe o conteúdo de uma chave de registro específica
- `volatility -f <file> dumpregistry -D <output_directory> -K <key>`: extrai uma chave de registro específica para um diretório de saída
- `volatility -f <file> filescan`: lista os arquivos abertos na imagem de memória
- `volatility -f <file> dumpfiles -D <output_directory> --name <filename>`: extrai um arquivo específico para um diretório de saída

### Análise de rede

- `volatility -f <file> netscan`: lista as conexões de rede na imagem de memória
- `volatility -f <file> connscan`: lista as conexões de rede na imagem de memória (busca em todos os processos)
- `volatility -f <file> sockets`: lista os sockets abertos na imagem de memória
- `volatility -f <file> sockscan`: lista os sockets abertos na imagem de memória (busca em todos os processos)

## Plugins úteis

### Malware

- `malfind`: procura por código malicioso na memória e extrai-o para um diretório de saída
- `malsysproc`: lista os processos suspeitos na imagem de memória
- `malfind`: procura por código malicioso na memória e extrai-o para um diretório de saída
- `apihooks`: lista as funções do sistema que foram modificadas por um rootkit
- `ldrmodules`: lista os módulos carregados por um processo específico
- `ldrmodules`: lista os módulos carregados por um processo específico
- `ldrmodules`: lista os módulos carregados por um processo específico

### Registro

- `hivelist`: lista os arquivos de registro na imagem de memória
- `printkey`: exibe o conteúdo de uma chave de registro específica
- `dumpregistry`: extrai uma chave de registro específica para um diretório de saída

### Processos

- `handles`: lista os handles abertos por um processo específico
- `memdump`: extrai o espaço de endereço virtual de um processo específico para um diretório de saída
- `procdump`: extrai o arquivo executável de um processo específico para um diretório de saída
- `dlllist`: lista as DLLs carregadas por um processo específico

### Rede

- `netscan`: lista as conexões de rede na imagem de memória
- `connscan`: lista as conexões de rede na imagem de memória (busca em todos os processos)
- `sockets`: lista os sockets abertos na imagem de memória
- `sockscan`: lista os sockets abertos na imagem de memória (busca em todos os processos)

### Outros

- `filescan`: lista os arquivos abertos na imagem de memória
- `pstree`: exibe a árvore de processos na imagem de memória
- `pslist`: lista os processos em execução na imagem de memória
- `psscan`: lista os processos em execução na imagem de memória (busca em todos os processos)
- `kdbgscan`: procura pelo valor do depurador do kernel (KDBG) na imagem de memória

## Referências

- [Volatility Cheat Sheet](https://github.com/superponible/volatility-cheatsheet) por superponible
- [Volatility Command Reference](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference) por Volatility Foundation
```bash
#Get enabled privileges of some processes
volatility --profile=Win7SP1x86_23418 privs --pid=3152 -f file.dmp | grep Enabled
#Get all processes with interesting privileges
volatility --profile=Win7SP1x86_23418 privs -f file.dmp | grep "SeImpersonatePrivilege\|SeAssignPrimaryPrivilege\|SeTcbPrivilege\|SeBackupPrivilege\|SeRestorePrivilege\|SeCreateTokenPrivilege\|SeLoadDriverPrivilege\|SeTakeOwnershipPrivilege\|SeDebugPrivilege"
```
### SIDs

Verifique cada SSID possuído por um processo.\
Pode ser interessante listar os processos que usam um SID de privilégios (e os processos que usam algum SID de serviço).
```bash
./vol.py -f file.dmp windows.getsids.GetSIDs [--pid <pid>] #Get SIDs of processes
./vol.py -f file.dmp windows.getservicesids.GetServiceSIDs #Get the SID of services
```
{% endtab %}

{% tab title="volatility-cheatsheet" %}
# Folha de dicas do Volatility

## Comandos básicos

### Análise de imagem

- `volatility -f <file> imageinfo`: exibe informações sobre a imagem de memória
- `volatility -f <file> profileinfo`: exibe informações sobre o perfil da imagem de memória
- `volatility -f <file> pslist`: exibe a lista de processos em execução
- `volatility -f <file> pstree`: exibe a árvore de processos em execução
- `volatility -f <file> psscan`: exibe a lista de processos em execução usando o scanner de processo
- `volatility -f <file> dlllist -p <pid>`: exibe a lista de DLLs carregadas por um processo
- `volatility -f <file> handles -p <pid>`: exibe a lista de handles abertos por um processo
- `volatility -f <file> filescan`: exibe a lista de arquivos abertos
- `volatility -f <file> netscan`: exibe a lista de conexões de rede

### Análise de processo

- `volatility -f <file> procdump -p <pid> -D <output_directory>`: cria um dump de memória de um processo
- `volatility -f <file> memdump -p <pid> -D <output_directory>`: cria um dump de memória de um processo (mais rápido que o procdump)
- `volatility -f <file> malfind -p <pid> -D <output_directory>`: procura por malwares na memória de um processo
- `volatility -f <file> apihooks -p <pid>`: exibe a lista de ganchos de API instalados em um processo
- `volatility -f <file> vadinfo -p <pid>`: exibe informações sobre as regiões de memória de um processo
- `volatility -f <file> vadtree -p <pid>`: exibe a árvore de regiões de memória de um processo
- `volatility -f <file> vadwalk -p <pid> -v <address>`: exibe informações sobre uma região de memória específica de um processo

### Análise de sistema de arquivos

- `volatility -f <file> hivelist`: exibe a lista de arquivos de registro carregados
- `volatility -f <file> printkey -K <key>`: exibe o conteúdo de uma chave de registro
- `volatility -f <file> dumpregistry -D <output_directory>`: cria um dump do registro do sistema
- `volatility -f <file> filescan -S <offset> -E <offset>`: exibe a lista de arquivos abertos em um intervalo de endereços

### Análise de rede

- `volatility -f <file> connscan`: exibe a lista de conexões de rede
- `volatility -f <file> connscan -s`: exibe a lista de conexões de rede com informações de socket
- `volatility -f <file> sockets`: exibe a lista de sockets
- `volatility -f <file> sockscan`: exibe a lista de sockets usando o scanner de socket

## Plugins úteis

- `volatility -f <file> malfind`: procura por malwares na memória
- `volatility -f <file> apihooks`: exibe a lista de ganchos de API instalados
- `volatility -f <file> svcscan`: exibe a lista de serviços em execução
- `volatility -f <file> getsids`: exibe a lista de SIDs de segurança
- `volatility -f <file> printkey`: exibe o conteúdo de uma chave de registro
- `volatility -f <file> dumpregistry`: cria um dump do registro do sistema
- `volatility -f <file> hivelist`: exibe a lista de arquivos de registro carregados
- `volatility -f <file> filescan`: exibe a lista de arquivos abertos
- `volatility -f <file> netscan`: exibe a lista de conexões de rede
- `volatility -f <file> connscan`: exibe a lista de conexões de rede
- `volatility -f <file> sockets`: exibe a lista de sockets

## Referências

- [https://github.com/volatilityfoundation/volatility/wiki/Command-Reference](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference)
- [https://github.com/volatilityfoundation/volatility/wiki/Plugins](https://github.com/volatilityfoundation/volatility/wiki/Plugins)
```bash
volatility --profile=Win7SP1x86_23418 getsids -f file.dmp #Get the SID owned by each process
volatility --profile=Win7SP1x86_23418 getservicesids -f file.dmp #Get the SID of each service
```
### Handles

Útil para saber a quais outros arquivos, chaves, threads, processos... um **processo tem um handle** (aberto).
```bash
vol.py -f file.dmp windows.handles.Handles [--pid <pid>]
```
{% endtab %}

{% tab title="volatility-cheatsheet" %}
# Folha de dicas do Volatility

## Comandos básicos

### Análise de imagem

- `volatility -f <file> imageinfo`: exibe informações sobre a imagem de memória
- `volatility -f <file> profileinfo`: exibe informações sobre o perfil da imagem de memória
- `volatility -f <file> pslist`: exibe a lista de processos em execução
- `volatility -f <file> pstree`: exibe a árvore de processos em execução
- `volatility -f <file> psscan`: exibe a lista de processos em execução usando o scanner de processo
- `volatility -f <file> dlllist -p <pid>`: exibe a lista de DLLs carregadas por um processo
- `volatility -f <file> filescan`: exibe a lista de arquivos abertos
- `volatility -f <file> netscan`: exibe a lista de conexões de rede
- `volatility -f <file> connections`: exibe a lista de conexões de rede usando o plugin `connections`
- `volatility -f <file> connscan`: exibe a lista de conexões de rede usando o scanner de conexão
- `volatility -f <file> cmdline -p <pid>`: exibe a linha de comando usada para iniciar um processo
- `volatility -f <file> consoles`: exibe a lista de consoles interativos
- `volatility -f <file> getsids`: exibe a lista de SIDs de segurança
- `volatility -f <file> hivelist`: exibe a lista de chaves do registro do Windows
- `volatility -f <file> printkey -K <key>`: exibe o conteúdo de uma chave do registro do Windows
- `volatility -f <file> dumpregistry -D <dir> -S <key>`: extrai uma subárvore do registro do Windows para um diretório

### Análise de processo

- `volatility -f <file> procdump -p <pid> -D <dir>`: cria um dump de memória de um processo
- `volatility -f <file> memdump -p <pid> -D <dir>`: cria um dump de memória de um processo usando o plugin `memdump`
- `volatility -f <file> memmap -p <pid>`: exibe o mapeamento de memória de um processo
- `volatility -f <file> memdump -p <pid> -D <dir> --dump-dir <dir>`: cria um dump de memória de um processo em um diretório específico
- `volatility -f <file> memdump -p <pid> -D <dir> --dump-dir <dir> --name <name>`: cria um dump de memória de um processo com um nome específico

### Análise de driver

- `volatility -f <file> modules`: exibe a lista de módulos do kernel
- `volatility -f <file> moddump -n <name> -D <dir>`: cria um dump de memória de um módulo do kernel
- `volatility -f <file> moddump -n <name> -D <dir> --dump-dir <dir>`: cria um dump de memória de um módulo do kernel em um diretório específico
- `volatility -f <file> moddump -n <name> -D <dir> --dump-dir <dir> --name <name>`: cria um dump de memória de um módulo do kernel com um nome específico

### Análise de sistema de arquivos

- `volatility -f <file> mftparser`: exibe a lista de entradas do MFT
- `volatility -f <file> mftparser -o <offset>`: exibe a entrada do MFT em um determinado deslocamento
- `volatility -f <file> filescan -S <offset>`: exibe informações sobre um arquivo em um determinado deslocamento
- `volatility -f <file> dumpfiles -Q <offset> -D <dir>`: extrai um arquivo em um determinado deslocamento para um diretório

### Análise de rede

- `volatility -f <file> connscan`: exibe a lista de conexões de rede
- `volatility -f <file> connscan -p <pid>`: exibe a lista de conexões de rede de um processo
- `volatility -f <file> connscan -s <src_ip>`: exibe a lista de conexões de rede de um endereço IP de origem
- `volatility -f <file> connscan -d <dst_ip>`: exibe a lista de conexões de rede de um endereço IP de destino
- `volatility -f <file> connscan -p <pid> -s <src_ip> -d <dst_ip>`: exibe a lista de conexões de rede de um processo com um endereço IP de origem e destino específicos

## Plugins adicionais

### Análise de processo

- `volatility -f <file> procdumpex -p <pid> -D <dir>`: cria um dump de memória de um processo, incluindo as regiões de memória desprotegidas
- `volatility -f <file> memdump -p <pid> -D <dir> --dump-dir <dir> --dump-privs`: cria um dump de memória de um processo, incluindo as chaves de registro e tokens de segurança
- `volatility -f <file> memdump -p <pid> -D <dir> --dump-dir <dir> --dump-privs --dump-dir-privs`: cria um dump de memória de um processo, incluindo as chaves de registro e tokens de segurança, e extrai os arquivos de diretórios protegidos

### Análise de driver

- `volatility -f <file> moddump -n <name> -D <dir> --dump-dir <dir> --dump-driver`: cria um dump de memória de um módulo do kernel, incluindo o arquivo do driver

### Análise de sistema de arquivos

- `volatility -f <file> filescan -F`: exibe informações sobre arquivos excluídos
- `volatility -f <file> dumpfiles -Q <offset> -D <dir> --dump-dir <dir> --dump-unallocated`: extrai um arquivo em um determinado deslocamento, incluindo o espaço não alocado

### Análise de rede

- `volatility -f <file> netscan -R <ip_range>`: exibe a lista de conexões de rede em um intervalo de endereços IP
- `volatility -f <file> netscan -r <ip_range>`: exibe a lista de conexões de rede em um intervalo de endereços IP, incluindo conexões fechadas

## Referências

- [Volatility Cheat Sheet](https://github.com/JamesHabben/volatility-cheatsheet) por James Habben
- [The Art of Memory Forensics](https://www.wiley.com/en-us/The+Art+of+Memory+Forensics%3A+Detecting+Malware+and+Threats+in+Windows%2C+Linux%2C+and+Mac+Memory-p-9781118825099) por Michael Hale Ligh, Andrew Case, Jamie Levy e Aaron Walters
- [Volatility Labs](https://www.volatilityfoundation.org/volatility-labs) por Volatility Foundation
{% endtab %}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp handles [--pid=<pid>]
```
### DLLs

{% tabs %}
{% tab title="vol3" %}
As DLLs são bibliotecas de vínculo dinâmico que contêm código e dados que podem ser usados por mais de um programa ao mesmo tempo. Eles são carregados na memória quando um programa que os usa é iniciado e permanecem lá até que o programa seja encerrado. DLLs podem ser usados para compartilhar código comum entre programas, reduzindo o tamanho do executável e melhorando a eficiência do sistema. No entanto, eles também podem ser usados para fins maliciosos, como injetar código em um processo em execução ou roubar informações confidenciais. O Volatility pode ser usado para analisar DLLs carregados na memória e identificar quais processos estão usando-os.
{% endtab %}
{% endtabs %}
```bash
./vol.py -f file.dmp windows.dlllist.DllList [--pid <pid>] #List dlls used by each
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --pid <pid> #Dump the .exe and dlls of the process in the current directory process
```
{% endtab %}

{% tab title="volatility-cheatsheet" %}
# Folha de dicas do Volatility

## Comandos básicos

### Análise de imagem

- `volatility -f <file> imageinfo`: exibe informações sobre a imagem de memória
- `volatility -f <file> kdbgscan`: procura pelo valor do depurador do kernel (KDBG) na imagem de memória
- `volatility -f <file> pslist`: lista os processos em execução na imagem de memória
- `volatility -f <file> psscan`: lista os processos em execução na imagem de memória (busca em todos os processos)
- `volatility -f <file> pstree`: exibe a árvore de processos na imagem de memória
- `volatility -f <file> dlllist -p <pid>`: lista as DLLs carregadas por um processo específico
- `volatility -f <file> filescan`: lista os arquivos abertos na imagem de memória
- `volatility -f <file> netscan`: lista as conexões de rede na imagem de memória
- `volatility -f <file> connections`: lista as conexões de rede na imagem de memória (versão mais recente do Volatility)
- `volatility -f <file> connscan`: lista as conexões de rede na imagem de memória (versão mais antiga do Volatility)
- `volatility -f <file> hivelist`: lista as chaves do registro presentes na imagem de memória
- `volatility -f <file> printkey -K <key>`: exibe o conteúdo de uma chave do registro na imagem de memória
- `volatility -f <file> hashdump -y <syskey> -s <system> -a <security>`: extrai hashes de senha da imagem de memória

### Análise de processo

- `volatility -f <file> memdump -p <pid> -D <output_directory>`: cria um dump de memória de um processo específico
- `volatility -f <file> procdump -p <pid> -D <output_directory>`: cria um dump de processo de um processo específico
- `volatility -f <file> malfind -p <pid> -D <output_directory>`: procura por código malicioso na memória de um processo específico
- `volatility -f <file> apihooks -p <pid>`: lista as funções do sistema que foram modificadas por um processo específico
- `volatility -f <file> vadinfo -p <pid>`: exibe informações sobre as regiões de memória alocadas por um processo específico
- `volatility -f <file> vadtree -p <pid>`: exibe a árvore de regiões de memória alocadas por um processo específico
- `volatility -f <file> vadwalk -p <pid> -s <start_address>`: exibe a árvore de regiões de memória alocadas por um processo específico, começando em um endereço específico
- `volatility -f <file> handles -p <pid>`: lista os handles abertos por um processo específico
- `volatility -f <file> mutantscan -p <pid>`: lista os objetos de mutex criados por um processo específico
- `volatility -f <file> thrdscan -p <pid>`: lista as threads criadas por um processo específico
- `volatility -f <file> callbacks -p <pid>`: lista os callbacks registrados por um processo específico
- `volatility -f <file> deskscan -p <pid>`: lista as janelas criadas por um processo específico

## Plugins adicionais

### Análise de malware

- `volatility -f <file> yarascan -Y <yara_rule_file>`: procura por padrões de YARA na imagem de memória
- `volatility -f <file> malfind`: procura por código malicioso na imagem de memória
- `volatility -f <file> malfind --dump-dir <output_directory>`: procura por código malicioso na imagem de memória e cria dumps dos arquivos encontrados
- `volatility -f <file> malfind --dump-dir <output_directory> --disassemble`: procura por código malicioso na imagem de memória, cria dumps dos arquivos encontrados e desmonta o código

### Análise de rede

- `volatility -f <file> connscan`: lista as conexões de rede na imagem de memória
- `volatility -f <file> netscan`: lista as conexões de rede na imagem de memória
- `volatility -f <file> sockets`: lista os sockets na imagem de memória
- `volatility -f <file> sockscan`: lista os sockets na imagem de memória

### Análise de registro

- `volatility -f <file> hivelist`: lista as chaves do registro presentes na imagem de memória
- `volatility -f <file> printkey -K <key>`: exibe o conteúdo de uma chave do registro na imagem de memória
- `volatility -f <file> printkey -K <key> --output-file <output_file>`: exibe o conteúdo de uma chave do registro na imagem de memória e salva em um arquivo
- `volatility -f <file> userassist`: lista as entradas do UserAssist na imagem de memória
- `volatility -f <file> shellbags`: lista as entradas do ShellBags na imagem de memória

### Análise de sistema de arquivos

- `volatility -f <file> filescan`: lista os arquivos abertos na imagem de memória
- `volatility -f <file> dumpfiles -Q <file_offset>`: extrai um arquivo da imagem de memória
- `volatility -f <file> dumpfiles -Q <file_offset> --dump-dir <output_directory>`: extrai um arquivo da imagem de memória e salva em um diretório
- `volatility -f <file> dumpfiles -Q <file_offset> --dump-dir <output_directory> --name <file_name>`: extrai um arquivo da imagem de memória, salva em um diretório e renomeia o arquivo
- `volatility -f <file> timeliner`: lista as atividades do sistema de arquivos na imagem de memória
- `volatility -f <file> timeliner --output-file <output_file>`: lista as atividades do sistema de arquivos na imagem de memória e salva em um arquivo

### Análise de virtualização

- `volatility -f <file> vboxinfo`: exibe informações sobre as máquinas virtuais do VirtualBox presentes na imagem de memória
- `volatility -f <file> vboxguestinfo -p <pid>`: exibe informações sobre o processo do VBoxGuest presente na imagem de memória
- `volatility -f <file> vboxsf`: lista os diretórios compartilhados do VirtualBox presentes na imagem de memória

### Análise de Android

- `volatility -f <file> androidinfo`: exibe informações sobre o dispositivo Android presente na imagem de memória
- `volatility -f <file> androiddump -n <name> -D <output_directory>`: cria um dump de memória de um processo específico do Android
- `volatility -f <file> androiddump --all -D <output_directory>`: cria dumps de memória de todos os processos do Android presentes na imagem de memória

## Referências

- [Volatility Cheat Sheet](https://github.com/JamesHabben/volatility-cheatsheet) por James Habben
- [Volatility Command Reference](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference) no GitHub do Volatility Foundation
{% endtab %}
```bash
volatility --profile=Win7SP1x86_23418 dlllist --pid=3152 -f file.dmp #Get dlls of a proc
volatility --profile=Win7SP1x86_23418 dlldump --pid=3152 --dump-dir=. -f file.dmp #Dump dlls of a proc
```
### Strings por processos

O Volatility permite verificar a qual processo uma string pertence.

{% tabs %}
{% tab title="vol3" %}
```bash
strings file.dmp > /tmp/strings.txt
./vol.py -f /tmp/file.dmp windows.strings.Strings --strings-file /tmp/strings.txt
```
{% endtab %}

{% tab title="volatility-cheatsheet.md" %}
# Folha de dicas do Volatility

## Comandos básicos

### Análise de imagem

- `volatility -f <file> imageinfo`: exibe informações sobre a imagem de memória
- `volatility -f <file> kdbgscan`: procura pelo valor do depurador do kernel (KDBG) na imagem de memória
- `volatility -f <file> pslist`: lista os processos em execução na imagem de memória
- `volatility -f <file> pstree`: exibe uma árvore de processos em execução na imagem de memória
- `volatility -f <file> psscan`: procura por processos na imagem de memória
- `volatility -f <file> dlllist -p <pid>`: lista as DLLs carregadas por um processo específico
- `volatility -f <file> filescan`: procura por arquivos abertos na imagem de memória
- `volatility -f <file> netscan`: procura por conexões de rede na imagem de memória
- `volatility -f <file> connections`: exibe informações sobre as conexões de rede na imagem de memória
- `volatility -f <file> connscan`: procura por conexões de rede na imagem de memória
- `volatility -f <file> hivelist`: lista as chaves do registro presentes na imagem de memória
- `volatility -f <file> printkey -K <key>`: exibe o conteúdo de uma chave do registro na imagem de memória
- `volatility -f <file> hashdump -y <offset>`: extrai hashes de senha da imagem de memória

### Análise de processo

- `volatility -f <file> memdump -p <pid> -D <output_directory>`: cria um dump de memória de um processo específico
- `volatility -f <file> procdump -p <pid> -D <output_directory>`: cria um dump de processo de um processo específico
- `volatility -f <file> malfind -p <pid> -D <output_directory>`: procura por código malicioso na memória de um processo específico
- `volatility -f <file> apihooks -p <pid>`: exibe informações sobre os ganchos de API em um processo específico
- `volatility -f <file> vadinfo -p <pid>`: exibe informações sobre as regiões de memória virtuais de um processo específico
- `volatility -f <file> vadtree -p <pid>`: exibe uma árvore das regiões de memória virtuais de um processo específico
- `volatility -f <file> handles -p <pid>`: lista os identificadores de objeto abertos por um processo específico
- `volatility -f <file> cmdscan -p <pid>`: procura por comandos executados por um processo específico
- `volatility -f <file> consoles -p <pid>`: exibe informações sobre as janelas do console de um processo específico
- `volatility -f <file> getsids -p <pid>`: exibe informações sobre os SIDs (identificadores de segurança) associados a um processo específico

## Plugins adicionais

### Análise de malware

- `volatility -f <file> yarascan -Y <rule_file>`: procura por padrões de YARA na imagem de memória
- `volatility -f <file> malfind`: procura por código malicioso na imagem de memória
- `volatility -f <file> malfind --dump-dir <output_directory>`: cria dumps de memória de regiões suspeitas encontradas pelo `malfind`
- `volatility -f <file> malfind --dump-dir <output_directory> --disassemble`: cria dumps de memória e desmonta o código de regiões suspeitas encontradas pelo `malfind`
- `volatility -f <file> malfind --dump-dir <output_directory> --disassemble --no-follow-jumps`: cria dumps de memória e desmonta o código de regiões suspeitas encontradas pelo `malfind`, sem seguir saltos

### Análise de rede

- `volatility -f <file> connscan`: procura por conexões de rede na imagem de memória
- `volatility -f <file> connscan --ip`: procura por conexões de rede na imagem de memória e exibe os endereços IP
- `volatility -f <file> connscan --ip --output-file <output_file>`: procura por conexões de rede na imagem de memória, exibe os endereços IP e salva a saída em um arquivo
- `volatility -f <file> connscan --ip --output-file <output_file> --output-format csv`: procura por conexões de rede na imagem de memória, exibe os endereços IP, salva a saída em um arquivo e usa o formato CSV

### Análise de registro

- `volatility -f <file> hivelist`: lista as chaves do registro presentes na imagem de memória
- `volatility -f <file> printkey -K <key>`: exibe o conteúdo de uma chave do registro na imagem de memória
- `volatility -f <file> printkey -K <key> --output-file <output_file>`: exibe o conteúdo de uma chave do registro na imagem de memória e salva a saída em um arquivo
- `volatility -f <file> printkey -K <key> --output-file <output_file> --output-format csv`: exibe o conteúdo de uma chave do registro na imagem de memória, salva a saída em um arquivo e usa o formato CSV

### Análise de sistema de arquivos

- `volatility -f <file> filescan`: procura por arquivos abertos na imagem de memória
- `volatility -f <file> filescan --name <file_name>`: procura por arquivos com um nome específico na imagem de memória
- `volatility -f <file> filescan --output-file <output_file>`: procura por arquivos abertos na imagem de memória e salva a saída em um arquivo
- `volatility -f <file> filescan --output-file <output_file> --output-format csv`: procura por arquivos abertos na imagem de memória, salva a saída em um arquivo e usa o formato CSV

### Análise de memória virtual

- `volatility -f <file> vadinfo`: exibe informações sobre as regiões de memória virtuais presentes na imagem de memória
- `volatility -f <file> vadinfo --output-file <output_file>`: exibe informações sobre as regiões de memória virtuais presentes na imagem de memória e salva a saída em um arquivo
- `volatility -f <file> vadinfo --output-file <output_file> --output-format csv`: exibe informações sobre as regiões de memória virtuais presentes na imagem de memória, salva a saída em um arquivo e usa o formato CSV

## Referências

- [Volatility Cheat Sheet](https://github.com/JamesHabben/volatility-cheatsheet) por James Habben
- [Volatility Command Reference](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference) no GitHub do Volatility Foundation
{% endtab %}
```bash
strings file.dmp > /tmp/strings.txt
volatility -f /tmp/file.dmp windows.strings.Strings --string-file /tmp/strings.txt

volatility -f /tmp/file.dmp --profile=Win81U1x64 memdump -p 3532 --dump-dir .
strings 3532.dmp > strings_file
```
{% endtab %}
{% tab title="volatility" %}
Também permite pesquisar por strings dentro de um processo usando o módulo yarascan:

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.vadyarascan.VadYaraScan --yara-rules "https://" --pid 3692 3840 3976 3312 3084 2784
./vol.py -f file.dmp yarascan.YaraScan --yara-rules "https://"
```
{% endtab %}

{% tab title="volatility-cheatsheet.md" %}
# Folha de dicas do Volatility

## Comandos básicos

### Análise de imagem

- `volatility -f <file> imageinfo`: exibe informações sobre a imagem de memória
- `volatility -f <file> kdbgscan`: procura pelo valor do depurador do kernel (KDBG) na imagem de memória
- `volatility -f <file> pslist`: lista os processos em execução na imagem de memória
- `volatility -f <file> pstree`: exibe uma árvore de processos em execução na imagem de memória
- `volatility -f <file> psscan`: procura por processos na imagem de memória
- `volatility -f <file> dlllist -p <pid>`: lista as DLLs carregadas por um processo específico
- `volatility -f <file> handles -p <pid>`: lista os identificadores de objeto abertos por um processo específico
- `volatility -f <file> filescan`: procura por arquivos na imagem de memória
- `volatility -f <file> netscan`: procura por conexões de rede na imagem de memória
- `volatility -f <file> connections`: exibe informações sobre as conexões de rede na imagem de memória
- `volatility -f <file> consoles`: lista as janelas de console abertas na imagem de memória
- `volatility -f <file> hivelist`: lista as chaves do registro presentes na imagem de memória
- `volatility -f <file> printkey -o <offset>`: exibe o conteúdo de uma chave do registro em um determinado deslocamento
- `volatility -f <file> dumpregistry -o <offset> -D <output_directory>`: extrai uma chave do registro em um determinado deslocamento para um diretório de saída
- `volatility -f <file> malfind`: procura por processos suspeitos na imagem de memória
- `volatility -f <file> apihooks`: exibe informações sobre os ganchos de API na imagem de memória
- `volatility -f <file> mutantscan`: procura por objetos de mutante na imagem de memória
- `volatility -f <file> svcscan`: lista os serviços em execução na imagem de memória
- `volatility -f <file> driverirp`: exibe informações sobre as solicitações de E/S (IRPs) de driver na imagem de memória
- `volatility -f <file> modscan`: lista os módulos carregados na imagem de memória
- `volatility -f <file> moddump -n <name> -D <output_directory>`: extrai um módulo específico para um diretório de saída
- `volatility -f <file> envars -p <pid>`: lista as variáveis de ambiente de um processo específico
- `volatility -f <file> cmdline -p <pid>`: exibe a linha de comando usada para iniciar um processo específico
- `volatility -f <file> consoles -p <pid>`: exibe informações sobre as janelas de console associadas a um processo específico
- `volatility -f <file> getsids`: lista os SIDs (identificadores de segurança) presentes na imagem de memória
- `volatility -f <file> getsid -o <offset>`: exibe informações sobre um SID em um determinado deslocamento
- `volatility -f <file> dumpfiles -Q <string> -D <output_directory>`: extrai arquivos que contenham uma determinada string para um diretório de saída
- `volatility -f <file> dumpfiles -S <start_address> -E <end_address> -D <output_directory>`: extrai arquivos que estejam dentro de um determinado intervalo de endereços para um diretório de saída

### Análise de processo

- `volatility -f <file> procdump -p <pid> -D <output_directory>`: extrai o espaço de endereço de um processo específico para um diretório de saída
- `volatility -f <file> memdump -p <pid> -D <output_directory>`: extrai o conteúdo da memória de um processo específico para um diretório de saída
- `volatility -f <file> memmap -p <pid>`: exibe informações sobre o espaço de endereço de um processo específico
- `volatility -f <file> vadinfo -p <pid>`: exibe informações sobre as regiões de memória alocadas para um processo específico
- `volatility -f <file> vadtree -p <pid>`: exibe uma árvore de regiões de memória alocadas para um processo específico
- `volatility -f <file> vadwalk -p <pid> -s <start_address>`: exibe informações sobre a região de memória que contém um determinado endereço em um processo específico
- `volatility -f <file> memdump -p <pid> -D <output_directory> --dump-dir <dump_directory>`: extrai o conteúdo da memória de um processo específico para um diretório de saída, com arquivos separados para cada região de memória

### Análise de sistema de arquivos

- `volatility -f <file> hivelist`: lista as chaves do registro presentes na imagem de memória
- `volatility -f <file> printkey -o <offset>`: exibe o conteúdo de uma chave do registro em um determinado deslocamento
- `volatility -f <file> dumpregistry -o <offset> -D <output_directory>`: extrai uma chave do registro em um determinado deslocamento para um diretório de saída
- `volatility -f <file> filescan`: procura por arquivos na imagem de memória
- `volatility -f <file> dumpfiles -Q <string> -D <output_directory>`: extrai arquivos que contenham uma determinada string para um diretório de saída
- `volatility -f <file> dumpfiles -S <start_address> -E <end_address> -D <output_directory>`: extrai arquivos que estejam dentro de um determinado intervalo de endereços para um diretório de saída

### Análise de rede

- `volatility -f <file> netscan`: procura por conexões de rede na imagem de memória
- `volatility -f <file> connections`: exibe informações sobre as conexões de rede na imagem de memória

## Plugins adicionais

### Dump de senhas

- `volatility -f <file> mimikatz`: extrai senhas da memória usando o plugin Mimikatz
- `volatility -f <file> mimikatz_command -m <module> <command>`: executa um comando do Mimikatz em um determinado módulo

### Análise de malware

- `volatility -f <file> malfind`: procura por processos suspeitos na imagem de memória
- `volatility -f <file> malprocfind`: procura por processos suspeitos na imagem de memória usando técnicas de detecção de malware
- `volatility -f <file> malfilter -D <output_directory>`: filtra processos suspeitos e extrai o conteúdo da memória para um diretório de saída
- `volatility -f <file> malfilter -p <pid> -D <output_directory>`: filtra um processo suspeito e extrai o conteúdo da memória para um diretório de saída

### Análise de rootkit

- `volatility -f <file> ldrmodules`: lista os módulos carregados na imagem de memória, incluindo os ocultos por rootkits
- `volatility -f <file> ldrmodules -p <pid>`: lista os módulos carregados por um processo específico, incluindo os ocultos por rootkits
- `volatility -f <file> apihooks`: exibe informações sobre os ganchos de API na imagem de memória, incluindo os instalados por rootkits
- `volatility -f <file> svcscan`: lista os serviços em execução na imagem de memória, incluindo os ocultos por rootkits
- `volatility -f <file> driverirp`: exibe informações sobre as solicitações de E/S (IRPs) de driver na imagem de memória, incluindo as manipuladas por rootkits

### Análise de virtualização

- `volatility -f <file> vboxinfo`: exibe informações sobre as máquinas virtuais do VirtualBox presentes na imagem de memória
- `volatility -f <file> vboxguestinfo -p <pid>`: exibe informações sobre o processo do Guest Additions do VirtualBox em um processo específico
- `volatility -f <file> vboxsf`: lista os compartilhamentos de pasta do VirtualBox presentes na imagem de memória
- `volatility -f <file> vmwareinfo`: exibe informações sobre as máquinas virtuais do VMware presentes na imagem de memória
- `volatility -f <file> vmwarecheck`: verifica se a imagem de memória é de uma máquina virtual do VMware
- `volatility -f <file> vmwareregistry`: exibe informações sobre o registro do VMware presente na imagem de memória

### Análise de sistema de arquivos

- `volatility -f <file> filescan`: procura por arquivos na imagem de memória
- `volatility -f <file> dumpfiles -Q <string> -D <output_directory>`: extrai arquivos que contenham uma determinada string para um diretório de saída
- `volatility -f <file> dumpfiles -S <start_address> -E <end_address> -D <output_directory>`: extrai arquivos que estejam dentro de um determinado intervalo de endereços para um diretório de saída
- `volatility -f <file> mftparser`: exibe informações sobre o Master File Table (MFT) do NTFS
- `volatility -f <file> usnjrnl`: exibe informações sobre o journal de alterações do NTFS
- `volatility -f <file> shimcache`: exibe informações sobre o cache de compatibilidade do Windows
- `volatility -f <file> printkey -K <key>`: exibe o conteúdo de uma chave do registro específica
- `volatility -f <file> dumpregistry -K <key> -D <output_directory>`: extrai uma chave do registro específica para um diretório de saída

### Análise de memória física

- `volatility -f <file> hibernateinfo`: exibe informações sobre o arquivo de hibernação do Windows
- `volatility -f <file> hiberfilscan`: procura por arquivos de hibernação na imagem de memória
- `volatility -f <file> windowspcap`: extrai pacotes de rede capturados pelo WinPcap
- `volatility -f <file> raw2dmp -i <input_file> -o <output_file>`: converte um arquivo de memória bruta em um arquivo de despejo de memória (DMP) do Windows

## Referências

- [Volatility Command Reference](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference)
```bash
volatility --profile=Win7SP1x86_23418 yarascan -Y "https://" -p 3692,3840,3976,3312,3084,2784
```
### UserAssist

Os sistemas **Windows** mantêm um conjunto de **chaves** no banco de dados do registro (**chaves UserAssist**) para acompanhar os programas que são executados. O número de execuções e a data e hora da última execução estão disponíveis nessas **chaves**.
```bash
./vol.py -f file.dmp windows.registry.userassist.UserAssist
```
{% endtab %}

{% tab title="volatility-cheatsheet" %}
# Folha de dicas do Volatility

## Comandos básicos

### Análise de imagem

- `volatility -f <file> imageinfo`: exibe informações sobre a imagem de memória
- `volatility -f <file> profileinfo`: exibe informações sobre o perfil da imagem de memória
- `volatility -f <file> pslist`: exibe a lista de processos em execução
- `volatility -f <file> pstree`: exibe a árvore de processos em execução
- `volatility -f <file> psscan`: exibe a lista de processos em execução usando o scanner de processo
- `volatility -f <file> dlllist -p <pid>`: exibe a lista de DLLs carregadas por um processo
- `volatility -f <file> handles -p <pid>`: exibe a lista de handles abertos por um processo
- `volatility -f <file> filescan`: exibe a lista de arquivos abertos
- `volatility -f <file> netscan`: exibe a lista de conexões de rede

### Análise de processo

- `volatility -f <file> procdump -p <pid> -D <output_directory>`: cria um dump de memória de um processo
- `volatility -f <file> memdump -p <pid> -D <output_directory>`: cria um dump de memória de um processo (alternativa ao procdump)
- `volatility -f <file> cmdline -p <pid>`: exibe a linha de comando usada para iniciar um processo
- `volatility -f <file> consoles -p <pid>`: exibe a lista de consoles usados por um processo
- `volatility -f <file> getsids -p <pid>`: exibe a lista de SIDs associados a um processo
- `volatility -f <file> malfind -p <pid> -D <output_directory>`: procura por código malicioso em um processo
- `volatility -f <file> apihooks -p <pid>`: exibe a lista de ganchos de API instalados em um processo
- `volatility -f <file> envars -p <pid>`: exibe a lista de variáveis de ambiente usadas por um processo

### Análise de sistema de arquivos

- `volatility -f <file> hivelist`: exibe a lista de arquivos de registro carregados
- `volatility -f <file> printkey -o <offset>`: exibe o conteúdo de uma chave de registro
- `volatility -f <file> filescan`: exibe a lista de arquivos abertos
- `volatility -f <file> dumpfiles -Q <path>`: extrai arquivos do sistema de arquivos

### Análise de rede

- `volatility -f <file> connscan`: exibe a lista de conexões de rede
- `volatility -f <file> sockets`: exibe a lista de sockets abertos

## Plugins adicionais

### Análise de malware

- `volatility -f <file> malfind`: procura por código malicioso em todos os processos
- `volatility -f <file> malprocfind`: procura por processos maliciosos
- `volatility -f <file> maldriverscan`: procura por drivers maliciosos
- `volatility -f <file> apihooks`: exibe a lista de ganchos de API instalados em todos os processos

### Análise de memória física

- `volatility -f <file> pagedump -o <offset> -D <output_directory>`: cria um dump de uma página física
- `volatility -f <file> physmap`: exibe o mapeamento de páginas físicas

### Análise de virtualização

- `volatility -f <file> vboxinfo`: exibe informações sobre máquinas virtuais VirtualBox
- `volatility -f <file> vboxguestinfo -p <pid>`: exibe informações sobre o processo do Guest Additions do VirtualBox
- `volatility -f <file> vmwareinfo`: exibe informações sobre máquinas virtuais VMware
- `volatility -f <file> vmwarecheck`: verifica se a imagem de memória é de uma máquina virtual VMware

### Análise de sistema de arquivos

- `volatility -f <file> lsmod`: exibe a lista de módulos do kernel carregados
- `volatility -f <file> moddump -n <name> -D <output_directory>`: cria um dump de um módulo do kernel
- `volatility -f <file> modscan`: exibe a lista de módulos do kernel carregados
- `volatility -f <file> printkey -K <key>`: exibe o conteúdo de uma chave de registro
- `volatility -f <file> printkey -K <key> -o <offset>`: exibe o conteúdo de uma chave de registro em um arquivo de registro específico

### Análise de rede

- `volatility -f <file> connscan`: exibe a lista de conexões de rede
- `volatility -f <file> sockets`: exibe a lista de sockets abertos
- `volatility -f <file> sockscan`: exibe a lista de sockets abertos usando o scanner de socket

## Referências

- [Volatility Cheat Sheet](https://github.com/JamesHabben/volatility-cheatsheet) por James Habben
- [Volatility Command Reference](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference) no wiki do Volatility Foundation
{% endtab %}
```
volatility --profile=Win7SP1x86_23418 -f file.dmp userassist
```
{% endtab %}
{% tab title="Português" %}
{% endtab %}
{% endtabs %}

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​[**RootedCON**](https://www.rootedcon.com/) é o evento de cibersegurança mais relevante na **Espanha** e um dos mais importantes na **Europa**. Com a missão de promover o conhecimento técnico, este congresso é um ponto de encontro fervilhante para profissionais de tecnologia e cibersegurança em todas as disciplinas.

{% embed url="https://www.rootedcon.com/" %}

## Serviços
```bash
./vol.py -f file.dmp windows.svcscan.SvcScan #List services
./vol.py -f file.dmp windows.getservicesids.GetServiceSIDs #Get the SID of services
```
{% endtab %}

{% tab title="volatility-cheatsheet" %}
# Folha de dicas do Volatility

## Comandos básicos

### Análise de imagem

- `volatility -f <file> imageinfo`: exibe informações sobre a imagem de memória
- `volatility -f <file> profileinfo`: exibe informações sobre o perfil da imagem de memória
- `volatility -f <file> pslist`: exibe a lista de processos em execução
- `volatility -f <file> pstree`: exibe a árvore de processos em execução
- `volatility -f <file> psscan`: exibe a lista de processos em execução usando o scanner de processo
- `volatility -f <file> dlllist -p <pid>`: exibe a lista de DLLs carregadas por um processo
- `volatility -f <file> handles -p <pid>`: exibe a lista de handles abertos por um processo
- `volatility -f <file> filescan`: exibe a lista de arquivos abertos
- `volatility -f <file> netscan`: exibe a lista de conexões de rede

### Análise de processo

- `volatility -f <file> procdump -p <pid> -D <output_directory>`: cria um dump de memória de um processo
- `volatility -f <file> memdump -p <pid> -D <output_directory>`: cria um dump de memória de um processo (alternativa ao procdump)
- `volatility -f <file> cmdline -p <pid>`: exibe a linha de comando usada para iniciar um processo
- `volatility -f <file> consoles -p <pid>`: exibe a lista de consoles usados por um processo
- `volatility -f <file> getsids -p <pid>`: exibe a lista de SIDs associados a um processo
- `volatility -f <file> malfind -p <pid> -D <output_directory>`: procura por código malicioso em um processo
- `volatility -f <file> apihooks -p <pid>`: exibe a lista de ganchos de API instalados em um processo
- `volatility -f <file> envars -p <pid>`: exibe a lista de variáveis de ambiente usadas por um processo

### Análise de sistema de arquivos

- `volatility -f <file> hivelist`: exibe a lista de arquivos de registro carregados
- `volatility -f <file> printkey -K <key>`: exibe o conteúdo de uma chave de registro
- `volatility -f <file> filescan`: exibe a lista de arquivos abertos
- `volatility -f <file> dumpfiles -Q <address_range> -D <output_directory>`: extrai arquivos da memória

### Análise de rede

- `volatility -f <file> connscan`: exibe a lista de conexões de rede
- `volatility -f <file> sockets`: exibe a lista de sockets abertos

## Plugins adicionais

### Análise de malware

- `volatility -f <file> malfind`: procura por código malicioso na imagem de memória
- `volatility -f <file> malprocfind`: procura por processos maliciosos na imagem de memória
- `volatility -f <file> maldriverscan`: procura por drivers maliciosos na imagem de memória
- `volatility -f <file> malfind`: procura por código malicioso na imagem de memória

### Análise de sistema de arquivos

- `volatility -f <file> timeliner`: exibe uma linha do tempo dos arquivos acessados
- `volatility -f <file> shellbags`: exibe a lista de pastas abertas recentemente
- `volatility -f <file> usnparser`: exibe a lista de entradas do USN Journal

### Análise de rede

- `volatility -f <file> connscan`: exibe a lista de conexões de rede
- `volatility -f <file> sockets`: exibe a lista de sockets abertos
- `volatility -f <file> connscan -s`: exibe a lista de conexões de rede ordenadas por tamanho de pacote

### Análise de memória

- `volatility -f <file> memmap`: exibe o mapa de memória
- `volatility -f <file> memdump`: cria um dump de memória da imagem de memória
- `volatility -f <file> memstrings`: procura por strings na imagem de memória
- `volatility -f <file> memdiff`: compara dois dumps de memória

### Análise de processo

- `volatility -f <file> procdump`: cria um dump de memória de um processo
- `volatility -f <file> memdump`: cria um dump de memória de um processo (alternativa ao procdump)
- `volatility -f <file> vadinfo -p <pid>`: exibe informações sobre as regiões de memória de um processo
- `volatility -f <file> vadtree -p <pid>`: exibe a árvore de regiões de memória de um processo
- `volatility -f <file> vadwalk -p <pid> -r <vaddr>`: exibe informações sobre uma região de memória específica de um processo
- `volatility -f <file> dlldump -p <pid> -b <base_address> -D <output_directory>`: cria um dump de uma DLL carregada por um processo
- `volatility -f <file> handles -p <pid>`: exibe a lista de handles abertos por um processo
- `volatility -f <file> deskscan`: exibe a lista de janelas abertas
- `volatility -f <file> deskview -D <output_directory>`: cria uma captura de tela da área de trabalho

### Análise de registro

- `volatility -f <file> hivelist`: exibe a lista de arquivos de registro carregados
- `volatility -f <file> printkey -K <key>`: exibe o conteúdo de uma chave de registro
- `volatility -f <file> printkey -K <key> -o <output_format>`: exibe o conteúdo de uma chave de registro em um formato específico (ex: csv, json)
- `volatility -f <file> hashdump -y <system_hive> -s <sam_hive> -o <output_file>`: extrai hashes de senha do SAM e do SYSTEM hives

### Análise de virtualização

- `volatility -f <file> vboxinfo`: exibe informações sobre as máquinas virtuais do VirtualBox
- `volatility -f <file> vboxguestinfo -p <pid>`: exibe informações sobre o processo do VBoxGuest
- `volatility -f <file> vboxsf`: exibe informações sobre os compartilhamentos do VirtualBox
- `volatility -f <file> vboxsfinfo -p <pid>`: exibe informações sobre o processo do VBoxSF

### Análise de criptografia

- `volatility -f <file> truecryptpassphrase`: exibe a senha usada para montar um volume TrueCrypt
- `volatility -f <file> bitlockerrecovery`: exibe a chave de recuperação do BitLocker

### Análise de sistema operacional

- `volatility -f <file> svcscan`: exibe a lista de serviços em execução
- `volatility -f <file> driverirp`: exibe a lista de IRPs (I/O Request Packets) de drivers
- `volatility -f <file> printd`: exibe a lista de impressoras instaladas
- `volatility -f <file> printd -u`: exibe a lista de trabalhos de impressão
- `volatility -f <file> printd -j <job_id>`: exibe informações sobre um trabalho de impressão específico
- `volatility -f <file> printd -s <printer_name>`: exibe informações sobre uma impressora específica

### Análise de memória de kernel

- `volatility -f <file> kdbgscan`: exibe a lista de depuradores do kernel
- `volatility -f <file> kpcrscan`: exibe a lista de KPCRs (Kernel Process Control Region)
- `volatility -f <file> kprocess`: exibe informações sobre um processo do kernel
- `volatility -f <file> kthread`: exibe informações sobre uma thread do kernel
- `volatility -f <file> modscan`: exibe a lista de módulos do kernel
- `volatility -f <file> moddump -b <base_address> -D <output_directory>`: cria um dump de um módulo do kernel
- `volatility -f <file> ssdt`: exibe a lista de funções do SSDT (System Service Descriptor Table)
- `volatility -f <file> idt`: exibe a lista de entradas da IDT (Interrupt Descriptor Table)
- `volatility -f <file> gdt`: exibe a lista de entradas da GDT (Global Descriptor Table)
- `volatility -f <file> ldrmodules`: exibe a lista de módulos carregados pelo LDR (Loader)
- `volatility -f <file> ldrmodules -p <pid>`: exibe a lista de módulos carregados por um processo específico
- `volatility -f <file> ldrmodules -s`: exibe a lista de módulos ordenados por tamanho

### Análise de memória física

- `volatility -f <file> hibernateinfo`: exibe informações sobre o arquivo de hibernação
- `volatility -f <file> hiberfilscan`: exibe a lista de processos encontrados no arquivo de hibernação
- `volatility -f <file> hibinfo`: exibe informações sobre o arquivo de hibernação
- `volatility -f <file> memdump`: cria um dump de memória da imagem de memória
- `volatility -f <file> memdump --dump-dir <output_directory> --physical`: cria um dump de memória física
- `volatility -f <file> memdump --dump-dir <output_directory> --profile <profile> --physical-offset <offset>`: cria um dump de memória física com um perfil e um offset específicos

## Referências

- [Volatility Cheat Sheet](https://github.com/JamesHabben/volatility-cheatsheet) por James Habben
- [Volatility Command Reference](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference) no GitHub
- [Volatility Documentation](https://github.com/volatilityfoundation/volatility/wiki) no GitHub
{% endtab %}
```bash
#Get services and binary path
volatility --profile=Win7SP1x86_23418 svcscan -f file.dmp
#Get name of the services and SID (slow)
volatility --profile=Win7SP1x86_23418 getservicesids -f file.dmp
```
## Rede

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.netscan.NetScan
#For network info of linux use volatility2
```
{% endtab %}

{% tab title="volatility-cheatsheet.md" %}
# Folha de dicas do Volatility

## Comandos básicos

### Análise de imagem

- `volatility -f <file> imageinfo`: exibe informações sobre a imagem de memória
- `volatility -f <file> kdbgscan`: procura pelo valor do depurador do kernel (KDBG) na imagem de memória
- `volatility -f <file> pslist`: lista os processos em execução na imagem de memória
- `volatility -f <file> pstree`: exibe a árvore de processos na imagem de memória
- `volatility -f <file> psscan`: procura por processos na imagem de memória
- `volatility -f <file> dlllist -p <pid>`: lista as DLLs carregadas por um processo específico
- `volatility -f <file> filescan`: procura por arquivos abertos na imagem de memória
- `volatility -f <file> netscan`: exibe informações sobre as conexões de rede na imagem de memória
- `volatility -f <file> connections`: exibe informações sobre as conexões de rede na imagem de memória (alternativa para o comando `netscan`)
- `volatility -f <file> connscan`: procura por conexões de rede na imagem de memória
- `volatility -f <file> hivelist`: lista as chaves do registro do Windows presentes na imagem de memória
- `volatility -f <file> printkey -K <key>`: exibe o conteúdo de uma chave do registro do Windows na imagem de memória
- `volatility -f <file> hashdump -y <offset>`: extrai hashes de senha do SAM (Security Account Manager) na imagem de memória

### Análise de processo

- `volatility -f <file> memdump -p <pid> -D <output_directory>`: cria um dump de memória para um processo específico
- `volatility -f <file> procdump -p <pid> -D <output_directory>`: cria um dump de memória para um processo específico (alternativa para o comando `memdump`)
- `volatility -f <file> malfind -p <pid> -D <output_directory>`: procura por código malicioso injetado em um processo específico
- `volatility -f <file> apihooks -p <pid>`: exibe informações sobre os hooks de API em um processo específico
- `volatility -f <file> cmdscan -p <pid>`: procura por comandos executados em um processo específico
- `volatility -f <file> consoles -p <pid>`: exibe informações sobre as janelas de console em um processo específico
- `volatility -f <file> getsids -p <pid>`: exibe informações sobre os SIDs (Security Identifiers) associados a um processo específico
- `volatility -f <file> handles -p <pid>`: exibe informações sobre os handles abertos por um processo específico
- `volatility -f <file> privs -p <pid>`: exibe informações sobre os privilégios de um processo específico
- `volatility -f <file> psxview`: exibe informações sobre os processos ocultos na imagem de memória

## Plugins adicionais

### Análise de malware

- `volatility -f <file> yarascan -Y <rule_file>`: procura por padrões de malware usando regras YARA
- `volatility -f <file> malfind`: procura por código malicioso injetado em processos
- `volatility -f <file> malprocfind`: procura por processos maliciosos na imagem de memória
- `volatility -f <file> malfind`: procura por arquivos maliciosos na imagem de memória

### Análise de rede

- `volatility -f <file> connscan`: procura por conexões de rede na imagem de memória
- `volatility -f <file> netscan`: exibe informações sobre as conexões de rede na imagem de memória
- `volatility -f <file> sockets`: exibe informações sobre os sockets na imagem de memória

### Análise de registro

- `volatility -f <file> hivelist`: lista as chaves do registro do Windows presentes na imagem de memória
- `volatility -f <file> printkey -K <key>`: exibe o conteúdo de uma chave do registro do Windows na imagem de memória
- `volatility -f <file> userassist`: exibe informações sobre os programas executados pelo usuário na imagem de memória
- `volatility -f <file> shellbags`: exibe informações sobre as pastas abertas pelo usuário na imagem de memória

### Análise de sistema de arquivos

- `volatility -f <file> filescan`: procura por arquivos abertos na imagem de memória
- `volatility -f <file> dumpfiles -Q <address>`: extrai um arquivo da imagem de memória
- `volatility -f <file> dumpfiles -Q <address> -D <output_directory>`: extrai um arquivo da imagem de memória para um diretório específico
- `volatility -f <file> mftparser`: exibe informações sobre o Master File Table (MFT) do sistema de arquivos NTFS
- `volatility -f <file> usnjrnl`: exibe informações sobre o journal de alterações do sistema de arquivos NTFS

### Análise de virtualização

- `volatility -f <file> vboxinfo`: exibe informações sobre as máquinas virtuais do VirtualBox presentes na imagem de memória
- `volatility -f <file> vboxguestinfo -p <pid>`: exibe informações sobre o processo do Guest Additions do VirtualBox em um processo específico
- `volatility -f <file> vmwareinfo`: exibe informações sobre as máquinas virtuais do VMware presentes na imagem de memória
- `volatility -f <file> vmwarecheck`: verifica se a imagem de memória é de uma máquina virtual do VMware

### Análise de memória física

- `volatility -f <file> hibernateinfo`: exibe informações sobre o arquivo de hibernação presente na imagem de memória
- `volatility -f <file> hiberfilscan`: procura por arquivos de hibernação na imagem de memória
- `volatility -f <file> windowspcap`: exibe informações sobre os pacotes capturados pelo driver WinPcap na imagem de memória

## Referências

- [Volatility Command Reference](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference)
```bash
volatility --profile=Win7SP1x86_23418 netscan -f file.dmp
volatility --profile=Win7SP1x86_23418 connections -f file.dmp#XP and 2003 only
volatility --profile=Win7SP1x86_23418 connscan -f file.dmp#TCP connections 
volatility --profile=Win7SP1x86_23418 sockscan -f file.dmp#Open sockets
volatility --profile=Win7SP1x86_23418 sockets -f file.dmp#Scanner for tcp socket objects

volatility --profile=SomeLinux -f file.dmp linux_ifconfig
volatility --profile=SomeLinux -f file.dmp linux_netstat
volatility --profile=SomeLinux -f file.dmp linux_netfilter
volatility --profile=SomeLinux -f file.dmp linux_arp #ARP table
volatility --profile=SomeLinux -f file.dmp linux_list_raw #Processes using promiscuous raw sockets (comm between processes)
volatility --profile=SomeLinux -f file.dmp linux_route_cache
```
## Registro do hive

### Imprimir hives disponíveis

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.registry.hivelist.HiveList #List roots
./vol.py -f file.dmp windows.registry.printkey.PrintKey #List roots and get initial subkeys
```
{% endtab %}

{% tab title="volatility-cheatsheet.md" %}
# Folha de dicas do Volatility

## Comandos básicos

### Análise de imagem

- `volatility -f <file> imageinfo`: exibe informações sobre a imagem de memória
- `volatility -f <file> kdbgscan`: procura pelo valor do depurador do kernel (KDBG) na imagem de memória
- `volatility -f <file> pslist`: lista os processos em execução na imagem de memória
- `volatility -f <file> pstree`: exibe uma árvore de processos em execução na imagem de memória
- `volatility -f <file> psscan`: procura por processos na imagem de memória
- `volatility -f <file> dlllist -p <pid>`: lista as DLLs carregadas por um processo específico
- `volatility -f <file> handles -p <pid>`: lista os identificadores de objeto abertos por um processo específico
- `volatility -f <file> filescan`: procura por arquivos na imagem de memória
- `volatility -f <file> netscan`: procura por conexões de rede na imagem de memória
- `volatility -f <file> connections`: exibe informações sobre as conexões de rede na imagem de memória
- `volatility -f <file> consoles`: exibe informações sobre as janelas do console na imagem de memória
- `volatility -f <file> printkey -K <key>`: exibe o conteúdo de uma chave do registro do Windows na imagem de memória
- `volatility -f <file> hivelist`: lista as chaves do registro do Windows na imagem de memória

### Análise de processo

- `volatility -f <file> procdump -p <pid> -D <output_directory>`: cria um despejo de memória para um processo específico
- `volatility -f <file> memdump -p <pid> -D <output_directory>`: cria um despejo de memória para um processo específico (alternativa ao `procdump`)
- `volatility -f <file> malfind -p <pid> -D <output_directory>`: procura por código malicioso em um processo específico
- `volatility -f <file> apihooks -p <pid>`: exibe informações sobre os ganchos de API em um processo específico
- `volatility -f <file> cmdscan -p <pid>`: procura por comandos executados em um processo específico
- `volatility -f <file> consoles -p <pid>`: exibe informações sobre as janelas do console em um processo específico
- `volatility -f <file> filescan -p <pid>`: procura por arquivos abertos por um processo específico
- `volatility -f <file> handles -p <pid>`: lista os identificadores de objeto abertos por um processo específico
- `volatility -f <file> privs -p <pid>`: lista os privilégios de um processo específico
- `volatility -f <file> psxview`: exibe informações sobre os processos ocultos na imagem de memória

### Análise de sistema de arquivos

- `volatility -f <file> hivelist`: lista as chaves do registro do Windows na imagem de memória
- `volatility -f <file> printkey -K <key>`: exibe o conteúdo de uma chave do registro do Windows na imagem de memória
- `volatility -f <file> filescan`: procura por arquivos na imagem de memória
- `volatility -f <file> dumpfiles -Q <address_range> -D <output_directory>`: extrai arquivos da imagem de memória
- `volatility -f <file> timeliner -f <image> -o <output_directory>`: cria uma linha do tempo dos arquivos modificados na imagem de memória

### Análise de rede

- `volatility -f <file> netscan`: procura por conexões de rede na imagem de memória
- `volatility -f <file> connections`: exibe informações sobre as conexões de rede na imagem de memória
- `volatility -f <file> connscan`: procura por conexões de rede na imagem de memória (alternativa ao `netscan`)
- `volatility -f <file> sockscan`: procura por sockets na imagem de memória

## Plugins adicionais

### Análise de malware

- `volatility -f <file> malfind`: procura por código malicioso na imagem de memória
- `volatility -f <file> malprocfind`: procura por processos maliciosos na imagem de memória
- `volatility -f <file> maldriverscan`: procura por drivers maliciosos na imagem de memória
- `volatility -f <file> apihooks`: exibe informações sobre os ganchos de API na imagem de memória
- `volatility -f <file> svcscan`: lista os serviços do Windows na imagem de memória
- `volatility -f <file> svcscan -t`: lista os serviços do Windows na imagem de memória (incluindo os serviços ocultos)
- `volatility -f <file> ldrmodules`: lista os módulos carregados na imagem de memória
- `volatility -f <file> ldrmodules -p <pid>`: lista os módulos carregados por um processo específico
- `volatility -f <file> modscan`: procura por módulos na imagem de memória
- `volatility -f <file> moddump -n <name> -D <output_directory>`: cria um despejo de memória para um módulo específico
- `volatility -f <file> moddump -m <base_address> -D <output_directory>`: cria um despejo de memória para um módulo específico
- `volatility -f <file> idt`: exibe informações sobre a tabela de interrupção do descritor na imagem de memória
- `volatility -f <file> gdt`: exibe informações sobre a tabela de descritor global na imagem de memória
- `volatility -f <file> ssdt`: exibe informações sobre a tabela de descritor de serviço do sistema na imagem de memória
- `volatility -f <file> callbacks`: exibe informações sobre os callbacks do kernel na imagem de memória
- `volatility -f <file> driverirp`: exibe informações sobre as solicitações de E/S do driver na imagem de memória
- `volatility -f <file> devicetree`: exibe informações sobre a árvore de dispositivos na imagem de memória
- `volatility -f <file> devicetree -t <type>`: exibe informações sobre a árvore de dispositivos de um tipo específico na imagem de memória
- `volatility -f <file> handles`: lista os identificadores de objeto abertos na imagem de memória
- `volatility -f <file> handles -t <type>`: lista os identificadores de objeto abertos de um tipo específico na imagem de memória
- `volatility -f <file> privs`: lista os privilégios na imagem de memória
- `volatility -f <file> privs -p <pid>`: lista os privilégios de um processo específico na imagem de memória
- `volatility -f <file> envars`: lista as variáveis de ambiente na imagem de memória
- `volatility -f <file> envars -p <pid>`: lista as variáveis de ambiente de um processo específico na imagem de memória
- `volatility -f <file> deskscan`: lista as janelas do desktop na imagem de memória
- `volatility -f <file> deskscan -p <pid>`: lista as janelas do desktop de um processo específico na imagem de memória
- `volatility -f <file> atomscan`: lista os átomos na imagem de memória
- `volatility -f <file> atomscan -p <pid>`: lista os átomos de um processo específico na imagem de memória
- `volatility -f <file> wndscan`: lista as janelas na imagem de memória
- `volatility -f <file> wndscan -p <pid>`: lista as janelas de um processo específico na imagem de memória

### Análise de sistema de arquivos

- `volatility -f <file> filescan`: procura por arquivos na imagem de memória
- `volatility -f <file> dumpfiles -Q <address_range> -D <output_directory>`: extrai arquivos da imagem de memória
- `volatility -f <file> timeliner -f <image> -o <output_directory>`: cria uma linha do tempo dos arquivos modificados na imagem de memória
- `volatility -f <file> shimcache`: exibe informações sobre o cache de compatibilidade do aplicativo na imagem de memória
- `volatility -f <file> usnjrnl`: exibe informações sobre o diário de alterações do NTFS na imagem de memória
- `volatility -f <file> usnjrnl -J <path>`: extrai o diário de alterações do NTFS da imagem de memória
- `volatility -f <file> mftparser`: exibe informações sobre a tabela de arquivos mestre (MFT) na imagem de memória
- `volatility -f <file> mftparser -o <output_directory>`: extrai a tabela de arquivos mestre (MFT) da imagem de memória
- `volatility -f <file> mftparser -u <inode>`: extrai um arquivo específico da tabela de arquivos mestre (MFT) na imagem de memória
- `volatility -f <file> mftparser --output-file=<output_file> -u <inode>`: extrai um arquivo específico da tabela de arquivos mestre (MFT) na imagem de memória e salva em um arquivo
- `volatility -f <file> shimcache`: exibe informações sobre o cache de compatibilidade do aplicativo na imagem de memória

### Análise de rede

- `volatility -f <file> netscan`: procura por conexões de rede na imagem de memória
- `volatility -f <file> connections`: exibe informações sobre as conexões de rede na imagem de memória
- `volatility -f <file> connscan`: procura por conexões de rede na imagem de memória (alternativa ao `netscan`)
- `volatility -f <file> sockscan`: procura por sockets na imagem de memória
- `volatility -f <file> sockscan -p <pid>`: procura por sockets em um processo específico na imagem de memória
- `volatility -f <file> sockscan -P <port>`: procura por sockets em uma porta específica na imagem de memória
- `volatility -f <file> sockscan -a`: exibe informações sobre todos os sockets na imagem de memória

## Referências

- [Volatility Documentation](https://github.com/volatilityfoundation/volatility/wiki)
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp hivelist #List roots
volatility --profile=Win7SP1x86_23418 -f file.dmp printkey #List roots and get initial subkeys
```
### Obter um valor

{% tabs %}
{% tab title="vol3" %}
Para obter um valor específico de um processo, você pode usar o comando `vol3 memdump -p <pid> --dump-dir <dir>`. Em seguida, você pode usar o comando `vol3 printkey -K <key> -o <output_file> <dump_file>` para imprimir o valor da chave especificada em um arquivo de saída. Por exemplo, para obter o valor da chave `ImageFile` do processo com PID 1234, você pode executar os seguintes comandos:

```
vol3 memdump -p 1234 --dump-dir /tmp/
vol3 printkey -K "ControlSet001\Services\MyService" -o /tmp/output.txt /tmp/memdump.1234
```

Isso imprimirá o valor da chave `ImageFile` do serviço `MyService` em um arquivo de saída em `/tmp/output.txt`.
{% endtab %}
{% endtabs %}
```bash
./vol.py -f file.dmp windows.registry.printkey.PrintKey --key "Software\Microsoft\Windows NT\CurrentVersion"
```
{% endtab %}

{% tab title="volatility-cheatsheet.md" %}
# Folha de dicas do Volatility

## Comandos básicos

### Análise de imagem

- `volatility -f <file> imageinfo`: exibe informações sobre a imagem de memória
- `volatility -f <file> kdbgscan`: procura pelo valor do depurador do kernel (KDBG) na imagem de memória
- `volatility -f <file> pslist`: lista os processos em execução na imagem de memória
- `volatility -f <file> pstree`: exibe uma árvore de processos em execução na imagem de memória
- `volatility -f <file> psscan`: procura por processos na imagem de memória
- `volatility -f <file> dlllist -p <pid>`: lista as DLLs carregadas por um processo específico
- `volatility -f <file> filescan`: procura por arquivos abertos na imagem de memória
- `volatility -f <file> netscan`: procura por conexões de rede na imagem de memória
- `volatility -f <file> connections`: exibe informações sobre as conexões de rede na imagem de memória
- `volatility -f <file> connscan`: procura por conexões de rede na imagem de memória
- `volatility -f <file> hivelist`: lista as chaves do registro presentes na imagem de memória
- `volatility -f <file> printkey -K <key>`: exibe o conteúdo de uma chave do registro na imagem de memória
- `volatility -f <file> hashdump -y <offset>`: extrai hashes de senha da imagem de memória

### Análise de processo

- `volatility -f <file> memdump -p <pid> -D <output_directory>`: cria um dump de memória de um processo específico
- `volatility -f <file> procdump -p <pid> -D <output_directory>`: cria um dump de processo de um processo específico
- `volatility -f <file> malfind -p <pid> -D <output_directory>`: procura por malwares na memória de um processo específico
- `volatility -f <file> apihooks -p <pid>`: exibe informações sobre os hooks de API em um processo específico
- `volatility -f <file> vadinfo -p <pid>`: exibe informações sobre as regiões de memória virtuais de um processo específico
- `volatility -f <file> vadtree -p <pid>`: exibe uma árvore das regiões de memória virtuais de um processo específico
- `volatility -f <file> vadwalk -p <pid> -v <start_address>`: exibe informações sobre a região de memória virtual que contém um endereço específico em um processo específico
- `volatility -f <file> handles -p <pid>`: exibe informações sobre os handles abertos por um processo específico
- `volatility -f <file> mutantscan -p <pid>`: procura por objetos de mutex em um processo específico
- `volatility -f <file> thrdscan -p <pid>`: exibe informações sobre as threads em um processo específico
- `volatility -f <file> callbacks -p <pid>`: exibe informações sobre os callbacks registrados por um processo específico
- `volatility -f <file> deskscan -p <pid>`: exibe informações sobre as janelas de desktop em um processo específico
- `volatility -f <file> getsids -p <pid>`: exibe informações sobre os SIDs associados a um processo específico

## Plugins adicionais

### Análise de malware

- `volatility -f <file> malfind`: procura por malwares na imagem de memória
- `volatility -f <file> malprocfind`: procura por processos maliciosos na imagem de memória
- `volatility -f <file> maldriverscan`: procura por drivers maliciosos na imagem de memória
- `volatility -f <file> apihooks`: exibe informações sobre os hooks de API na imagem de memória
- `volatility -f <file> svcscan`: exibe informações sobre os serviços na imagem de memória
- `volatility -f <file> svcscan -v`: exibe informações detalhadas sobre os serviços na imagem de memória
- `volatility -f <file> ldrmodules`: exibe informações sobre os módulos carregados na imagem de memória
- `volatility -f <file> ldrmodules -v`: exibe informações detalhadas sobre os módulos carregados na imagem de memória
- `volatility -f <file> modscan`: procura por módulos na imagem de memória
- `volatility -f <file> moddump -n <name> -D <output_directory>`: cria um dump de um módulo específico na imagem de memória
- `volatility -f <file> moddump -p <pid> -D <output_directory>`: cria um dump de todos os módulos carregados por um processo específico na imagem de memória
- `volatility -f <file> moddump -D <output_directory>`: cria um dump de todos os módulos carregados na imagem de memória
- `volatility -f <file> iehistory`: exibe o histórico de navegação do Internet Explorer na imagem de memória
- `volatility -f <file> chromehistory`: exibe o histórico de navegação do Google Chrome na imagem de memória
- `volatility -f <file> firefoxhistory`: exibe o histórico de navegação do Mozilla Firefox na imagem de memória

### Análise de rede

- `volatility -f <file> netscan`: procura por conexões de rede na imagem de memória
- `volatility -f <file> connscan`: procura por conexões de rede na imagem de memória
- `volatility -f <file> connscan -s`: exibe informações sobre as conexões de rede na imagem de memória
- `volatility -f <file> sockets`: exibe informações sobre os sockets na imagem de memória
- `volatility -f <file> sockscan`: procura por sockets na imagem de memória
- `volatility -f <file> sockscan -p <pid>`: procura por sockets abertos por um processo específico na imagem de memória
- `volatility -f <file> tcpvconnections`: exibe informações sobre as conexões TCP na imagem de memória
- `volatility -f <file> connscan -p <pid>`: exibe informações sobre as conexões de rede abertas por um processo específico na imagem de memória

### Análise de registro

- `volatility -f <file> hivelist`: lista as chaves do registro presentes na imagem de memória
- `volatility -f <file> printkey -K <key>`: exibe o conteúdo de uma chave do registro na imagem de memória
- `volatility -f <file> printkey -K <key> -o <offset>`: exibe o conteúdo de uma chave do registro em um determinado deslocamento na imagem de memória
- `volatility -f <file> userassist`: exibe informações sobre os programas executados pelo usuário na imagem de memória
- `volatility -f <file> userassist -o`: exibe informações detalhadas sobre os programas executados pelo usuário na imagem de memória
- `volatility -f <file> shellbags`: exibe informações sobre as pastas abertas recentemente na imagem de memória
- `volatility -f <file> shellbags -o`: exibe informações detalhadas sobre as pastas abertas recentemente na imagem de memória
- `volatility -f <file> shimcache`: exibe informações sobre os programas executados recentemente na imagem de memória
- `volatility -f <file> shimcache -o`: exibe informações detalhadas sobre os programas executados recentemente na imagem de memória

### Análise de virtualização

- `volatility -f <file> vboxinfo`: exibe informações sobre as máquinas virtuais do VirtualBox na imagem de memória
- `volatility -f <file> vboxguestinfo -p <pid>`: exibe informações sobre o processo do Guest Additions do VirtualBox em um processo específico na imagem de memória
- `volatility -f <file> vboxsf`: exibe informações sobre os compartilhamentos de pasta do VirtualBox na imagem de memória
- `volatility -f <file> vmwareinfo`: exibe informações sobre as máquinas virtuais do VMware na imagem de memória
- `volatility -f <file> vmwarecheck`: verifica se a imagem de memória é de uma máquina virtual do VMware
- `volatility -f <file> vmwareregistry`: exibe informações sobre o registro da máquina virtual do VMware na imagem de memória
- `volatility -f <file> xeninfo`: exibe informações sobre as máquinas virtuais do Xen na imagem de memória
- `volatility -f <file> xenstore`: exibe informações sobre o XenStore na imagem de memória

### Análise de sistema de arquivos

- `volatility -f <file> filescan`: procura por arquivos abertos na imagem de memória
- `volatility -f <file> filescan -S <string>`: procura por arquivos abertos que contenham uma determinada string no nome na imagem de memória
- `volatility -f <file> filescan -F <regex>`: procura por arquivos abertos que correspondam a uma determinada expressão regular no nome na imagem de memória
- `volatility -f <file> dumpfiles -Q <address>`: cria um dump de um arquivo específico na imagem de memória
- `volatility -f <file> dumpfiles -Q <address> -D <output_directory>`: cria um dump de um arquivo específico na imagem de memória em um diretório de saída específico
- `volatility -f <file> dumpfiles -r <range> -D <output_directory>`: cria dumps de todos os arquivos na imagem de memória dentro de um determinado intervalo de endereços em um diretório de saída específico
- `volatility -f <file> dumpfiles -S <string> -D <output_directory>`: cria dumps de todos os arquivos na imagem de memória que contenham uma determinada string no nome em um diretório de saída específico
- `volatility -f <file> dumpfiles -F <regex> -D <output_directory>`: cria dumps de todos os arquivos na imagem de memória que correspondam a uma determinada expressão regular no nome em um diretório de saída específico

### Análise de banco de dados

- `volatility -f <file> sqlite3`: exibe informações sobre bancos de dados SQLite na imagem de memória
- `volatility -f <file> sqlite3 -d <database>`: exibe informações sobre uma tabela específica em um banco de dados SQLite na imagem de memória
- `volatility -f <file> sqlite3 -d <database> -t <table>`: exibe o conteúdo de uma tabela específica em um banco de dados SQLite na imagem de memória

## Referências

- [Volatility Documentation](https://github.com/volatilityfoundation/volatility/wiki)
```bash
volatility --profile=Win7SP1x86_23418 printkey -K "Software\Microsoft\Windows NT\CurrentVersion" -f file.dmp
# Get Run binaries registry value
volatility -f file.dmp --profile=Win7SP1x86 printkey -o 0x9670e9d0 -K 'Software\Microsoft\Windows\CurrentVersion\Run'
```
### Despejo

Um dump é uma cópia do conteúdo da memória de um sistema em um determinado momento. Essa cópia pode ser usada para análise forense e investigação de incidentes de segurança. Existem várias ferramentas que podem ser usadas para criar dumps de memória, como o Volatility, o DumpIt e o FTK Imager.

### Volatility

O Volatility é uma ferramenta de análise de memória que pode ser usada para extrair informações valiosas de dumps de memória. Ele suporta vários sistemas operacionais, incluindo Windows, Linux e macOS. O Volatility pode ser usado para extrair informações como processos em execução, conexões de rede, arquivos abertos e chaves de registro.

### Análise de Dump

A análise de dump é o processo de examinar um dump de memória em busca de informações relevantes. Isso pode incluir a identificação de processos maliciosos em execução, a identificação de arquivos maliciosos carregados na memória e a identificação de conexões de rede suspeitas. A análise de dump pode ser realizada manualmente ou com o uso de ferramentas automatizadas, como o Volatility.
```bash
#Dump a hive
volatility --profile=Win7SP1x86_23418 hivedump -o 0x9aad6148 -f file.dmp #Offset extracted by hivelist
#Dump all hives
volatility --profile=Win7SP1x86_23418 hivedump -f file.dmp
```
## Sistema de arquivos

### Montagem

{% tabs %}
{% tab title="vol3" %}
```bash
#See vol2
```
{% endtab %}

{% tab title="volatility-cheatsheet.md" %}
# Folha de dicas do Volatility

## Comandos básicos

### Análise de imagem

- `volatility -f <file> imageinfo`: exibe informações sobre a imagem de memória
- `volatility -f <file> kdbgscan`: procura pelo valor do depurador do kernel (KDBG) na imagem de memória
- `volatility -f <file> pslist`: lista os processos em execução na imagem de memória
- `volatility -f <file> psscan`: lista os processos em execução na imagem de memória (busca em todos os processos)
- `volatility -f <file> pstree`: exibe a árvore de processos na imagem de memória
- `volatility -f <file> dlllist -p <pid>`: lista as DLLs carregadas por um processo específico
- `volatility -f <file> handles -p <pid>`: lista os handles abertos por um processo específico
- `volatility -f <file> filescan`: lista os arquivos abertos na imagem de memória
- `volatility -f <file> netscan`: lista as conexões de rede na imagem de memória
- `volatility -f <file> connections`: lista as conexões de rede na imagem de memória (versão mais recente do Volatility)
- `volatility -f <file> connscan`: lista as conexões de rede na imagem de memória (versão mais antiga do Volatility)
- `volatility -f <file> hivelist`: lista as chaves do registro presentes na imagem de memória
- `volatility -f <file> printkey -K <key>`: exibe o conteúdo de uma chave do registro na imagem de memória
- `volatility -f <file> malfind`: procura por malwares na imagem de memória
- `volatility -f <file> yarascan -Y <rule_file>`: procura por padrões específicos usando o Yara na imagem de memória

### Análise de processo

- `volatility -f <file> memdump -p <pid> -D <output_directory>`: cria um dump de memória de um processo específico
- `volatility -f <file> procdump -p <pid> -D <output_directory>`: cria um dump de processo de um processo específico
- `volatility -f <file> cmdline -p <pid>`: exibe a linha de comando usada para iniciar um processo específico
- `volatility -f <file> consoles -p <pid>`: exibe as janelas de console associadas a um processo específico
- `volatility -f <file> getsids -p <pid>`: exibe os SIDs associados a um processo específico
- `volatility -f <file> envars -p <pid>`: exibe as variáveis de ambiente de um processo específico
- `volatility -f <file> vadinfo -p <pid>`: exibe informações sobre as regiões de memória virtuais de um processo específico
- `volatility -f <file> vadtree -p <pid>`: exibe a árvore de regiões de memória virtuais de um processo específico
- `volatility -f <file> vadwalk -p <pid> -r <vaddr>`: exibe informações sobre uma região de memória virtual específica de um processo específico
- `volatility -f <file> memmap`: exibe as regiões de memória mapeadas na imagem de memória
- `volatility -f <file> memdump -p <pid> -r <vaddr> -D <output_directory>`: cria um dump de memória de uma região de memória virtual específica de um processo específico

### Análise de driver

- `volatility -f <file> driverscan`: lista os drivers carregados na imagem de memória
- `volatility -f <file> modules`: lista os módulos carregados na imagem de memória
- `volatility -f <file> modscan`: lista os módulos carregados na imagem de memória (busca em todos os processos)
- `volatility -f <file> moddump -n <module_name> -D <output_directory>`: cria um dump de um módulo específico

### Análise de sistema de arquivos

- `volatility -f <file> filescan`: lista os arquivos abertos na imagem de memória
- `volatility -f <file> dumpfiles -Q <file_path_regex> -D <output_directory>`: cria dumps de arquivos correspondentes a um padrão de caminho específico
- `volatility -f <file> dumpregistry -D <output_directory>`: cria dumps de todas as chaves do registro presentes na imagem de memória

### Análise de rede

- `volatility -f <file> netscan`: lista as conexões de rede na imagem de memória
- `volatility -f <file> connscan`: lista as conexões de rede na imagem de memória (versão mais antiga do Volatility)
- `volatility -f <file> connections`: lista as conexões de rede na imagem de memória (versão mais recente do Volatility)

## Plugins adicionais

### Malware

- `volatility -f <file> malfind`: procura por malwares na imagem de memória
- `volatility -f <file> malfind -Y <rule_file>`: procura por malwares na imagem de memória usando regras Yara
- `volatility -f <file> malfind -D <output_directory>`: cria dumps de arquivos maliciosos encontrados na imagem de memória
- `volatility -f <file> malfind -D <output_directory> -p <pid>`: cria dumps de arquivos maliciosos encontrados na memória de um processo específico

### Rootkits

- `volatility -f <file> ldrmodules`: lista os módulos carregados na imagem de memória (incluindo os ocultos por rootkits)
- `volatility -f <file> ldrmodules -p <pid>`: lista os módulos carregados na memória de um processo específico (incluindo os ocultos por rootkits)
- `volatility -f <file> apihooks`: lista as funções do sistema que foram modificadas por rootkits
- `volatility -f <file> svcscan`: lista os serviços do sistema (incluindo os ocultos por rootkits)
- `volatility -f <file> driverirp`: lista as IRPs (I/O Request Packets) manipuladas por drivers (incluindo as manipuladas por rootkits)

### Análise de memória física

- `volatility -f <file> hibernateinfo`: exibe informações sobre o arquivo de hibernação
- `volatility -f <file> hiberfilscan`: lista os processos presentes no arquivo de hibernação
- `volatility -f <file> hibinfo`: exibe informações sobre o arquivo de hibernação (versão mais recente do Volatility)
- `volatility -f <file> hiblist`: lista os processos presentes no arquivo de hibernação (versão mais recente do Volatility)
- `volatility -f <file> windows.hivelist`: lista as chaves do registro presentes no arquivo de hibernação
- `volatility -f <file> printkey -H <hiber_file_path> -K <key>`: exibe o conteúdo de uma chave do registro presente no arquivo de hibernação
- `volatility -f <file> memdump`: cria um dump de memória física
- `volatility -f <file> memdump --offset=<offset> --length=<length>`: cria um dump de memória física a partir de um offset e com um comprimento específicos

### Análise de memória virtual

- `volatility -f <file> vaddump -p <pid> -D <output_directory>`: cria um dump de memória virtual de um processo específico
- `volatility -f <file> vaddump -p <pid> -r <vaddr> -D <output_directory>`: cria um dump de uma região de memória virtual específica de um processo específico
- `volatility -f <file> vaddump --base=<base_address> --size=<size> -D <output_directory>`: cria um dump de uma região de memória virtual específica da imagem de memória

### Análise de sistema de arquivos

- `volatility -f <file> filescan`: lista os arquivos abertos na imagem de memória
- `volatility -f <file> dumpfiles -Q <file_path_regex> -D <output_directory>`: cria dumps de arquivos correspondentes a um padrão de caminho específico
- `volatility -f <file> dumpregistry -D <output_directory>`: cria dumps de todas as chaves do registro presentes na imagem de memória

### Análise de rede

- `volatility -f <file> netscan`: lista as conexões de rede na imagem de memória
- `volatility -f <file> connscan`: lista as conexões de rede na imagem de memória (versão mais antiga do Volatility)
- `volatility -f <file> connections`: lista as conexões de rede na imagem de memória (versão mais recente do Volatility)

## Referências

- [Volatility Cheat Sheet](https://github.com/JamesHabben/volatility-cheatsheet) por James Habben
- [Volatility Command Reference](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference) no GitHub do Volatility Foundation
- [The Art of Memory Forensics](https://www.wiley.com/en-us/The+Art+of+Memory+Forensics%3A+Detecting+Malware+and+Threats+in+Windows%2C+Linux%2C+and+Mac+Memory-p-9781118825099) por Michael Hale Ligh, Andrew Case, Jamie Levy e Aaron Walters
```bash
volatility --profile=SomeLinux -f file.dmp linux_mount
volatility --profile=SomeLinux -f file.dmp linux_recover_filesystem #Dump the entire filesystem (if possible)
```
### Escaneamento/despejo

{% tabs %}
{% tab title="vol3" %}
#### Escaneamento de processos em execução

- `volatility -f <dumpfile> --profile=<profile> pslist` - Lista todos os processos em execução.
- `volatility -f <dumpfile> --profile=<profile> psscan` - Escaneia a memória em busca de processos em execução.
- `volatility -f <dumpfile> --profile=<profile> pstree` - Mostra a árvore de processos em execução.
- `volatility -f <dumpfile> --profile=<profile> psxview` - Mostra informações adicionais sobre os processos em execução.

#### Escaneamento de DLLs

- `volatility -f <dumpfile> --profile=<profile> dlllist` - Lista todas as DLLs carregadas.
- `volatility -f <dumpfile> --profile=<profile> dlldump -D <dump_directory> -p <pid>` - Faz o despejo de uma DLL específica.

#### Escaneamento de sockets

- `volatility -f <dumpfile> --profile=<profile> netscan` - Lista todos os sockets abertos.
- `volatility -f <dumpfile> --profile=<profile> sockets` - Lista informações detalhadas sobre os sockets abertos.

#### Escaneamento de arquivos

- `volatility -f <dumpfile> --profile=<profile> filescan` - Escaneia a memória em busca de arquivos abertos.
- `volatility -f <dumpfile> --profile=<profile> dumpfiles -D <dump_directory> -Q <file_offset>` - Faz o despejo de um arquivo específico.

#### Escaneamento de registros

- `volatility -f <dumpfile> --profile=<profile> hivelist` - Lista todos os registros do sistema.
- `volatility -f <dumpfile> --profile=<profile> printkey -K <registry_key>` - Mostra o conteúdo de uma chave de registro específica.
- `volatility -f <dumpfile> --profile=<profile> dumpregistry -D <dump_directory> -K <registry_key>` - Faz o despejo de uma chave de registro específica.

#### Escaneamento de usuários

- `volatility -f <dumpfile> --profile=<profile> getsids` - Lista todos os SIDs (Security Identifiers) encontrados na memória.
- `volatility -f <dumpfile> --profile=<profile> getsid -U <user>` - Mostra o SID de um usuário específico.
- `volatility -f <dumpfile> --profile=<profile> getsid -S <sid>` - Mostra informações sobre um SID específico.
- `volatility -f <dumpfile> --profile=<profile> envars` - Lista todas as variáveis de ambiente encontradas na memória.
- `volatility -f <dumpfile> --profile=<profile> printkey -K "ControlSet001\Control\Terminal Server\WinStations\RDP-Tcp"` - Mostra as informações de configuração do RDP.
{% endtab %}
{% endtabs %}
```bash
./vol.py -f file.dmp windows.filescan.FileScan #Scan for files inside the dump
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --physaddr <0xAAAAA> #Offset from previous command
```
{% endtab %}

{% tab title="volatility-cheatsheet.md" %}
# Folha de dicas do Volatility

## Comandos básicos

### Análise de imagem

- `volatility -f <file> imageinfo`: exibe informações sobre a imagem de memória
- `volatility -f <file> kdbgscan`: procura pelo valor do depurador do kernel (KDBG) na imagem de memória
- `volatility -f <file> pslist`: lista os processos em execução na imagem de memória
- `volatility -f <file> pstree`: exibe uma árvore de processos em execução na imagem de memória
- `volatility -f <file> psscan`: procura por processos na imagem de memória
- `volatility -f <file> dlllist -p <pid>`: lista as DLLs carregadas por um processo específico
- `volatility -f <file> handles -p <pid>`: lista os identificadores de objeto abertos por um processo específico
- `volatility -f <file> filescan`: procura por arquivos na imagem de memória
- `volatility -f <file> netscan`: procura por conexões de rede na imagem de memória
- `volatility -f <file> connections`: exibe informações sobre as conexões de rede na imagem de memória
- `volatility -f <file> consoles`: exibe informações sobre as janelas do console na imagem de memória
- `volatility -f <file> printkey -K <key>`: exibe o conteúdo de uma chave do registro do Windows na imagem de memória
- `volatility -f <file> hivelist`: lista as chaves do registro do Windows na imagem de memória

### Análise de processo

- `volatility -f <file> procdump -p <pid> -D <output_directory>`: cria um despejo de memória para um processo específico
- `volatility -f <file> memdump -p <pid> -D <output_directory>`: cria um despejo de memória para um processo específico (alternativa ao `procdump`)
- `volatility -f <file> malfind -p <pid> -D <output_directory>`: procura por código malicioso na memória de um processo específico
- `volatility -f <file> apihooks -p <pid>`: exibe informações sobre os ganchos de API em um processo específico
- `volatility -f <file> vadinfo -p <pid>`: exibe informações sobre as regiões de memória virtuais de um processo específico
- `volatility -f <file> vadtree -p <pid>`: exibe uma árvore das regiões de memória virtuais de um processo específico
- `volatility -f <file> vadwalk -p <pid> -r <vaddr>`: exibe informações sobre uma região de memória virtual específica em um processo específico
- `volatility -f <file> memmap`: exibe informações sobre as regiões de memória físicas e virtuais na imagem de memória

### Análise de sistema de arquivos

- `volatility -f <file> hivelist`: lista as chaves do registro do Windows na imagem de memória
- `volatility -f <file> printkey -K <key>`: exibe o conteúdo de uma chave do registro do Windows na imagem de memória
- `volatility -f <file> filescan`: procura por arquivos na imagem de memória
- `volatility -f <file> dumpfiles -Q <address>`: extrai um arquivo da imagem de memória
- `volatility -f <file> dumpfiles -Q <address> -D <output_directory>`: extrai um arquivo da imagem de memória para um diretório específico
- `volatility -f <file> mftparser`: analisa a tabela de arquivos mestre (MFT) do sistema de arquivos NTFS
- `volatility -f <file> usnjrnl`: exibe informações sobre o diário de alterações do sistema de arquivos NTFS

### Análise de rede

- `volatility -f <file> netscan`: procura por conexões de rede na imagem de memória
- `volatility -f <file> connscan`: exibe informações sobre as conexões de rede na imagem de memória
- `volatility -f <file> sockets`: exibe informações sobre os sockets de rede na imagem de memória

## Plugins adicionais

### Malware

- `volatility -f <file> malfind`: procura por código malicioso na imagem de memória
- `volatility -f <file> malprocfind`: procura por processos maliciosos na imagem de memória
- `volatility -f <file> maldriverscan`: procura por drivers maliciosos na imagem de memória
- `volatility -f <file> apihooks`: exibe informações sobre os ganchos de API na imagem de memória

### Sistema de arquivos

- `volatility -f <file> mftparser`: analisa a tabela de arquivos mestre (MFT) do sistema de arquivos NTFS
- `volatility -f <file> usnjrnl`: exibe informações sobre o diário de alterações do sistema de arquivos NTFS
- `volatility -f <file> shimcache`: exibe informações sobre o cache de compatibilidade do aplicativo do Windows

### Registro do Windows

- `volatility -f <file> hivelist`: lista as chaves do registro do Windows na imagem de memória
- `volatility -f <file> printkey -K <key>`: exibe o conteúdo de uma chave do registro do Windows na imagem de memória
- `volatility -f <file> userassist`: exibe informações sobre os programas executados pelo usuário na imagem de memória
- `volatility -f <file> shellbags`: exibe informações sobre as pastas abertas recentemente na imagem de memória

### Processos

- `volatility -f <file> procdump`: cria um despejo de memória para um processo específico
- `volatility -f <file> memdump`: cria um despejo de memória para um processo específico (alternativa ao `procdump`)
- `volatility -f <file> malfind -p <pid>`: procura por código malicioso na memória de um processo específico
- `volatility -f <file> apihooks -p <pid>`: exibe informações sobre os ganchos de API em um processo específico
- `volatility -f <file> vadinfo -p <pid>`: exibe informações sobre as regiões de memória virtuais de um processo específico
- `volatility -f <file> vadtree -p <pid>`: exibe uma árvore das regiões de memória virtuais de um processo específico
- `volatility -f <file> vadwalk -p <pid> -r <vaddr>`: exibe informações sobre uma região de memória virtual específica em um processo específico

### Rede

- `volatility -f <file> netscan`: procura por conexões de rede na imagem de memória
- `volatility -f <file> connscan`: exibe informações sobre as conexões de rede na imagem de memória
- `volatility -f <file> sockets`: exibe informações sobre os sockets de rede na imagem de memória

## Referências

- [Volatility Cheat Sheet](https://github.com/JamesHabben/volatility-cheatsheet) por James Habben
- [The Art of Memory Forensics: Detecting Malware and Threats in Windows, Linux, and Mac Memory](https://www.wiley.com/en-us/The+Art+of+Memory+Forensics%3A+Detecting+Malware+and+Threats+in+Windows%2C+Linux%2C+and+Mac+Memory-p-9781118825099) por Michael Hale Ligh, Andrew Case, Jamie Levy e Aaron Walters
```bash
volatility --profile=Win7SP1x86_23418 filescan -f file.dmp #Scan for files inside the dump
volatility --profile=Win7SP1x86_23418 dumpfiles -n --dump-dir=/tmp -f file.dmp #Dump all files
volatility --profile=Win7SP1x86_23418 dumpfiles -n --dump-dir=/tmp -Q 0x000000007dcaa620 -f file.dmp

volatility --profile=SomeLinux -f file.dmp linux_enumerate_files
volatility --profile=SomeLinux -f file.dmp linux_find_file -F /path/to/file
volatility --profile=SomeLinux -f file.dmp linux_find_file -i 0xINODENUMBER -O /path/to/dump/file
```
### Tabela de Arquivos Mestre

{% tabs %}
{% tab title="vol3" %}
```bash
# I couldn't find any plugin to extract this information in volatility3
```
{% endtab %}

{% tab title="volatility-cheatsheet.md" %}
# Folha de dicas do Volatility

## Comandos básicos

### Análise de imagem

- `volatility -f <file> imageinfo`: exibe informações sobre a imagem de memória
- `volatility -f <file> kdbgscan`: procura pelo valor do depurador do kernel (KDBG) na imagem de memória
- `volatility -f <file> pslist`: lista os processos em execução na imagem de memória
- `volatility -f <file> pstree`: exibe uma árvore de processos em execução na imagem de memória
- `volatility -f <file> psscan`: procura por processos na imagem de memória
- `volatility -f <file> dlllist -p <pid>`: lista as DLLs carregadas por um processo específico
- `volatility -f <file> filescan`: procura por arquivos abertos na imagem de memória
- `volatility -f <file> netscan`: procura por conexões de rede na imagem de memória
- `volatility -f <file> connections`: exibe informações sobre as conexões de rede na imagem de memória
- `volatility -f <file> connscan`: procura por conexões de rede na imagem de memória
- `volatility -f <file> hivelist`: lista as chaves do registro presentes na imagem de memória
- `volatility -f <file> printkey -K <key>`: exibe o conteúdo de uma chave do registro na imagem de memória
- `volatility -f <file> hashdump -y <offset>`: extrai hashes de senha da imagem de memória

### Análise de processo

- `volatility -f <file> memdump -p <pid> -D <output_directory>`: cria um dump de memória de um processo específico
- `volatility -f <file> procdump -p <pid> -D <output_directory>`: cria um dump de processo de um processo específico
- `volatility -f <file> malfind -p <pid> -D <output_directory>`: procura por código malicioso na memória de um processo específico
- `volatility -f <file> apihooks -p <pid>`: exibe informações sobre os hooks de API em um processo específico
- `volatility -f <file> vadinfo -p <pid>`: exibe informações sobre as regiões de memória virtuais de um processo específico
- `volatility -f <file> vadtree -p <pid>`: exibe uma árvore das regiões de memória virtuais de um processo específico
- `volatility -f <file> vadwalk -p <pid> -v <start_address>`: exibe informações sobre a região de memória virtual que contém um endereço específico em um processo específico
- `volatility -f <file> handles -p <pid>`: exibe informações sobre os handles abertos por um processo específico
- `volatility -f <file> mutantscan -p <pid>`: procura por objetos de mutex na memória de um processo específico
- `volatility -f <file> thrdscan -p <pid>`: procura por threads na memória de um processo específico
- `volatility -f <file> callbacks -p <pid>`: exibe informações sobre os callbacks registrados por um processo específico
- `volatility -f <file> deskscan -p <pid>`: procura por objetos de desktop na memória de um processo específico
- `volatility -f <file> getsids -p <pid>`: exibe informações sobre os SIDs associados a um processo específico
- `volatility -f <file> envars -p <pid>`: exibe as variáveis de ambiente definidas para um processo específico
- `volatility -f <file> modscan -p <pid>`: procura por módulos carregados na memória de um processo específico
- `volatility -f <file> moddump -p <pid> -D <output_directory>`: cria um dump de um módulo específico em um processo específico

## Plugins adicionais

### Análise de malware

- `volatility -f <file> yarascan -Y <rule_file>`: procura por padrões de YARA na imagem de memória
- `volatility -f <file> malfind`: procura por código malicioso na imagem de memória
- `volatility -f <file> malprocfind`: procura por processos maliciosos na imagem de memória
- `volatility -f <file> malfind`: procura por código malicioso na imagem de memória

### Análise de rede

- `volatility -f <file> connscan`: procura por conexões de rede na imagem de memória
- `volatility -f <file> netscan`: procura por conexões de rede na imagem de memória
- `volatility -f <file> sockets`: exibe informações sobre os sockets na imagem de memória
- `volatility -f <file> sockscan`: procura por sockets na imagem de memória

### Análise de registro

- `volatility -f <file> hivelist`: lista as chaves do registro presentes na imagem de memória
- `volatility -f <file> printkey -K <key>`: exibe o conteúdo de uma chave do registro na imagem de memória
- `volatility -f <file> userassist`: exibe informações sobre as entradas do UserAssist na imagem de memória
- `volatility -f <file> shellbags`: exibe informações sobre as entradas do ShellBags na imagem de memória

### Análise de sistema de arquivos

- `volatility -f <file> filescan`: procura por arquivos abertos na imagem de memória
- `volatility -f <file> dumpfiles -Q <file_path> -D <output_directory>`: extrai um arquivo específico da imagem de memória
- `volatility -f <file> dumpfiles -Q <file_path> -D <output_directory> --dump-dir <output_directory>`: extrai um arquivo específico da imagem de memória e salva em um diretório específico
- `volatility -f <file> mftparser`: exibe informações sobre o Master File Table (MFT) na imagem de memória
- `volatility -f <file> usnjrnl`: exibe informações sobre o USN Journal na imagem de memória

### Análise de virtualização

- `volatility -f <file> vboxinfo`: exibe informações sobre as máquinas virtuais do VirtualBox na imagem de memória
- `volatility -f <file> vboxguestinfo -p <pid>`: exibe informações sobre o processo do Guest Additions do VirtualBox em um processo específico
- `volatility -f <file> vmwareinfo`: exibe informações sobre as máquinas virtuais do VMware na imagem de memória
- `volatility -f <file> vmwarecheck`: verifica se a imagem de memória é de uma máquina virtual do VMware
- `volatility -f <file> vmitracer -p <pid>`: exibe informações sobre as operações de E/S realizadas por um processo específico em uma máquina virtual

### Análise de criptografia

- `volatility -f <file> truecryptpassphrase`: exibe senhas do TrueCrypt presentes na imagem de memória
- `volatility -f <file> bitlockerrecovery`: exibe informações sobre chaves de recuperação do BitLocker presentes na imagem de memória

### Análise de memória física

- `volatility -f <file> hibernateinfo`: exibe informações sobre o arquivo de hibernação usado para criar a imagem de memória
- `volatility -f <file> windowspagefileinfo`: exibe informações sobre o arquivo de paginação usado para criar a imagem de memória
- `volatility -f <file> memmap`: exibe informações sobre o mapa de memória física da imagem de memória
- `volatility -f <file> crashinfo`: exibe informações sobre um arquivo de despejo de memória criado após uma falha do sistema

## Referências

- [Volatility Documentation](https://github.com/volatilityfoundation/volatility/wiki)
```bash
volatility --profile=Win7SP1x86_23418 mftparser -f file.dmp
```
{% endtab %}
{% tab title="volatility" %}
O sistema de arquivos NTFS contém um arquivo chamado _master file table_, ou MFT. Existe pelo menos uma entrada no MFT para cada arquivo em um volume do sistema de arquivos NTFS, incluindo o próprio MFT. **Todas as informações sobre um arquivo, incluindo seu tamanho, carimbos de data e hora, permissões e conteúdo de dados**, são armazenadas em entradas MFT ou em espaço fora do MFT que é descrito por entradas MFT. De [aqui](https://docs.microsoft.com/en-us/windows/win32/fileio/master-file-table).

### Chaves/Certificados SSL
```bash
#vol3 allows to search for certificates inside the registry
./vol.py -f file.dmp windows.registry.certificates.Certificates
```
{% endtab %}

{% tab title="volatility-cheatsheet.md" %}
# Folha de dicas do Volatility

## Comandos básicos

### Análise de imagem

- `volatility -f <file> imageinfo`: exibe informações sobre a imagem de memória
- `volatility -f <file> kdbgscan`: procura pelo valor do depurador do kernel (KDBG) na imagem de memória
- `volatility -f <file> pslist`: lista os processos em execução na imagem de memória
- `volatility -f <file> pstree`: exibe a árvore de processos na imagem de memória
- `volatility -f <file> psscan`: procura por processos na imagem de memória
- `volatility -f <file> dlllist -p <pid>`: lista as DLLs carregadas por um processo específico
- `volatility -f <file> filescan`: procura por arquivos abertos na imagem de memória
- `volatility -f <file> netscan`: exibe informações sobre as conexões de rede na imagem de memória
- `volatility -f <file> connections`: exibe informações sobre as conexões de rede na imagem de memória (alternativa para o comando `netscan`)
- `volatility -f <file> connscan`: procura por conexões de rede na imagem de memória
- `volatility -f <file> hivelist`: lista as chaves do registro do Windows presentes na imagem de memória
- `volatility -f <file> printkey -o <offset>`: exibe o conteúdo de uma chave do registro do Windows em um determinado deslocamento
- `volatility -f <file> hashdump -y <offset>`: extrai as hashes de senha do SAM (Security Account Manager) do registro do Windows em um determinado deslocamento
- `volatility -f <file> malfind`: procura por processos suspeitos na imagem de memória
- `volatility -f <file> apihooks`: exibe informações sobre os ganchos de API na imagem de memória
- `volatility -f <file> getsids`: exibe informações sobre os SIDs (Security Identifiers) presentes na imagem de memória
- `volatility -f <file> getservicesids`: exibe informações sobre os SIDs (Security Identifiers) associados aos serviços presentes na imagem de memória
- `volatility -f <file> envars -p <pid>`: exibe as variáveis de ambiente de um processo específico
- `volatility -f <file> consoles`: exibe informações sobre as janelas do console na imagem de memória
- `volatility -f <file> consoles -p <pid>`: exibe informações sobre a janela do console de um processo específico

### Análise de processo

- `volatility -f <file> memdump -p <pid> -D <output_directory>`: cria um dump da memória de um processo específico
- `volatility -f <file> procdump -p <pid> -D <output_directory>`: cria um dump do processo e de sua memória virtual
- `volatility -f <file> vadinfo -p <pid>`: exibe informações sobre as regiões de memória virtuais de um processo específico
- `volatility -f <file> vadtree -p <pid>`: exibe a árvore de regiões de memória virtuais de um processo específico
- `volatility -f <file> vadwalk -p <pid> -s <start_address>`: exibe a árvore de regiões de memória virtuais de um processo específico a partir de um determinado endereço
- `volatility -f <file> memmap -p <pid>`: exibe informações sobre as regiões de memória físicas de um processo específico
- `volatility -f <file> memdump -p <pid> -D <output_directory>`: cria um dump da memória de um processo específico
- `volatility -f <file> memdump -p <pid> -r <range_start>..<range_end> -D <output_directory>`: cria um dump da memória de um processo específico em um determinado intervalo de endereços
- `volatility -f <file> memstrings -p <pid> -s <minimum_length>`: procura por strings na memória de um processo específico com um comprimento mínimo especificado
- `volatility -f <file> memdump --dump-dir <output_directory> --pid <pid>`: cria um dump da memória de um processo específico (alternativa para o comando `memdump -p <pid> -D <output_directory>`)

### Análise de driver

- `volatility -f <file> driverscan`: procura por drivers na imagem de memória
- `volatility -f <file> modules`: lista os módulos carregados na imagem de memória
- `volatility -f <file> modscan`: procura por módulos na imagem de memória
- `volatility -f <file> moddump -n <module_name> -D <output_directory>`: cria um dump do código de um módulo específico

### Análise de sistema de arquivos

- `volatility -f <file> hivelist`: lista as chaves do registro do Windows presentes na imagem de memória
- `volatility -f <file> printkey -o <offset>`: exibe o conteúdo de uma chave do registro do Windows em um determinado deslocamento
- `volatility -f <file> filescan`: procura por arquivos abertos na imagem de memória
- `volatility -f <file> dumpfiles -Q <file_path> -D <output_directory>`: cria um dump de um arquivo específico

### Análise de rede

- `volatility -f <file> netscan`: exibe informações sobre as conexões de rede na imagem de memória
- `volatility -f <file> connections`: exibe informações sobre as conexões de rede na imagem de memória (alternativa para o comando `netscan`)
- `volatility -f <file> connscan`: procura por conexões de rede na imagem de memória

### Análise de virtualização

- `volatility -f <file> vboxinfo`: exibe informações sobre as máquinas virtuais do VirtualBox presentes na imagem de memória
- `volatility -f <file> vboxguestinfo -p <pid>`: exibe informações sobre o processo do VBoxGuest presente na imagem de memória
- `volatility -f <file> vboxsf`: exibe informações sobre os compartilhamentos de arquivos do VirtualBox presentes na imagem de memória

## Plugins adicionais

### Análise de malware

- `volatility -f <file> malfind`: procura por processos suspeitos na imagem de memória
- `volatility -f <file> malprocfind`: procura por processos suspeitos na imagem de memória usando técnicas de detecção de malware
- `volatility -f <file> malfind`: procura por arquivos suspeitos na imagem de memória
- `volatility -f <file> malsysproc`: exibe informações sobre processos suspeitos na imagem de memória
- `volatility -f <file> malthfind`: procura por manipuladores de arquivos suspeitos na imagem de memória
- `volatility -f <file> malfind`: procura por processos suspeitos na imagem de memória

### Análise de sistema de arquivos

- `volatility -f <file> shimcache`: exibe informações sobre as entradas do cache de compatibilidade do aplicativo (AppCompat) presentes na imagem de memória
- `volatility -f <file> usnjrnl`: exibe informações sobre o diário de alterações do NTFS (USN Journal) presentes na imagem de memória
- `volatility -f <file> usnjrnl -o <offset>`: exibe informações sobre o diário de alterações do NTFS (USN Journal) em um determinado deslocamento
- `volatility -f <file> mftparser`: exibe informações sobre a tabela de arquivos mestre (MFT) do NTFS presentes na imagem de memória
- `volatility -f <file> mftparser -o <offset>`: exibe informações sobre a tabela de arquivos mestre (MFT) do NTFS em um determinado deslocamento
- `volatility -f <file> mftparser --output-file <output_file>`: extrai a tabela de arquivos mestre (MFT) do NTFS para um arquivo
- `volatility -f <file> mftparser --output-file <output_file> -o <offset>`: extrai a tabela de arquivos mestre (MFT) do NTFS em um determinado deslocamento para um arquivo
- `volatility -f <file> filescan`: procura por arquivos abertos na imagem de memória
- `volatility -f <file> dumpfiles -Q <file_path> -D <output_directory>`: cria um dump de um arquivo específico

### Análise de rede

- `volatility -f <file> connscan`: procura por conexões de rede na imagem de memória
- `volatility -f <file> connscan --pids=<pid_list>`: procura por conexões de rede na imagem de memória associadas a uma lista de PIDs
- `volatility -f <file> connscan --ip=<ip_address>`: procura por conexões de rede na imagem de memória associadas a um endereço IP
- `volatility -f <file> connscan --ip=<ip_address> --pids=<pid_list>`: procura por conexões de rede na imagem de memória associadas a um endereço IP e a uma lista de PIDs

### Análise de virtualização

- `volatility -f <file> vboxinfo`: exibe informações sobre as máquinas virtuais do VirtualBox presentes na imagem de memória
- `volatility -f <file> vboxguestinfo -p <pid>`: exibe informações sobre o processo do VBoxGuest presente na imagem de memória
- `volatility -f <file> vboxsf`: exibe informações sobre os compartilhamentos de arquivos do VirtualBox presentes na imagem de memória

## Referências

- [Volatility Cheat Sheet](https://github.com/JamesHabben/volatility-cheatsheet) por James Habben
- [Volatility Command Reference](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference) no GitHub
- [The Art of Memory Forensics: Detecting Malware and Threats in Windows, Linux, and Mac Memory](https://www.wiley.com/en-us/The+Art+of+Memory+Forensics%3A+Detecting+Malware+and+Threats+in+Windows%2C+Linux%2C+and+Mac+Memory-p-9781118824993) por Michael Hale Ligh, Andrew Case, Jamie Levy e Aaron Walters
```bash
#vol2 allos you to search and dump certificates from memory
#Interesting options for this modules are: --pid, --name, --ssl
volatility --profile=Win7SP1x86_23418 dumpcerts --dump-dir=. -f file.dmp
```
## Malware

{% tabs %}
{% tab title="vol3" %}
### Introdução

O Volatility pode ser usado para analisar memórias de sistemas infectados por malware. A análise de memória pode ajudar a identificar processos maliciosos em execução, arquivos maliciosos carregados na memória e outras atividades suspeitas.

### Comandos Úteis

- `malprocfind`: Encontra processos maliciosos na memória.
- `malfind`: Encontra arquivos maliciosos carregados na memória.
- `malstack`: Exibe a pilha de chamadas de um processo malicioso.
- `malhunt`: Encontra processos maliciosos com base em padrões de comportamento.
- `malfind`: Encontra arquivos maliciosos carregados na memória.
- `malfind`: Encontra arquivos maliciosos carregados na memória.

### Exemplo de Uso

```
$ volatility -f memdump.mem malprocfind
```

Este comando irá procurar por processos maliciosos na memória do arquivo `memdump.mem`.

```
$ volatility -f memdump.mem malfind
```

Este comando irá procurar por arquivos maliciosos carregados na memória do arquivo `memdump.mem`.
{% endtab %}
{% endtabs %}
```bash
./vol.py -f file.dmp windows.malfind.Malfind [--dump] #Find hidden and injected code, [dump each suspicious section]
#Malfind will search for suspicious structures related to malware
./vol.py -f file.dmp windows.driverirp.DriverIrp #Driver IRP hook detection
./vol.py -f file.dmp windows.ssdt.SSDT #Check system call address from unexpected addresses

./vol.py -f file.dmp linux.check_afinfo.Check_afinfo #Verifies the operation function pointers of network protocols
./vol.py -f file.dmp linux.check_creds.Check_creds #Checks if any processes are sharing credential structures
./vol.py -f file.dmp linux.check_idt.Check_idt #Checks if the IDT has been altered
./vol.py -f file.dmp linux.check_syscall.Check_syscall #Check system call table for hooks
./vol.py -f file.dmp linux.check_modules.Check_modules #Compares module list to sysfs info, if available
./vol.py -f file.dmp linux.tty_check.tty_check #Checks tty devices for hooks
```
{% endtab %}

{% tab title="volatility-cheatsheet.md" %}
# Folha de dicas do Volatility

## Comandos básicos

### Análise de imagem

- `volatility -f <file> imageinfo`: exibe informações sobre a imagem de memória
- `volatility -f <file> kdbgscan`: procura pelo valor do depurador do kernel (KDBG) na imagem de memória
- `volatility -f <file> pslist`: lista os processos em execução na imagem de memória
- `volatility -f <file> psscan`: lista os processos em execução na imagem de memória (busca em todos os processos)
- `volatility -f <file> pstree`: exibe a árvore de processos na imagem de memória
- `volatility -f <file> dlllist -p <pid>`: lista as DLLs carregadas por um processo específico
- `volatility -f <file> handles -p <pid>`: lista os handles abertos por um processo específico
- `volatility -f <file> filescan`: lista os arquivos abertos na imagem de memória
- `volatility -f <file> netscan`: lista as conexões de rede na imagem de memória
- `volatility -f <file> connscan`: lista as conexões de rede na imagem de memória (busca em todos os processos)
- `volatility -f <file> hivelist`: lista os arquivos de registro na imagem de memória
- `volatility -f <file> printkey -K <key>`: exibe o conteúdo de uma chave de registro específica
- `volatility -f <file> dumpregistry -D <output_directory> -K <key>`: extrai uma chave de registro específica para um diretório de saída

### Análise de processo

- `volatility -f <file> memdump -p <pid> -D <output_directory>`: extrai o espaço de endereço virtual de um processo específico para um diretório de saída
- `volatility -f <file> procdump -p <pid> -D <output_directory>`: extrai o arquivo executável de um processo específico para um diretório de saída
- `volatility -f <file> malfind -p <pid> -D <output_directory>`: procura por código malicioso injetado em um processo específico e extrai para um diretório de saída

### Análise de sistema de arquivos

- `volatility -f <file> filescan`: lista os arquivos abertos na imagem de memória
- `volatility -f <file> dumpfiles -D <output_directory> --name <filename>`: extrai um arquivo específico para um diretório de saída
- `volatility -f <file> dumpfiles -D <output_directory> --unlinked`: extrai todos os arquivos desvinculados para um diretório de saída

### Análise de rede

- `volatility -f <file> connscan`: lista as conexões de rede na imagem de memória (busca em todos os processos)
- `volatility -f <file> netscan`: lista as conexões de rede na imagem de memória

## Plugins adicionais

### Dump de senhas

- `volatility -f <file> mimikatz`: extrai senhas da memória usando o plugin Mimikatz

### Análise de navegador

- `volatility -f <file> chromehistory`: exibe o histórico de navegação do Google Chrome
- `volatility -f <file> chromecookies`: exibe os cookies do Google Chrome
- `volatility -f <file> iehistory`: exibe o histórico de navegação do Internet Explorer
- `volatility -f <file> iecookies`: exibe os cookies do Internet Explorer
- `volatility -f <file> firefoxhistory`: exibe o histórico de navegação do Mozilla Firefox
- `volatility -f <file> firefoxcookies`: exibe os cookies do Mozilla Firefox

### Análise de malware

- `volatility -f <file> malfind`: procura por código malicioso injetado em processos e extrai para um diretório de saída
- `volatility -f <file> malprocfind`: procura por processos maliciosos e exibe informações sobre eles
- `volatility -f <file> apihooks`: exibe informações sobre ganchos de API em processos
- `volatility -f <file> ldrmodules`: exibe informações sobre módulos carregados em processos
- `volatility -f <file> svcscan`: exibe informações sobre serviços do Windows na imagem de memória

### Análise de rootkit

- `volatility -f <file> autoruns`: exibe informações sobre programas que são executados automaticamente na inicialização do sistema
- `volatility -f <file> driverirp`: exibe informações sobre IRPs (pacotes de solicitação de E/S) em drivers
- `volatility -f <file> idt`: exibe informações sobre a tabela de interrupções do sistema
- `volatility -f <file> ssdt`: exibe informações sobre a tabela de serviços do sistema
- `volatility -f <file> callbacks`: exibe informações sobre os callbacks do kernel

### Análise de memória física

- `volatility -f <file> hibernateinfo`: exibe informações sobre o arquivo de hibernação
- `volatility -f <file> hiberfilscan`: lista os processos encontrados no arquivo de hibernação
- `volatility -f <file> memmap`: exibe informações sobre o mapa de memória física
- `volatility -f <file> crashinfo`: exibe informações sobre um arquivo de despejo de memória física

## Referências

- [Volatility Cheat Sheet](https://github.com/JamesHabben/volatility-cheatsheet) por James Habben
- [The Art of Memory Forensics: Detecting Malware and Threats in Windows, Linux, and Mac Memory](https://www.amazon.com/Art-Memory-Forensics-Detecting-Malware/dp/1118825098) por Michael Hale Ligh, Andrew Case, Jamie Levy e Aaron Walters
{% endtab %}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp malfind [-D /tmp] #Find hidden and injected code [dump each suspicious section]
volatility --profile=Win7SP1x86_23418 -f file.dmp apihooks #Detect API hooks in process and kernel memory
volatility --profile=Win7SP1x86_23418 -f file.dmp driverirp #Driver IRP hook detection
volatility --profile=Win7SP1x86_23418 -f file.dmp ssdt #Check system call address from unexpected addresses

volatility --profile=SomeLinux -f file.dmp linux_check_afinfo
volatility --profile=SomeLinux -f file.dmp linux_check_creds
volatility --profile=SomeLinux -f file.dmp linux_check_fop
volatility --profile=SomeLinux -f file.dmp linux_check_idt
volatility --profile=SomeLinux -f file.dmp linux_check_syscall
volatility --profile=SomeLinux -f file.dmp linux_check_modules
volatility --profile=SomeLinux -f file.dmp linux_check_tty
volatility --profile=SomeLinux -f file.dmp linux_keyboard_notifiers #Keyloggers
```
{% endtab %}
{% tab title="Português" %}
### Escaneando com yara

Use este script para baixar e mesclar todas as regras de malware yara do github: [https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9](https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9)\
Crie o diretório _**rules**_ e execute-o. Isso criará um arquivo chamado _**malware\_rules.yar**_ que contém todas as regras yara para malware.
```bash
wget https://gist.githubusercontent.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9/raw/4ec711d37f1b428b63bed1f786b26a0654aa2f31/malware_yara_rules.py
mkdir rules
python malware_yara_rules.py
#Only Windows
./vol.py -f file.dmp windows.vadyarascan.VadYaraScan --yara-file /tmp/malware_rules.yar
#All
./vol.py -f file.dmp yarascan.YaraScan --yara-file /tmp/malware_rules.yar
```
{% endtab %}

{% tab title="volatility-cheatsheet" %}
# Folha de dicas do Volatility

## Comandos básicos

### Análise de imagem

- `volatility -f <file> imageinfo`: exibe informações sobre a imagem de memória
- `volatility -f <file> profileinfo`: exibe informações sobre o perfil da imagem de memória
- `volatility -f <file> pslist`: exibe a lista de processos em execução
- `volatility -f <file> pstree`: exibe a árvore de processos em execução
- `volatility -f <file> psscan`: exibe a lista de processos em execução usando o scanner de processo
- `volatility -f <file> dlllist -p <pid>`: exibe a lista de DLLs carregadas por um processo
- `volatility -f <file> handles -p <pid>`: exibe a lista de handles abertos por um processo
- `volatility -f <file> filescan`: exibe a lista de arquivos abertos
- `volatility -f <file> netscan`: exibe a lista de conexões de rede

### Análise de processo

- `volatility -f <file> procdump -p <pid> -D <output_directory>`: cria um dump de memória de um processo
- `volatility -f <file> memdump -p <pid> -D <output_directory>`: cria um dump de memória de um processo (alternativa ao procdump)
- `volatility -f <file> cmdline -p <pid>`: exibe a linha de comando usada para iniciar um processo
- `volatility -f <file> consoles -p <pid>`: exibe a lista de consoles usados por um processo
- `volatility -f <file> getsids -p <pid>`: exibe a lista de SIDs associados a um processo
- `volatility -f <file> malfind -p <pid> -D <output_directory>`: procura por código malicioso em um processo
- `volatility -f <file> apihooks -p <pid>`: exibe a lista de ganchos de API instalados em um processo
- `volatility -f <file> envars -p <pid>`: exibe a lista de variáveis de ambiente usadas por um processo

### Análise de sistema de arquivos

- `volatility -f <file> hivelist`: exibe a lista de arquivos de registro carregados
- `volatility -f <file> printkey -o <offset>`: exibe o conteúdo de uma chave de registro
- `volatility -f <file> filescan`: exibe a lista de arquivos abertos
- `volatility -f <file> dumpfiles -Q <path>`: extrai arquivos do sistema de arquivos

### Análise de rede

- `volatility -f <file> connscan`: exibe a lista de conexões de rede
- `volatility -f <file> sockets`: exibe a lista de sockets abertos

## Plugins adicionais

### Análise de malware

- `volatility -f <file> malfind`: procura por código malicioso em todos os processos
- `volatility -f <file> malprocfind`: procura por processos maliciosos
- `volatility -f <file> maldriverscan`: procura por drivers maliciosos
- `volatility -f <file> apihooks`: exibe a lista de ganchos de API instalados em todos os processos

### Análise de memória física

- `volatility -f <file> pagedump -o <offset> -D <output_directory>`: cria um dump de uma página física
- `volatility -f <file> physmap`: exibe o mapeamento de páginas físicas

### Análise de virtualização

- `volatility -f <file> vboxinfo`: exibe informações sobre máquinas virtuais VirtualBox
- `volatility -f <file> vboxguestinfo -p <pid>`: exibe informações sobre o processo do Guest Additions do VirtualBox
- `volatility -f <file> vmwareinfo`: exibe informações sobre máquinas virtuais VMware
- `volatility -f <file> vmwarecheck`: verifica se a imagem de memória é de uma máquina virtual VMware

### Análise de sistema de arquivos

- `volatility -f <file> lsmod`: exibe a lista de módulos do kernel carregados
- `volatility -f <file> moddump -n <name> -D <output_directory>`: cria um dump de um módulo do kernel
- `volatility -f <file> modscan`: exibe a lista de módulos do kernel carregados
- `volatility -f <file> printkey -K <key>`: exibe o conteúdo de uma chave de registro
- `volatility -f <file> printkey -K <key> -o <offset>`: exibe o conteúdo de uma chave de registro em um arquivo de registro específico

### Análise de rede

- `volatility -f <file> connscan`: exibe a lista de conexões de rede
- `volatility -f <file> sockets`: exibe a lista de sockets abertos
- `volatility -f <file> sockscan`: exibe a lista de sockets abertos usando o scanner de socket

## Referências

- [Volatility Cheat Sheet](https://github.com/JamesHabben/volatility-cheatsheet) por James Habben
- [Volatility Command Reference](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference) no wiki do Volatility Foundation
{% endtab %}
```bash
wget https://gist.githubusercontent.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9/raw/4ec711d37f1b428b63bed1f786b26a0654aa2f31/malware_yara_rules.py
mkdir rules
python malware_yara_rules.py
volatility --profile=Win7SP1x86_23418 yarascan -y malware_rules.yar -f ch2.dmp | grep "Rule:" | grep -v "Str_Win32" | sort | uniq
```
## METODOLOGIA BÁSICA DE ANÁLISE DE DUMP DE MEMÓRIA

### CHEAT SHEET DO VOLATILITY

#### COMANDOS BÁSICOS

- `volatility -f <dump> imageinfo`: exibe informações sobre o dump de memória.
- `volatility -f <dump> pslist`: exibe a lista de processos em execução.
- `volatility -f <dump> pstree`: exibe a árvore de processos em execução.
- `volatility -f <dump> psscan`: exibe a lista de processos em execução, incluindo processos ocultos.
- `volatility -f <dump> netscan`: exibe a lista de conexões de rede.
- `volatility -f <dump> connscan`: exibe a lista de conexões de rede com detalhes adicionais.
- `volatility -f <dump> filescan`: exibe a lista de arquivos abertos.
- `volatility -f <dump> hivelist`: exibe a lista de chaves do registro.
- `volatility -f <dump> hivedump -o <offset> -f <output>`: extrai uma chave do registro.
- `volatility -f <dump> hashdump -y <system hive> -s <security hive>`: exibe as hashes de senha do sistema e do registro de segurança.
- `volatility -f <dump> malfind`: procura por processos maliciosos.
- `volatility -f <dump> apihooks`: exibe a lista de ganchos de API.
- `volatility -f <dump> ldrmodules`: exibe a lista de módulos carregados.
- `volatility -f <dump> modscan`: exibe a lista de módulos carregados com detalhes adicionais.
- `volatility -f <dump> getsids`: exibe a lista de SIDs.
- `volatility -f <dump> getservicesids`: exibe a lista de SIDs de serviços.
- `volatility -f <dump> dumpfiles -Q <PID> -D <output>`: extrai os arquivos abertos por um processo.
- `volatility -f <dump> memdump -p <PID> -D <output>`: extrai o dump de memória de um processo.

#### PLUGINS

- `volatility -f <dump> <plugin>`: executa um plugin específico.
- `volatility --info | grep <plugin>`: exibe informações sobre um plugin específico.
- `volatility --plugins=<path>`: especifica o caminho para os plugins.
- `volatility --plugins=<path> -f <dump> <plugin>`: executa um plugin específico com plugins externos.

#### OUTROS

- `volatility --profile=<profile> -f <dump> <plugin>`: especifica o perfil do sistema.
- `volatility --kdbg=<address> -f <dump> <plugin>`: especifica o endereço do depurador do kernel.
- `volatility --dtb=<address> -f <dump> <plugin>`: especifica o endereço da tabela de páginas do diretório.
- `volatility --physical-offset=<offset> -f <dump> <plugin>`: especifica o deslocamento físico do dump de memória.
- `volatility --output-file=<output> -f <dump> <plugin>`: especifica o arquivo de saída.
- `volatility --output=dot -f <dump> <plugin>`: exibe a saída em formato DOT.
- `volatility --output=html -f <dump> <plugin>`: exibe a saída em formato HTML.
- `volatility --output=json -f <dump> <plugin>`: exibe a saída em formato JSON.
- `volatility --output=sqlite -f <dump> <plugin>`: exibe a saída em formato SQLite.
- `volatility --output=txt -f <dump> <plugin>`: exibe a saída em formato texto.
- `volatility --output=yaml -f <dump> <plugin>`: exibe a saída em formato YAML.

#### PLUGINS EXTERNOS

Se você deseja usar plugins externos, certifique-se de que as pastas relacionadas aos plugins sejam o primeiro parâmetro usado.
```bash
./vol.py --plugin-dirs "/tmp/plugins/" [...]
```
{% endtab %}

{% tab title="volatility-cheatsheet.md" %}
# Folha de dicas do Volatility

## Comandos básicos

### Análise de imagem

- `volatility -f <file> imageinfo`: exibe informações sobre a imagem de memória
- `volatility -f <file> kdbgscan`: procura pelo valor do depurador do kernel (KDBG) na imagem de memória
- `volatility -f <file> pslist`: lista os processos em execução na imagem de memória
- `volatility -f <file> psscan`: lista os processos em execução na imagem de memória (busca em todos os processos)
- `volatility -f <file> pstree`: exibe a árvore de processos na imagem de memória
- `volatility -f <file> dlllist -p <pid>`: lista as DLLs carregadas por um processo específico
- `volatility -f <file> handles -p <pid>`: lista os handles abertos por um processo específico
- `volatility -f <file> filescan`: lista os arquivos abertos na imagem de memória
- `volatility -f <file> netscan`: lista as conexões de rede na imagem de memória
- `volatility -f <file> connscan`: lista as conexões de rede na imagem de memória (busca em todos os processos)
- `volatility -f <file> hivelist`: lista os arquivos de registro na imagem de memória
- `volatility -f <file> printkey -K <key>`: exibe o conteúdo de uma chave de registro específica
- `volatility -f <file> dumpregistry -D <output_directory> -K <key>`: extrai uma chave de registro específica para um diretório de saída

### Análise de processo

- `volatility -f <file> memdump -p <pid> -D <output_directory>`: extrai o espaço de endereço virtual de um processo específico para um diretório de saída
- `volatility -f <file> procdump -p <pid> -D <output_directory>`: extrai o arquivo executável de um processo específico para um diretório de saída
- `volatility -f <file> malfind -p <pid> -D <output_directory>`: procura por código malicioso na memória de um processo específico e extrai-o para um diretório de saída

### Análise de sistema de arquivos

- `volatility -f <file> hivelist`: lista os arquivos de registro na imagem de memória
- `volatility -f <file> printkey -K <key>`: exibe o conteúdo de uma chave de registro específica
- `volatility -f <file> dumpregistry -D <output_directory> -K <key>`: extrai uma chave de registro específica para um diretório de saída
- `volatility -f <file> filescan`: lista os arquivos abertos na imagem de memória
- `volatility -f <file> dumpfiles -D <output_directory> --name <filename>`: extrai um arquivo específico para um diretório de saída

### Outros comandos úteis

- `volatility -f <file> hashdump -y <profile>`: extrai as hashes de senha da imagem de memória
- `volatility -f <file> truecryptpassphrase`: extrai a senha do TrueCrypt da imagem de memória
- `volatility -f <file> clipboard`: exibe o conteúdo da área de transferência da imagem de memória
- `volatility -f <file> shellbags`: exibe as informações de shellbags da imagem de memória

## Plugins adicionais

### Malware

- `volatility -f <file> malfind`: procura por código malicioso na imagem de memória
- `volatility -f <file> malprocfind`: procura por processos maliciosos na imagem de memória
- `volatility -f <file> maldriverscan`: procura por drivers maliciosos na imagem de memória
- `volatility -f <file> malfind`: procura por código malicioso na imagem de memória
- `volatility -f <file> malfind`: procura por código malicioso na imagem de memória

### Análise de rede

- `volatility -f <file> connscan`: lista as conexões de rede na imagem de memória (busca em todos os processos)
- `volatility -f <file> netscan`: lista as conexões de rede na imagem de memória
- `volatility -f <file> sockets`: lista os sockets abertos na imagem de memória

### Análise de sistema de arquivos

- `volatility -f <file> shimcache`: exibe as informações do cache de compatibilidade do aplicativo da imagem de memória
- `volatility -f <file> usnjrnl`: exibe as informações do diário de alterações do NTFS da imagem de memória
- `volatility -f <file> mftparser`: exibe as informações da tabela de arquivos mestre (MFT) da imagem de memória
- `volatility -f <file> mftparser --output-file=<output_file>`: extrai a tabela de arquivos mestre (MFT) da imagem de memória para um arquivo de saída
- `volatility -f <file> filescan`: lista os arquivos abertos na imagem de memória
- `volatility -f <file> dumpfiles -D <output_directory> --name <filename>`: extrai um arquivo específico para um diretório de saída
- `volatility -f <file> dumpfiles -D <output_directory> --unallocated`: extrai todos os arquivos não alocados para um diretório de saída

### Análise de registro

- `volatility -f <file> hivelist`: lista os arquivos de registro na imagem de memória
- `volatility -f <file> printkey -K <key>`: exibe o conteúdo de uma chave de registro específica
- `volatility -f <file> dumpregistry -D <output_directory> -K <key>`: extrai uma chave de registro específica para um diretório de saída
- `volatility -f <file> userassist`: exibe as informações do UserAssist da imagem de memória
- `volatility -f <file> userassist -o`: exibe as informações do UserAssist da imagem de memória em formato CSV
- `volatility -f <file> shellbags`: exibe as informações de shellbags da imagem de memória
- `volatility -f <file> shellbags -o`: exibe as informações de shellbags da imagem de memória em formato CSV

### Análise de processo

- `volatility -f <file> memdump -p <pid> -D <output_directory>`: extrai o espaço de endereço virtual de um processo específico para um diretório de saída
- `volatility -f <file> procdump -p <pid> -D <output_directory>`: extrai o arquivo executável de um processo específico para um diretório de saída
- `volatility -f <file> malfind -p <pid> -D <output_directory>`: procura por código malicioso na memória de um processo específico e extrai-o para um diretório de saída
- `volatility -f <file> handles -p <pid>`: lista os handles abertos por um processo específico
- `volatility -f <file> dlllist -p <pid>`: lista as DLLs carregadas por um processo específico
- `volatility -f <file> vadinfo -p <pid>`: exibe informações sobre as regiões de memória virtuais de um processo específico
- `volatility -f <file> vadtree -p <pid>`: exibe a árvore de regiões de memória virtuais de um processo específico

### Análise de kernel

- `volatility -f <file> modules`: lista os módulos do kernel carregados na imagem de memória
- `volatility -f <file> modscan`: lista os módulos do kernel carregados na imagem de memória (busca em todos os processos)
- `volatility -f <file> driverirp`: exibe as informações do IRP de driver da imagem de memória
- `volatility -f <file> ssdt`: exibe as informações da tabela de serviços do sistema (SSDT) da imagem de memória
- `volatility -f <file> callbacks`: exibe as informações dos callbacks do kernel da imagem de memória
- `volatility -f <file> idt`: exibe as informações da tabela de interrupções do sistema (IDT) da imagem de memória
- `volatility -f <file> gdt`: exibe as informações da tabela de descritores globais (GDT) da imagem de memória
- `volatility -f <file> ldrmodules`: exibe as informações dos módulos do kernel carregados na imagem de memória
- `volatility -f <file> ldrmodules -p <pid>`: exibe as informações dos módulos do kernel carregados por um processo específico
- `volatility -f <file> atomscan`: exibe as informações dos objetos de atom da imagem de memória
- `volatility -f <file> atomscan -p <pid>`: exibe as informações dos objetos de atom de um processo específico

## Referências

- [Volatility Documentation](https://github.com/volatilityfoundation/volatility/wiki)
```bash
 volatilitye --plugins="/tmp/plugins/" [...]
```
{% endtab %}
{% endtabs %}

#### Autoruns

Baixe-o em [https://github.com/tomchop/volatility-autoruns](https://github.com/tomchop/volatility-autoruns)
```
 volatility --plugins=volatility-autoruns/ --profile=WinXPSP2x86 -f file.dmp autoruns
```
### Mutexes

### Mutexes

Um mutex é um objeto de sincronização que é usado para garantir que apenas um processo ou thread possa acessar um recurso compartilhado por vez. Eles são frequentemente usados para proteger seções críticas do código e evitar condições de corrida.

O Volatility pode ser usado para listar todos os mutexes presentes em um dump de memória usando o comando `mutantscan`. Isso pode ser útil para identificar mutexes que foram criados por malware ou para entender como um programa usa mutexes para proteger recursos compartilhados.

Exemplo de uso:

```
volatility -f memdump.mem mutantscan
```

Isso listará todos os mutexes presentes no dump de memória.

### Mutexes

Um mutex é um objeto de sincronização que é usado para garantir que apenas um processo ou thread possa acessar um recurso compartilhado por vez. Eles são frequentemente usados para proteger seções críticas do código e evitar condições de corrida.

O Volatility pode ser usado para listar todos os mutexes presentes em um dump de memória usando o comando `mutantscan`. Isso pode ser útil para identificar mutexes que foram criados por malware ou para entender como um programa usa mutexes para proteger recursos compartilhados.

Exemplo de uso:

```
volatility -f memdump.mem mutantscan
```

Isso listará todos os mutexes presentes no dump de memória.
```
./vol.py -f file.dmp windows.mutantscan.MutantScan
```
{% endtab %}

{% tab title="volatility-cheatsheet" %}
# Folha de dicas do Volatility

## Comandos básicos

### Análise de imagem

- `volatility -f <file> imageinfo`: exibe informações sobre a imagem de memória
- `volatility -f <file> profileinfo`: exibe informações sobre o perfil da imagem de memória
- `volatility -f <file> pslist`: exibe a lista de processos em execução
- `volatility -f <file> pstree`: exibe a árvore de processos em execução
- `volatility -f <file> psscan`: exibe a lista de processos em execução usando o scanner de processo
- `volatility -f <file> dlllist -p <pid>`: exibe a lista de DLLs carregadas por um processo
- `volatility -f <file> handles -p <pid>`: exibe a lista de handles abertos por um processo
- `volatility -f <file> filescan`: exibe a lista de arquivos abertos
- `volatility -f <file> netscan`: exibe a lista de conexões de rede

### Análise de processo

- `volatility -f <file> procdump -p <pid> -D <output_directory>`: cria um dump de memória de um processo
- `volatility -f <file> memdump -p <pid> -D <output_directory>`: cria um dump de memória de um processo (mais rápido que o procdump)
- `volatility -f <file> cmdline -p <pid>`: exibe a linha de comando usada para iniciar um processo
- `volatility -f <file> consoles -p <pid>`: exibe a lista de consoles usados por um processo
- `volatility -f <file> getsids -p <pid>`: exibe a lista de SIDs associados a um processo
- `volatility -f <file> envars -p <pid>`: exibe a lista de variáveis de ambiente usadas por um processo
- `volatility -f <file> malfind -p <pid> -Y <output_directory>`: procura por código malicioso em um processo

### Análise de sistema de arquivos

- `volatility -f <file> fileinfo -o <offset>`: exibe informações sobre um arquivo
- `volatility -f <file> mftparser -o <offset>`: exibe informações sobre o MFT (Master File Table)
- `volatility -f <file> usnjrnl -o <offset>`: exibe informações sobre o USN Journal
- `volatility -f <file> shimcache`: exibe informações sobre o cache de compatibilidade do Windows
- `volatility -f <file> printkey -K <key>`: exibe o conteúdo de uma chave do registro do Windows
- `volatility -f <file> hivelist`: exibe a lista de hives do registro do Windows
- `volatility -f <file> hashdump -s <system_offset> -s <software_offset>`: exibe as hashes de senha armazenadas no registro do Windows

### Análise de rede

- `volatility -f <file> connscan`: exibe a lista de conexões de rede
- `volatility -f <file> sockets`: exibe a lista de sockets abertos
- `volatility -f <file> sockscan`: exibe a lista de sockets abertos usando o scanner de socket

## Plugins adicionais

### Análise de malware

- `volatility -f <file> malfind`: procura por código malicioso em toda a imagem de memória
- `volatility -f <file> malprocfind`: procura por processos maliciosos em toda a imagem de memória
- `volatility -f <file> maldriverscan`: procura por drivers maliciosos em toda a imagem de memória
- `volatility -f <file> apihooks`: exibe a lista de funções do sistema que foram modificadas por um rootkit

### Análise de sistema de arquivos

- `volatility -f <file> filescan`: exibe a lista de arquivos abertos
- `volatility -f <file> filescan -S <string>`: exibe a lista de arquivos abertos que contêm uma string específica
- `volatility -f <file> filescan -F <regex>`: exibe a lista de arquivos abertos que correspondem a uma expressão regular
- `volatility -f <file> dumpfiles -Q <string> -D <output_directory>`: extrai arquivos da imagem de memória que contêm uma string específica
- `volatility -f <file> dumpfiles -R <regex> -D <output_directory>`: extrai arquivos da imagem de memória que correspondem a uma expressão regular

### Análise de registro do Windows

- `volatility -f <file> printkey -K <key>`: exibe o conteúdo de uma chave do registro do Windows
- `volatility -f <file> hivelist`: exibe a lista de hives do registro do Windows
- `volatility -f <file> hivedump -o <offset> -O <output_directory>`: cria um dump de uma hive do registro do Windows
- `volatility -f <file> hashdump -s <system_offset> -s <software_offset>`: exibe as hashes de senha armazenadas no registro do Windows

### Análise de memória

- `volatility -f <file> memdump`: cria um dump de toda a imagem de memória
- `volatility -f <file> memdump -p <pid>`: cria um dump de memória de um processo
- `volatility -f <file> memdump -o <offset>`: cria um dump de memória de uma região específica da imagem de memória
- `volatility -f <file> memmap`: exibe o mapa de memória da imagem de memória
- `volatility -f <file> memmap --dump-dir <output_directory>`: cria um dump de todas as regiões de memória da imagem de memória

### Análise de rede

- `volatility -f <file> connscan`: exibe a lista de conexões de rede
- `volatility -f <file> sockets`: exibe a lista de sockets abertos
- `volatility -f <file> sockscan`: exibe a lista de sockets abertos usando o scanner de socket

### Análise de processo

- `volatility -f <file> procdump`: cria um dump de memória de todos os processos
- `volatility -f <file> procdump -p <pid>`: cria um dump de memória de um processo
- `volatility -f <file> procdump -D <output_directory>`: cria um dump de memória de todos os processos em um diretório
- `volatility -f <file> procdump -p <pid> -D <output_directory>`: cria um dump de memória de um processo em um diretório
- `volatility -f <file> vadinfo -p <pid>`: exibe informações sobre as regiões de memória de um processo
- `volatility -f <file> vadtree -p <pid>`: exibe a árvore de regiões de memória de um processo
- `volatility -f <file> vadwalk -p <pid> -r <vaddr>`: exibe a lista de regiões de memória acessíveis a partir de um endereço virtual

### Análise de sistema

- `volatility -f <file> svcscan`: exibe a lista de serviços do Windows
- `volatility -f <file> driverirp`: exibe a lista de IRPs (I/O Request Packets) de drivers do Windows
- `volatility -f <file> modscan`: exibe a lista de módulos do kernel do Windows
- `volatility -f <file> moddump -n <name> -D <output_directory>`: cria um dump de um módulo do kernel do Windows
- `volatility -f <file> atomscan`: exibe a lista de objetos atômicos do Windows
- `volatility -f <file> atomscan -s <string>`: exibe a lista de objetos atômicos do Windows que contêm uma string específica
- `volatility -f <file> atomscan -S <substring>`: exibe a lista de objetos atômicos do Windows que contêm uma substring específica
- `volatility -f <file> atomscan -o <offset>`: exibe a lista de objetos atômicos do Windows que estão em um offset específico
- `volatility -f <file> atomscan -O <output_directory>`: cria um dump de todos os objetos atômicos do Windows

### Análise de virtualização

- `volatility -f <file> vboxinfo`: exibe informações sobre máquinas virtuais do VirtualBox
- `volatility -f <file> vboxguestinfo -p <pid>`: exibe informações sobre o processo do VBoxGuest.sys
- `volatility -f <file> vboxsf`: exibe informações sobre compartilhamentos de arquivos do VirtualBox
- `volatility -f <file> vmwareinfo`: exibe informações sobre máquinas virtuais do VMware
- `volatility -f <file> vmwarecheck`: verifica se a imagem de memória é de uma máquina virtual do VMware
- `volatility -f <file> vmwareregistry`: exibe informações sobre o registro do Windows de uma máquina virtual do VMware
- `volatility -f <file> xeninfo`: exibe informações sobre máquinas virtuais do Xen
- `volatility -f <file> xenstore`: exibe informações sobre o XenStore

### Análise de Android

- `volatility -f <file> androidinfo`: exibe informações sobre dispositivos Android
- `volatility -f <file> androiddump -p <pid> -D <output_directory>`: cria um dump de memória de um processo Android
- `volatility -f <file> androidps`: exibe a lista de processos Android
- `volatility -f <file> androidsvc`: exibe a lista de serviços Android
- `volatility -f <file> androidperms`: exibe a lista de permissões Android
- `volatility -f <file> androidactivity`: exibe a lista de atividades Android
- `volatility -f <file> androidintents`: exibe a lista de intents Android

### Análise de Linux

- `volatility -f <file> linuxinfo`: exibe informações sobre sistemas Linux
- `volatility -f <file> linuxbanner`: exibe o banner do kernel do Linux
- `volatility -f <file> linuxprocmaps`: exibe o mapa de memória de um processo Linux
- `volatility -f <file> linuxpstree`: exibe a árvore de processos Linux
- `volatility -f <file> linuxpslist`: exibe a lista de processos Linux
- `volatility -f <file> linuxnetscan`: exibe a lista de conexões de rede Linux
- `volatility -f <file> linuxifconfig`: exibe a lista de interfaces de rede Linux
- `volatility -f <file> linuxdump -p <pid> -D <output_directory>`: cria um dump de memória de um processo Linux
- `volatility -f <file> linuxdmesg`: exibe o log do kernel do Linux
- `volatility -f <file> linuxfile -S <string>`: exibe a lista de arquivos abertos que contêm uma string específica
- `volatility -f <file> linuxfile -F <regex>`: exibe a lista de arquivos abertos que correspondem a uma expressão regular
- `volatility -f <file> linuxbanner`: exibe o banner do kernel do Linux

### Análise de macOS

- `volatility -f <file> macinfo`: exibe informações sobre sistemas macOS
- `volatility -f <file> macbanner`: exibe o banner do kernel do macOS
- `volatility -f <file> macpslist`: exibe a lista de processos macOS
- `volatility -f <file> macpstree`: exibe a árvore de processos macOS
- `volatility -f <file> macdump -p <pid> -D <output_directory>`: cria um dump de memória de um processo macOS
- `volatility -f <file> macfile -S <string>`: exibe a lista de arquivos abertos que contêm uma string específica
- `volatility -f <file> macfile -F <regex>`: exibe a lista de arquivos abertos que correspondem a uma expressão regular
- `volatility -f <file> macsockets`: exibe a lista de sockets abertos no macOS

## Referências

- [Volatility Cheat Sheet](https://github.com/JamesHabben/volatility-cheatsheet) por James Habben
- [Volatility Command Reference](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference) no wiki do Volatility Foundation
- [Volatility Plugin List](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference) no wiki do Volatility Foundation
{% endtab %}
```bash
volatility --profile=Win7SP1x86_23418 mutantscan -f file.dmp
volatility --profile=Win7SP1x86_23418 -f file.dmp handles -p <PID> -t mutant
```
### Links simbólicos

{% tabs %}
{% tab title="vol3" %}

#### Comando: `symlinkscan`

O `symlinkscan` é um plugin do Volatility que procura por links simbólicos em um dump de memória. Ele pode ser usado para encontrar arquivos que foram ocultados por meio de links simbólicos.

```
volatility -f <memory_dump> --profile=<profile> symlinkscan
```

#### Comando: `symlinkenum`

O `symlinkenum` é um plugin do Volatility que lista todos os links simbólicos em um dump de memória.

```
volatility -f <memory_dump> --profile=<profile> symlinkenum
```

#### Comando: `symlinkfiles`

O `symlinkfiles` é um plugin do Volatility que lista todos os arquivos que estão sendo referenciados por links simbólicos em um dump de memória.

```
volatility -f <memory_dump> --profile=<profile> symlinkfiles
```

{% endtab %}
{% endtabs %}
```bash
./vol.py -f file.dmp windows.symlinkscan.SymlinkScan
```
{% endtab %}

{% tab title="volatility-cheatsheet.md" %}
# Folha de dicas do Volatility

## Comandos básicos

### Análise de imagem

- `volatility -f <file> imageinfo`: exibe informações sobre a imagem de memória
- `volatility -f <file> kdbgscan`: procura pelo valor do depurador do kernel (KDBG) na imagem de memória
- `volatility -f <file> pslist`: lista os processos em execução na imagem de memória
- `volatility -f <file> pstree`: exibe a árvore de processos na imagem de memória
- `volatility -f <file> psscan`: procura por processos na imagem de memória
- `volatility -f <file> dlllist -p <pid>`: lista as DLLs carregadas por um processo específico
- `volatility -f <file> filescan`: procura por arquivos abertos na imagem de memória
- `volatility -f <file> netscan`: exibe informações sobre as conexões de rede na imagem de memória
- `volatility -f <file> connections`: exibe informações sobre as conexões de rede na imagem de memória (alternativa para o comando `netscan`)
- `volatility -f <file> connscan`: procura por conexões de rede na imagem de memória
- `volatility -f <file> hivelist`: lista as chaves do registro do Windows presentes na imagem de memória
- `volatility -f <file> printkey -K <key>`: exibe o conteúdo de uma chave do registro do Windows na imagem de memória
- `volatility -f <file> hashdump -y <offset>`: extrai hashes de senha do SAM (Security Account Manager) na imagem de memória

### Análise de processo

- `volatility -f <file> memdump -p <pid> -D <output_directory>`: cria um dump de memória para um processo específico
- `volatility -f <file> procdump -p <pid> -D <output_directory>`: cria um dump de memória para um processo específico (alternativa para o comando `memdump`)
- `volatility -f <file> malfind -p <pid> -D <output_directory>`: procura por código malicioso injetado em um processo específico
- `volatility -f <file> apihooks -p <pid>`: exibe informações sobre os hooks de API em um processo específico
- `volatility -f <file> cmdscan -p <pid>`: procura por comandos executados em um processo específico
- `volatility -f <file> consoles -p <pid>`: exibe informações sobre as janelas de console em um processo específico
- `volatility -f <file> getsids -p <pid>`: exibe informações sobre os SIDs (Security Identifiers) associados a um processo específico
- `volatility -f <file> handles -p <pid>`: exibe informações sobre os handles abertos por um processo específico
- `volatility -f <file> privs -p <pid>`: exibe informações sobre os privilégios de um processo específico
- `volatility -f <file> psxview`: exibe informações sobre os processos ocultos na imagem de memória

## Plugins adicionais

### Análise de malware

- `volatility -f <file> yarascan -Y <rule_file>`: procura por padrões de malware usando regras YARA
- `volatility -f <file> malfind`: procura por código malicioso injetado em processos
- `volatility -f <file> malprocfind`: procura por processos maliciosos na imagem de memória
- `volatility -f <file> malfind`: procura por arquivos maliciosos na imagem de memória

### Análise de rede

- `volatility -f <file> connscan`: procura por conexões de rede na imagem de memória
- `volatility -f <file> netscan`: exibe informações sobre as conexões de rede na imagem de memória
- `volatility -f <file> sockets`: exibe informações sobre os sockets na imagem de memória

### Análise de registro

- `volatility -f <file> hivelist`: lista as chaves do registro do Windows presentes na imagem de memória
- `volatility -f <file> printkey -K <key>`: exibe o conteúdo de uma chave do registro do Windows na imagem de memória
- `volatility -f <file> userassist`: exibe informações sobre os programas executados pelo usuário na imagem de memória
- `volatility -f <file> shellbags`: exibe informações sobre as pastas abertas pelo usuário na imagem de memória

### Análise de sistema de arquivos

- `volatility -f <file> filescan`: procura por arquivos abertos na imagem de memória
- `volatility -f <file> dumpfiles -Q <address>`: extrai um arquivo da imagem de memória
- `volatility -f <file> dumpfiles -Q <address> -D <output_directory>`: extrai um arquivo da imagem de memória para um diretório específico
- `volatility -f <file> mftparser`: exibe informações sobre o Master File Table (MFT) do sistema de arquivos NTFS
- `volatility -f <file> usnjrnl`: exibe informações sobre o journal de alterações do sistema de arquivos NTFS

### Análise de virtualização

- `volatility -f <file> vboxinfo`: exibe informações sobre as máquinas virtuais do VirtualBox presentes na imagem de memória
- `volatility -f <file> vboxguestinfo -p <pid>`: exibe informações sobre o processo do Guest Additions do VirtualBox em um processo específico
- `volatility -f <file> vmwareinfo`: exibe informações sobre as máquinas virtuais do VMware presentes na imagem de memória
- `volatility -f <file> vmwarecheck`: verifica se a imagem de memória é de uma máquina virtual do VMware

### Análise de memória física

- `volatility -f <file> hibernateinfo`: exibe informações sobre o arquivo de hibernação presente na imagem de memória
- `volatility -f <file> hiberfilscan`: procura por arquivos de hibernação na imagem de memória
- `volatility -f <file> windowspcap`: exibe informações sobre os pacotes capturados pelo driver WinPcap na imagem de memória

## Referências

- [Volatility Command Reference](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference)
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp symlinkscan
```
### Bash

É possível **ler do histórico do bash na memória.** Você também pode despejar o arquivo _.bash\_history_, mas se ele estiver desativado, você ficará feliz em poder usar este módulo do volatility. 

{% tabs %}
{% tab title="vol3" %}
```
./vol.py -f file.dmp linux.bash.Bash
```
{% endtab %}

{% tab title="volatility-cheatsheet" %}
# Folha de dicas do Volatility

## Comandos básicos

### Análise de imagem

- `volatility -f <file> imageinfo`: exibe informações sobre a imagem de memória
- `volatility -f <file> profileinfo`: exibe informações sobre o perfil da imagem de memória
- `volatility -f <file> pslist`: exibe a lista de processos em execução
- `volatility -f <file> pstree`: exibe a árvore de processos em execução
- `volatility -f <file> psscan`: exibe a lista de processos em execução usando o scanner de processo
- `volatility -f <file> dlllist -p <pid>`: exibe a lista de DLLs carregadas por um processo
- `volatility -f <file> handles -p <pid>`: exibe a lista de handles abertos por um processo
- `volatility -f <file> filescan`: exibe a lista de arquivos abertos
- `volatility -f <file> netscan`: exibe a lista de conexões de rede

### Análise de processo

- `volatility -f <file> procdump -p <pid> -D <output_directory>`: cria um dump de memória de um processo
- `volatility -f <file> memdump -p <pid> -D <output_directory>`: cria um dump de memória de um processo (alternativa ao procdump)
- `volatility -f <file> cmdline -p <pid>`: exibe a linha de comando usada para iniciar um processo
- `volatility -f <file> consoles -p <pid>`: exibe a lista de consoles usados por um processo
- `volatility -f <file> getsids -p <pid>`: exibe a lista de SIDs associados a um processo
- `volatility -f <file> malfind -p <pid> -D <output_directory>`: procura por código malicioso em um processo
- `volatility -f <file> apihooks -p <pid>`: exibe a lista de ganchos de API instalados em um processo
- `volatility -f <file> envars -p <pid>`: exibe a lista de variáveis de ambiente usadas por um processo

### Análise de sistema de arquivos

- `volatility -f <file> hivelist`: exibe a lista de arquivos de registro carregados
- `volatility -f <file> printkey -o <offset>`: exibe o conteúdo de uma chave de registro
- `volatility -f <file> filescan`: exibe a lista de arquivos abertos
- `volatility -f <file> dumpfiles -Q <path>`: extrai arquivos do sistema de arquivos

### Análise de rede

- `volatility -f <file> connscan`: exibe a lista de conexões de rede
- `volatility -f <file> sockets`: exibe a lista de sockets abertos

## Plugins adicionais

### Análise de malware

- `volatility -f <file> malfind`: procura por código malicioso em todos os processos
- `volatility -f <file> malprocfind`: procura por processos maliciosos
- `volatility -f <file> maldriverscan`: procura por drivers maliciosos
- `volatility -f <file> apihooks`: exibe a lista de ganchos de API instalados em todos os processos

### Análise de memória física

- `volatility -f <file> pagedump -o <offset> -D <output_directory>`: cria um dump de uma página física
- `volatility -f <file> physmap`: exibe o mapeamento de páginas físicas

### Análise de virtualização

- `volatility -f <file> vboxinfo`: exibe informações sobre máquinas virtuais VirtualBox
- `volatility -f <file> vboxguestinfo -p <pid>`: exibe informações sobre o processo do Guest Additions do VirtualBox
- `volatility -f <file> vmwareinfo`: exibe informações sobre máquinas virtuais VMware
- `volatility -f <file> vmwarecheck`: verifica se a imagem de memória é de uma máquina virtual VMware

### Análise de sistema de arquivos

- `volatility -f <file> lsmod`: exibe a lista de módulos do kernel carregados
- `volatility -f <file> moddump -n <name> -D <output_directory>`: cria um dump de um módulo do kernel
- `volatility -f <file> modscan`: exibe a lista de módulos do kernel carregados
- `volatility -f <file> printkey -K <key>`: exibe o conteúdo de uma chave de registro
- `volatility -f <file> printkey -K <key> -o <offset>`: exibe o conteúdo de uma chave de registro em um arquivo de registro específico

### Análise de rede

- `volatility -f <file> connscan`: exibe a lista de conexões de rede
- `volatility -f <file> sockets`: exibe a lista de sockets abertos
- `volatility -f <file> sockscan`: exibe a lista de sockets abertos usando o scanner de socket

## Referências

- [Volatility Cheat Sheet](https://github.com/sans-dfir/sift-files/blob/master/volatility-cheat-sheet.pdf) (PDF)
- [Volatility Command Reference](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference) (Wiki)
```
volatility --profile=Win7SP1x86_23418 -f file.dmp linux_bash
```
### Linha do Tempo

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp timeLiner.TimeLiner
```
{% endtab %}

{% tab title="volatility-cheatsheet.md" %}
# Folha de dicas do Volatility

## Comandos básicos

### Análise de imagem

- `volatility -f <file> imageinfo`: exibe informações sobre a imagem de memória
- `volatility -f <file> kdbgscan`: procura pelo valor do depurador do kernel (KDBG) na imagem de memória
- `volatility -f <file> pslist`: lista os processos em execução na imagem de memória
- `volatility -f <file> psscan`: lista os processos em execução na imagem de memória (busca em todos os processos)
- `volatility -f <file> pstree`: exibe a árvore de processos na imagem de memória
- `volatility -f <file> dlllist -p <pid>`: lista as DLLs carregadas por um processo específico
- `volatility -f <file> handles -p <pid>`: lista os handles abertos por um processo específico
- `volatility -f <file> filescan`: lista os arquivos abertos na imagem de memória
- `volatility -f <file> netscan`: lista as conexões de rede na imagem de memória
- `volatility -f <file> connscan`: lista as conexões de rede na imagem de memória (busca em todos os processos)
- `volatility -f <file> hivelist`: lista os arquivos de registro na imagem de memória
- `volatility -f <file> printkey -K <key>`: exibe o conteúdo de uma chave de registro específica
- `volatility -f <file> dumpregistry -D <output_directory> -K <key>`: extrai uma chave de registro específica para um diretório de saída

### Análise de processo

- `volatility -f <file> memdump -p <pid> -D <output_directory>`: extrai o espaço de endereço virtual de um processo específico para um diretório de saída
- `volatility -f <file> procdump -p <pid> -D <output_directory>`: extrai o arquivo executável de um processo específico para um diretório de saída
- `volatility -f <file> malfind -p <pid> -D <output_directory>`: procura por código malicioso na memória de um processo específico e extrai-o para um diretório de saída

### Análise de sistema de arquivos

- `volatility -f <file> hivelist`: lista os arquivos de registro na imagem de memória
- `volatility -f <file> printkey -K <key>`: exibe o conteúdo de uma chave de registro específica
- `volatility -f <file> dumpregistry -D <output_directory> -K <key>`: extrai uma chave de registro específica para um diretório de saída
- `volatility -f <file> filescan`: lista os arquivos abertos na imagem de memória
- `volatility -f <file> dumpfiles -D <output_directory> --name <filename>`: extrai um arquivo específico para um diretório de saída

### Análise de rede

- `volatility -f <file> netscan`: lista as conexões de rede na imagem de memória
- `volatility -f <file> connscan`: lista as conexões de rede na imagem de memória (busca em todos os processos)
- `volatility -f <file> sockets`: lista os sockets abertos na imagem de memória
- `volatility -f <file> sockscan`: lista os sockets abertos na imagem de memória (busca em todos os processos)

## Plugins úteis

### Malware

- `malfind`: procura por código malicioso na memória e extrai-o para um diretório de saída
- `malsysproc`: lista os processos suspeitos na imagem de memória
- `malfind`: procura por código malicioso na memória e extrai-o para um diretório de saída
- `apihooks`: lista as funções do sistema que foram modificadas por um rootkit
- `ldrmodules`: lista os módulos carregados por um processo específico
- `ldrmodules`: lista os módulos carregados por um processo específico
- `ldrmodules`: lista os módulos carregados por um processo específico

### Registro

- `hivelist`: lista os arquivos de registro na imagem de memória
- `printkey`: exibe o conteúdo de uma chave de registro específica
- `dumpregistry`: extrai uma chave de registro específica para um diretório de saída

### Processos

- `handles`: lista os handles abertos por um processo específico
- `memdump`: extrai o espaço de endereço virtual de um processo específico para um diretório de saída
- `procdump`: extrai o arquivo executável de um processo específico para um diretório de saída
- `malfind`: procura por código malicioso na memória de um processo específico e extrai-o para um diretório de saída

### Sistema de arquivos

- `filescan`: lista os arquivos abertos na imagem de memória
- `dumpfiles`: extrai um arquivo específico para um diretório de saída

### Rede

- `netscan`: lista as conexões de rede na imagem de memória
- `connscan`: lista as conexões de rede na imagem de memória (busca em todos os processos)
- `sockets`: lista os sockets abertos na imagem de memória
- `sockscan`: lista os sockets abertos na imagem de memória (busca em todos os processos)

## Referências

- [Volatility Cheat Sheet](https://github.com/JamesHabben/volatility-cheatsheet) por James Habben
- [Volatility Command Reference](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference) no GitHub
- [The Art of Memory Forensics](https://www.wiley.com/en-us/The+Art+of+Memory+Forensics%3A+Detecting+Malware+and+Threats+in+Windows%2C+Linux%2C+and+Mac+Memory-p-9781118825099) por Michael Hale Ligh, Andrew Case, Jamie Levy e Aaron Walters
```
volatility --profile=Win7SP1x86_23418 -f timeliner
```
### Drivers

{% tabs %}
{% tab title="vol3" %}
Os drivers são módulos de software que permitem que o sistema operacional interaja com o hardware. Eles são carregados na memória do kernel e podem ser encontrados em processos como `System` ou `smss.exe`. O Volatility pode extrair informações sobre os drivers carregados na memória, incluindo seus nomes, endereços base, tamanho e data/hora de carregamento.

#### Comandos

- `driverirp`: lista as estruturas IRP (I/O Request Packet) para cada driver carregado na memória.
- `drivermodule`: lista informações sobre os módulos de driver carregados na memória, incluindo seus nomes, endereços base, tamanho e data/hora de carregamento.
- `driverscan`: varre a memória em busca de módulos de driver carregados e exibe informações sobre eles.
- `moddump`: extrai um módulo de driver específico da memória.
{% endtab %}
{% endtabs %}
```
./vol.py -f file.dmp windows.driverscan.DriverScan
```
{% endtab %}

{% tab title="volatility-cheatsheet.md" %}
# Folha de dicas do Volatility

## Comandos básicos

### Análise de imagem

- `volatility -f <file> imageinfo`: exibe informações sobre a imagem de memória
- `volatility -f <file> kdbgscan`: procura pelo valor do depurador do kernel (KDBG) na imagem de memória
- `volatility -f <file> pslist`: lista os processos em execução na imagem de memória
- `volatility -f <file> pstree`: exibe uma árvore de processos em execução na imagem de memória
- `volatility -f <file> psscan`: procura por processos na imagem de memória
- `volatility -f <file> dlllist -p <pid>`: lista as DLLs carregadas por um processo específico
- `volatility -f <file> handles -p <pid>`: lista os identificadores de objeto abertos por um processo específico
- `volatility -f <file> filescan`: procura por arquivos na imagem de memória
- `volatility -f <file> netscan`: procura por conexões de rede na imagem de memória
- `volatility -f <file> connections`: exibe informações sobre as conexões de rede na imagem de memória
- `volatility -f <file> consoles`: exibe informações sobre as janelas do console na imagem de memória
- `volatility -f <file> printkey -K <key>`: exibe o conteúdo de uma chave do registro do Windows na imagem de memória
- `volatility -f <file> hivelist`: lista as chaves do registro do Windows na imagem de memória

### Análise de processo

- `volatility -f <file> procdump -p <pid> -D <output_directory>`: cria um despejo de memória para um processo específico
- `volatility -f <file> memdump -p <pid> -D <output_directory>`: cria um despejo de memória para um processo específico (alternativa ao `procdump`)
- `volatility -f <file> malfind -p <pid> -D <output_directory>`: procura por código malicioso em um processo específico
- `volatility -f <file> apihooks -p <pid>`: exibe informações sobre os ganchos de API em um processo específico
- `volatility -f <file> cmdscan -p <pid>`: procura por comandos executados em um processo específico
- `volatility -f <file> consoles -p <pid>`: exibe informações sobre as janelas do console em um processo específico
- `volatility -f <file> filescan -p <pid>`: procura por arquivos abertos por um processo específico
- `volatility -f <file> handles -p <pid>`: lista os identificadores de objeto abertos por um processo específico
- `volatility -f <file> privs -p <pid>`: lista os privilégios de um processo específico
- `volatility -f <file> psxview`: exibe informações sobre os processos ocultos na imagem de memória

### Análise de sistema de arquivos

- `volatility -f <file> hivelist`: lista as chaves do registro do Windows na imagem de memória
- `volatility -f <file> printkey -K <key>`: exibe o conteúdo de uma chave do registro do Windows na imagem de memória
- `volatility -f <file> filescan`: procura por arquivos na imagem de memória
- `volatility -f <file> dumpfiles -Q <address_range> -D <output_directory>`: extrai arquivos da imagem de memória
- `volatility -f <file> timeliner -f <image> -o <output_directory>`: cria uma linha do tempo dos arquivos modificados na imagem de memória

## Plugins úteis

- `malfind`: procura por código malicioso na imagem de memória
- `apihooks`: exibe informações sobre os ganchos de API na imagem de memória
- `cmdscan`: procura por comandos executados na imagem de memória
- `consoles`: exibe informações sobre as janelas do console na imagem de memória
- `filescan`: procura por arquivos na imagem de memória
- `handles`: lista os identificadores de objeto abertos na imagem de memória
- `privs`: lista os privilégios na imagem de memória
- `psxview`: exibe informações sobre os processos ocultos na imagem de memória
- `dumpfiles`: extrai arquivos da imagem de memória
- `timeliner`: cria uma linha do tempo dos arquivos modificados na imagem de memória

## Referências

- [Volatility Cheat Sheet](https://github.com/sans-dfir/sift/blob/master/Cheat%20Sheets/Volatility%20Cheat%20Sheet.pdf) (SANS Digital Forensics and Incident Response)
- [Volatility Command Reference](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference) (Volatility Foundation)
{% endtab %}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp driverscan
```
### Obter área de transferência

Para obter o conteúdo da área de transferência, use o plugin **clipboard** do Volatility:

```
$ vol.py clipboard -f <memory_dump>
```
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 clipboard -f file.dmp
```
### Obter histórico do Internet Explorer
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 iehistory -f file.dmp
```
### Obter texto do bloco de notas
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 notepad -f file.dmp
```
### Captura de tela
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 screenshot -f file.dmp
```
### Registro Mestre de Inicialização (MBR)
```
volatility --profile=Win7SP1x86_23418 mbrparser -f file.dmp
```
O MBR contém informações sobre como as partições lógicas, contendo sistemas de arquivos, estão organizadas nesse meio. O MBR também contém código executável para funcionar como um carregador para o sistema operacional instalado - geralmente passando o controle para o segundo estágio do carregador, ou em conjunto com o registro de inicialização do volume de cada partição (VBR). Esse código MBR é geralmente referido como um carregador de inicialização. De aqui.

RootedCON é o evento de cibersegurança mais relevante na Espanha e um dos mais importantes na Europa. Com a missão de promover o conhecimento técnico, este congresso é um ponto de encontro fervilhante para profissionais de tecnologia e cibersegurança em todas as disciplinas.

https://www.rootedcon.com/

☁️ HackTricks Cloud ☁️ -🐦 Twitter 🐦 - 🎙️ Twitch 🎙️ - 🎥 Youtube 🎥

- Você trabalha em uma empresa de cibersegurança? Você quer ver sua empresa anunciada no HackTricks? ou você quer ter acesso à versão mais recente do PEASS ou baixar o HackTricks em PDF? Verifique os PLANOS DE ASSINATURA!
- Descubra The PEASS Family, nossa coleção exclusiva de NFTs
- Obtenha o swag oficial do PEASS & HackTricks
- Junte-se ao grupo Discord ou ao grupo telegram ou siga-me no Twitter @carlospolopm.
- Compartilhe seus truques de hacking enviando PRs para o repositório hacktricks e hacktricks-cloud.
