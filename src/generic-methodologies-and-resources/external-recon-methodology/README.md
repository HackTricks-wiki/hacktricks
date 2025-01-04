# Metodologia de Reconhecimento Externo

{{#include ../../banners/hacktricks-training.md}}

## Descobertas de Ativos

> Então, foi dito que tudo que pertence a alguma empresa está dentro do escopo, e você quer descobrir o que essa empresa realmente possui.

O objetivo desta fase é obter todas as **empresas pertencentes à empresa principal** e, em seguida, todos os **ativos** dessas empresas. Para isso, vamos:

1. Encontrar as aquisições da empresa principal, isso nos dará as empresas dentro do escopo.
2. Encontrar o ASN (se houver) de cada empresa, isso nos dará os intervalos de IP pertencentes a cada empresa.
3. Usar consultas de whois reverso para buscar outras entradas (nomes de organizações, domínios...) relacionadas à primeira (isso pode ser feito recursivamente).
4. Usar outras técnicas como filtros `org` e `ssl` do shodan para buscar outros ativos (o truque `ssl` pode ser feito recursivamente).

### **Aquisições**

Primeiro de tudo, precisamos saber quais **outras empresas são pertencentes à empresa principal**.\
Uma opção é visitar [https://www.crunchbase.com/](https://www.crunchbase.com), **pesquisar** pela **empresa principal** e **clicar** em "**aquisições**". Lá você verá outras empresas adquiridas pela principal.\
Outra opção é visitar a página da **Wikipedia** da empresa principal e procurar por **aquisições**.

> Ok, neste ponto você deve saber todas as empresas dentro do escopo. Vamos descobrir como encontrar seus ativos.

### **ASNs**

Um número de sistema autônomo (**ASN**) é um **número único** atribuído a um **sistema autônomo** (AS) pela **Internet Assigned Numbers Authority (IANA)**.\
Um **AS** consiste em **blocos** de **endereços IP** que têm uma política claramente definida para acessar redes externas e são administrados por uma única organização, mas podem ser compostos por vários operadores.

É interessante descobrir se a **empresa atribuiu algum ASN** para encontrar seus **intervalos de IP.** Será interessante realizar um **teste de vulnerabilidade** contra todos os **hosts** dentro do **escopo** e **procurar por domínios** dentro desses IPs.\
Você pode **pesquisar** pelo **nome** da empresa, por **IP** ou por **domínio** em [**https://bgp.he.net/**](https://bgp.he.net)**.**\
**Dependendo da região da empresa, esses links podem ser úteis para coletar mais dados:** [**AFRINIC**](https://www.afrinic.net) **(África),** [**Arin**](https://www.arin.net/about/welcome/region/)**(América do Norte),** [**APNIC**](https://www.apnic.net) **(Ásia),** [**LACNIC**](https://www.lacnic.net) **(América Latina),** [**RIPE NCC**](https://www.ripe.net) **(Europa). De qualquer forma, provavelmente todas as** informações úteis **(intervalos de IP e Whois)** já aparecem no primeiro link.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Além disso, a enumeração de subdomínios do [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s** agrega e resume automaticamente os ASNs no final da varredura.
```bash
bbot -t tesla.com -f subdomain-enum
...
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+
[INFO] bbot.modules.asn: | AS394161 | 8.244.131.0/24      | 5            | TESLA          | Tesla Motors, Inc.         | US        |
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+
[INFO] bbot.modules.asn: | AS16509  | 54.148.0.0/15       | 4            | AMAZON-02      | Amazon.com, Inc.           | US        |
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+
[INFO] bbot.modules.asn: | AS394161 | 8.45.124.0/24       | 3            | TESLA          | Tesla Motors, Inc.         | US        |
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+
[INFO] bbot.modules.asn: | AS3356   | 8.32.0.0/12         | 1            | LEVEL3         | Level 3 Parent, LLC        | US        |
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+
[INFO] bbot.modules.asn: | AS3356   | 8.0.0.0/9           | 1            | LEVEL3         | Level 3 Parent, LLC        | US        |
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+

```
Você pode encontrar os intervalos de IP de uma organização também usando [http://asnlookup.com/](http://asnlookup.com) (ele tem uma API gratuita).\
Você pode encontrar o IP e ASN de um domínio usando [http://ipv4info.com/](http://ipv4info.com).

### **Procurando vulnerabilidades**

Neste ponto, sabemos **todos os ativos dentro do escopo**, então, se você tiver permissão, poderia lançar algum **scanner de vulnerabilidades** (Nessus, OpenVAS) sobre todos os hosts.\
Além disso, você poderia lançar alguns [**scans de portas**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **ou usar serviços como** shodan **para encontrar** portas abertas **e dependendo do que você encontrar, você deve** dar uma olhada neste livro sobre como realizar pentesting em vários serviços possíveis em execução.\
**Além disso, pode valer a pena mencionar que você também pode preparar algumas listas de** nomes de usuário **e** senhas **padrão e tentar** bruteforçar serviços com [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domínios

> Sabemos todas as empresas dentro do escopo e seus ativos, é hora de encontrar os domínios dentro do escopo.

_Por favor, note que nas técnicas propostas a seguir você também pode encontrar subdomínios e que essa informação não deve ser subestimada._

Primeiramente, você deve procurar pelo(s) **domínio(s) principal(is)** de cada empresa. Por exemplo, para _Tesla Inc._ será _tesla.com_.

### **DNS Reverso**

Como você encontrou todos os intervalos de IP dos domínios, poderia tentar realizar **consultas de DNS reverso** nesses **IPs para encontrar mais domínios dentro do escopo**. Tente usar algum servidor DNS da vítima ou algum servidor DNS bem conhecido (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Para que isso funcione, o administrador precisa habilitar manualmente o PTR.\
Você também pode usar uma ferramenta online para essas informações: [http://ptrarchive.com/](http://ptrarchive.com)

### **Reverse Whois (loop)**

Dentro de um **whois** você pode encontrar muitas **informações** interessantes, como **nome da organização**, **endereço**, **emails**, números de telefone... Mas o que é ainda mais interessante é que você pode encontrar **mais ativos relacionados à empresa** se realizar **buscas reversas de whois por qualquer um desses campos** (por exemplo, outros registros whois onde o mesmo email aparece).\
Você pode usar ferramentas online como:

- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Gratuito**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Gratuito**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Gratuito**
- [https://www.whoxy.com/](https://www.whoxy.com) - **Gratuito** na web, API não gratuita.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Não gratuito
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Não Gratuito (apenas **100 buscas gratuitas**)
- [https://www.domainiq.com/](https://www.domainiq.com) - Não Gratuito

Você pode automatizar essa tarefa usando [**DomLink** ](https://github.com/vysecurity/DomLink) (requer uma chave de API whoxy).\
Você também pode realizar algumas descobertas automáticas de reverse whois com [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Note que você pode usar essa técnica para descobrir mais nomes de domínio toda vez que encontrar um novo domínio.**

### **Trackers**

Se encontrar o **mesmo ID do mesmo tracker** em 2 páginas diferentes, você pode supor que **ambas as páginas** são **gerenciadas pela mesma equipe**.\
Por exemplo, se você ver o mesmo **ID do Google Analytics** ou o mesmo **ID do Adsense** em várias páginas.

Existem algumas páginas e ferramentas que permitem que você pesquise por esses trackers e mais:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)

### **Favicon**

Você sabia que podemos encontrar domínios e subdomínios relacionados ao nosso alvo procurando pelo mesmo hash do ícone favicon? Isso é exatamente o que a ferramenta [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) feita por [@m4ll0k2](https://twitter.com/m4ll0k2) faz. Aqui está como usá-la:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - descobrir domínios com o mesmo hash de ícone favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Simplificando, favihash nos permitirá descobrir domínios que têm o mesmo hash de ícone favicon que nosso alvo.

Além disso, você também pode pesquisar tecnologias usando o hash do favicon, conforme explicado em [**este post do blog**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139). Isso significa que, se você souber o **hash do favicon de uma versão vulnerável de uma tecnologia web**, pode pesquisar no shodan e **encontrar mais lugares vulneráveis**:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
É assim que você pode **calcular o hash do favicon** de um site:
```python
import mmh3
import requests
import codecs

def fav_hash(url):
response = requests.get(url)
favicon = codecs.encode(response.content,"base64")
fhash = mmh3.hash(favicon)
print(f"{url} : {fhash}")
return fhash
```
### **Copyright / Uniq string**

Pesquise nas páginas da web **strings que podem ser compartilhadas entre diferentes sites na mesma organização**. A **string de copyright** pode ser um bom exemplo. Em seguida, procure essa string no **google**, em outros **navegadores** ou até mesmo no **shodan**: `shodan search http.html:"Copyright string"`

### **CRT Time**

É comum ter um cron job como
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
renovar todos os certificados de domínio no servidor. Isso significa que, mesmo que a CA usada para isso não defina o tempo em que foi gerado no tempo de validade, é possível **encontrar domínios pertencentes à mesma empresa nos logs de transparência de certificados**.\
Confira este [**artigo para mais informações**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

### Informações de Mail DMARC

Você pode usar um site como [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) ou uma ferramenta como [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) para encontrar **domínios e subdomínios que compartilham as mesmas informações de dmarc**.

### **Tomada Passiva**

Aparentemente, é comum que as pessoas atribuam subdomínios a IPs que pertencem a provedores de nuvem e, em algum momento, **percam esse endereço IP, mas se esqueçam de remover o registro DNS**. Portanto, apenas **criar uma VM** em uma nuvem (como Digital Ocean) você estará, na verdade, **assumindo alguns subdomínios**.

[**Este post**](https://kmsec.uk/blog/passive-takeover/) explica uma história sobre isso e propõe um script que **cria uma VM no DigitalOcean**, **obtém** o **IPv4** da nova máquina e **busca no Virustotal por registros de subdomínio** que apontam para ela.

### **Outras maneiras**

**Observe que você pode usar essa técnica para descobrir mais nomes de domínio toda vez que encontrar um novo domínio.**

**Shodan**

Como você já sabe o nome da organização que possui o espaço de IP. Você pode pesquisar por esses dados no shodan usando: `org:"Tesla, Inc."` Verifique os hosts encontrados para novos domínios inesperados no certificado TLS.

Você poderia acessar o **certificado TLS** da página principal, obter o **nome da Organização** e, em seguida, pesquisar esse nome dentro dos **certificados TLS** de todas as páginas da web conhecidas pelo **shodan** com o filtro: `ssl:"Tesla Motors"` ou usar uma ferramenta como [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder**](https://github.com/tomnomnom/assetfinder) é uma ferramenta que procura **domínios relacionados** com um domínio principal e **subdomínios** deles, bastante incrível.

### **Procurando vulnerabilidades**

Verifique se há alguma [tomada de domínio](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Talvez alguma empresa esteja **usando algum domínio** mas **perdeu a propriedade**. Basta registrá-lo (se for barato o suficiente) e informar a empresa.

Se você encontrar algum **domínio com um IP diferente** dos que você já encontrou na descoberta de ativos, você deve realizar uma **varredura básica de vulnerabilidades** (usando Nessus ou OpenVAS) e alguma [**varredura de portas**](../pentesting-network/index.html#discovering-hosts-from-the-outside) com **nmap/masscan/shodan**. Dependendo de quais serviços estão em execução, você pode encontrar neste livro algumas dicas para "atacá-los".\
&#xNAN;_&#x4E;ote que às vezes o domínio está hospedado dentro de um IP que não é controlado pelo cliente, então não está no escopo, tenha cuidado._

## Subdomínios

> Sabemos todas as empresas dentro do escopo, todos os ativos de cada empresa e todos os domínios relacionados às empresas.

É hora de encontrar todos os possíveis subdomínios de cada domínio encontrado.

> [!TIP]
> Observe que algumas das ferramentas e técnicas para encontrar domínios também podem ajudar a encontrar subdomínios

### **DNS**

Vamos tentar obter **subdomínios** dos registros **DNS**. Também devemos tentar por **Transferência de Zona** (Se vulnerável, você deve relatar isso).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

A maneira mais rápida de obter muitos subdomínios é pesquisar em fontes externas. As **ferramentas** mais utilizadas são as seguintes (para melhores resultados, configure as chaves da API):

- [**BBOT**](https://github.com/blacklanternsecurity/bbot)
```bash
# subdomains
bbot -t tesla.com -f subdomain-enum

# subdomains (passive only)
bbot -t tesla.com -f subdomain-enum -rf passive

# subdomains + port scan + web screenshots
bbot -t tesla.com -f subdomain-enum -m naabu gowitness -n my_scan -o .
```
- [**Amass**](https://github.com/OWASP/Amass)
```bash
amass enum [-active] [-ip] -d tesla.com
amass enum -d tesla.com | grep tesla.com # To just list subdomains
```
- [**subfinder**](https://github.com/projectdiscovery/subfinder)
```bash
# Subfinder, use -silent to only have subdomains in the output
./subfinder-linux-amd64 -d tesla.com [-silent]
```
- [**findomain**](https://github.com/Edu4rdSHL/findomain/)
```bash
# findomain, use -silent to only have subdomains in the output
./findomain-linux -t tesla.com [--quiet]
```
- [**OneForAll**](https://github.com/shmilylty/OneForAll/tree/master/docs/en-us)
```bash
python3 oneforall.py --target tesla.com [--dns False] [--req False] [--brute False] run
```
- [**assetfinder**](https://github.com/tomnomnom/assetfinder)
```bash
assetfinder --subs-only <domain>
```
- [**Sudomy**](https://github.com/Screetsec/Sudomy)
```bash
# It requires that you create a sudomy.api file with API keys
sudomy -d tesla.com
```
- [**vita**](https://github.com/junnlikestea/vita)
```
vita -d tesla.com
```
- [**theHarvester**](https://github.com/laramies/theHarvester)
```bash
theHarvester -d tesla.com -b "anubis, baidu, bing, binaryedge, bingapi, bufferoverun, censys, certspotter, crtsh, dnsdumpster, duckduckgo, fullhunt, github-code, google, hackertarget, hunter, intelx, linkedin, linkedin_links, n45ht, omnisint, otx, pentesttools, projectdiscovery, qwant, rapiddns, rocketreach, securityTrails, spyse, sublist3r, threatcrowd, threatminer, trello, twitter, urlscan, virustotal, yahoo, zoomeye"
```
Existem **outras ferramentas/APIs interessantes** que, mesmo não sendo diretamente especializadas em encontrar subdomínios, podem ser úteis para encontrá-los, como:

- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Usa a API [https://sonar.omnisint.io](https://sonar.omnisint.io) para obter subdomínios
```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```
- [**API gratuita do JLDC**](https://jldc.me/anubis/subdomains/google.com)
```bash
curl https://jldc.me/anubis/subdomains/tesla.com | jq -r ".[]"
```
- [**RapidDNS**](https://rapiddns.io) API gratuita
```bash
# Get Domains from rapiddns free API
rapiddns(){
curl -s "https://rapiddns.io/subdomain/$1?full=1" \
| grep -oE "[\.a-zA-Z0-9-]+\.$1" \
| sort -u
}
rapiddns tesla.com
```
- [**https://crt.sh/**](https://crt.sh)
```bash
# Get Domains from crt free API
crt(){
curl -s "https://crt.sh/?q=%25.$1" \
| grep -oE "[\.a-zA-Z0-9-]+\.$1" \
| sort -u
}
crt tesla.com
```
- [**gau**](https://github.com/lc/gau)**:** busca URLs conhecidas do Open Threat Exchange da AlienVault, da Wayback Machine e do Common Crawl para qualquer domínio dado.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Eles vasculham a web em busca de arquivos JS e extraem subdomínios a partir daí.
```bash
# Get only subdomains from SubDomainizer
python3 SubDomainizer.py -u https://tesla.com | grep tesla.com

# Get only subdomains from subscraper, this already perform recursion over the found results
python subscraper.py -u tesla.com | grep tesla.com | cut -d " " -f
```
- [**Shodan**](https://www.shodan.io/)
```bash
# Get info about the domain
shodan domain <domain>
# Get other pages with links to subdomains
shodan search "http.html:help.domain.com"
```
- [**Censys subdomain finder**](https://github.com/christophetd/censys-subdomain-finder)
```bash
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
python3 censys-subdomain-finder.py tesla.com
```
- [**DomainTrail.py**](https://github.com/gatete/DomainTrail)
```bash
python3 DomainTrail.py -d example.com
```
- [**securitytrails.com**](https://securitytrails.com/) tem uma API gratuita para pesquisar subdomínios e histórico de IP
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Este projeto oferece **gratuitamente todos os subdomínios relacionados a programas de bug-bounty**. Você pode acessar esses dados também usando [chaospy](https://github.com/dr-0x0x/chaospy) ou até mesmo acessar o escopo usado por este projeto [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Você pode encontrar uma **comparação** de muitas dessas ferramentas aqui: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Vamos tentar encontrar novos **subdomínios** forçando servidores DNS usando possíveis nomes de subdomínio.

Para esta ação, você precisará de algumas **listas de palavras comuns de subdomínios como**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

E também IPs de bons resolvedores DNS. Para gerar uma lista de resolvedores DNS confiáveis, você pode baixar os resolvedores de [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) e usar [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) para filtrá-los. Ou você poderia usar: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

As ferramentas mais recomendadas para brute-force DNS são:

- [**massdns**](https://github.com/blechschmidt/massdns): Esta foi a primeira ferramenta que realizou um brute-force DNS eficaz. É muito rápida, no entanto, é propensa a falsos positivos.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Este eu acho que usa apenas 1 resolvedor
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) é um wrapper em torno do `massdns`, escrito em go, que permite enumerar subdomínios válidos usando bruteforce ativo, além de resolver subdomínios com tratamento de wildcard e suporte fácil de entrada-saída.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): Ele também usa `massdns`.
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) usa asyncio para forçar nomes de domínio de forma assíncrona.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Segunda Rodada de Força Bruta DNS

Após ter encontrado subdomínios usando fontes abertas e força bruta, você pode gerar alterações dos subdomínios encontrados para tentar encontrar ainda mais. Várias ferramentas são úteis para esse propósito:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Dado os domínios e subdomínios, gera permutações.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): Dado os domínios e subdomínios, gera permutações.
- Você pode obter as permutações do goaltdns **wordlist** [**aqui**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** Dado os domínios e subdomínios, gera permutações. Se nenhum arquivo de permutações for indicado, o gotator usará o seu próprio.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Além de gerar permutações de subdomínios, ele também pode tentar resolvê-los (mas é melhor usar as ferramentas comentadas anteriormente).
- Você pode obter a **wordlist** de permutações do altdns [**aqui**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Outra ferramenta para realizar permutações, mutações e alterações de subdomínios. Esta ferramenta fará força bruta no resultado (não suporta wildcard dns).
- Você pode obter a lista de palavras de permutações do dmut [**aqui**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Com base em um domínio, ele **gera novos nomes de subdomínios potenciais** com base em padrões indicados para tentar descobrir mais subdomínios.

#### Geração de permutações inteligentes

- [**regulator**](https://github.com/cramppet/regulator): Para mais informações, leia este [**post**](https://cramppet.github.io/regulator/index.html), mas basicamente ele pegará as **partes principais** dos **subdomínios descobertos** e as misturará para encontrar mais subdomínios.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ é um fuzzer de força bruta para subdomínios acoplado a um algoritmo guiado por resposta DNS imensamente simples, mas eficaz. Ele utiliza um conjunto de dados de entrada fornecido, como uma lista de palavras personalizada ou registros DNS/TLS históricos, para sintetizar com precisão mais nomes de domínio correspondentes e expandi-los ainda mais em um loop com base nas informações coletadas durante a varredura DNS.
```
echo www | subzuf facebook.com
```
### **Fluxo de Trabalho de Descoberta de Subdomínios**

Confira este post de blog que escrevi sobre como **automatizar a descoberta de subdomínios** a partir de um domínio usando **Trickest workflows** para que eu não precise lançar manualmente um monte de ferramentas no meu computador:

{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}

{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Hosts Virtuais**

Se você encontrou um endereço IP contendo **uma ou várias páginas da web** pertencentes a subdomínios, você pode tentar **encontrar outros subdomínios com sites nesse IP** procurando em **fontes OSINT** por domínios em um IP ou **forçando nomes de domínio VHost nesse IP**.

#### OSINT

Você pode encontrar alguns **VHosts em IPs usando** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **ou outras APIs**.

**Força Bruta**

Se você suspeitar que algum subdomínio pode estar oculto em um servidor web, você pode tentar forçá-lo:
```bash
ffuf -c -w /path/to/wordlist -u http://victim.com -H "Host: FUZZ.victim.com"

gobuster vhost -u https://mysite.com -t 50 -w subdomains.txt

wfuzz -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt --hc 400,404,403 -H "Host: FUZZ.example.com" -u http://example.com -t 100

#From https://github.com/allyshka/vhostbrute
vhostbrute.py --url="example.com" --remoteip="10.1.1.15" --base="www.example.com" --vhosts="vhosts_full.list"

#https://github.com/codingo/VHostScan
VHostScan -t example.com
```
> [!NOTE]
> Com esta técnica, você pode até conseguir acessar endpoints internos/ocultos.

### **CORS Brute Force**

Às vezes, você encontrará páginas que retornam apenas o cabeçalho _**Access-Control-Allow-Origin**_ quando um domínio/subdomínio válido é definido no cabeçalho _**Origin**_. Nesses cenários, você pode abusar desse comportamento para **descobrir** novos **subdomínios**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

Enquanto procura por **subdomínios**, fique atento para ver se está **apontando** para algum tipo de **bucket**, e nesse caso [**verifique as permissões**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Além disso, como neste ponto você já conhecerá todos os domínios dentro do escopo, tente [**forçar nomes de buckets possíveis e verificar as permissões**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Monitorização**

Você pode **monitorar** se **novos subdomínios** de um domínio são criados monitorando os **Logs de Transparência de Certificados** [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py)faz.

### **Procurando por vulnerabilidades**

Verifique possíveis [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Se o **subdomínio** estiver apontando para algum **bucket S3**, [**verifique as permissões**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Se você encontrar algum **subdomínio com um IP diferente** dos que você já encontrou na descoberta de ativos, você deve realizar uma **varredura básica de vulnerabilidades** (usando Nessus ou OpenVAS) e alguma [**varredura de portas**](../pentesting-network/index.html#discovering-hosts-from-the-outside) com **nmap/masscan/shodan**. Dependendo dos serviços que estão em execução, você pode encontrar neste livro alguns truques para "atacá-los".\
&#xNAN;_&#x4E;ote que às vezes o subdomínio está hospedado dentro de um IP que não é controlado pelo cliente, então não está no escopo, tenha cuidado._

## IPs

Nos passos iniciais, você pode ter **encontrado alguns intervalos de IP, domínios e subdomínios**.\
É hora de **recolher todos os IPs desses intervalos** e para os **domínios/subdomínios (consultas DNS).**

Usando serviços das seguintes **APIs gratuitas**, você também pode encontrar **IPs anteriores usados por domínios e subdomínios**. Esses IPs podem ainda ser de propriedade do cliente (e podem permitir que você encontre [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

- [**https://securitytrails.com/**](https://securitytrails.com/)

Você também pode verificar domínios apontando para um endereço IP específico usando a ferramenta [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Procurando por vulnerabilidades**

**Varra todas as portas dos IPs que não pertencem a CDNs** (pois você provavelmente não encontrará nada interessante lá). Nos serviços em execução descobertos, você pode ser **capaz de encontrar vulnerabilidades**.

**Encontre um** [**guia**](../pentesting-network/index.html) **sobre como escanear hosts.**

## Caça a servidores web

> Encontramos todas as empresas e seus ativos e sabemos os intervalos de IP, domínios e subdomínios dentro do escopo. É hora de procurar por servidores web.

Nos passos anteriores, você provavelmente já realizou alguma **reconhecimento dos IPs e domínios descobertos**, então você pode já ter **encontrado todos os possíveis servidores web**. No entanto, se você não encontrou, agora vamos ver alguns **truques rápidos para procurar servidores web** dentro do escopo.

Por favor, note que isso será **orientado para descoberta de aplicativos web**, então você deve **realizar a varredura de vulnerabilidades** e **varredura de portas** também (**se permitido** pelo escopo).

Um **método rápido** para descobrir **portas abertas** relacionadas a **servidores** web usando [**masscan** pode ser encontrado aqui](../pentesting-network/index.html#http-port-discovery).\
Outra ferramenta amigável para procurar servidores web é [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) e [**httpx**](https://github.com/projectdiscovery/httpx). Você apenas passa uma lista de domínios e ela tentará se conectar à porta 80 (http) e 443 (https). Além disso, você pode indicar para tentar outras portas:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Capturas de Tela**

Agora que você descobriu **todos os servidores web** presentes no escopo (entre os **IPs** da empresa e todos os **domínios** e **subdomínios**), você provavelmente **não sabe por onde começar**. Então, vamos simplificar e começar apenas tirando capturas de tela de todos eles. Apenas ao **dar uma olhada** na **página principal**, você pode encontrar **endpoints estranhos** que são mais **propensos** a serem **vulneráveis**.

Para realizar a ideia proposta, você pode usar [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) ou [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Além disso, você pode usar [**eyeballer**](https://github.com/BishopFox/eyeballer) para analisar todas as **capturas de tela** e te dizer **o que provavelmente contém vulnerabilidades** e o que não contém.

## Ativos de Nuvem Pública

Para encontrar potenciais ativos de nuvem pertencentes a uma empresa, você deve **começar com uma lista de palavras-chave que identificam essa empresa**. Por exemplo, para uma empresa de criptomoeda, você pode usar palavras como: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Você também precisará de listas de palavras de **palavras comuns usadas em buckets**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Então, com essas palavras, você deve gerar **permutations** (ver [**Segunda Rodada de Brute-Force DNS**](#second-dns-bruteforce-round) para mais informações).

Com as listas de palavras resultantes, você pode usar ferramentas como [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **ou** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Lembre-se de que, ao procurar Ativos de Nuvem, você deve **procurar mais do que apenas buckets na AWS**.

### **Procurando vulnerabilidades**

Se você encontrar coisas como **buckets abertos ou funções de nuvem expostas**, você deve **acessá-los** e tentar ver o que eles oferecem e se você pode abusar deles.

## Emails

Com os **domínios** e **subdomínios** dentro do escopo, você basicamente tem tudo o que **precisa para começar a procurar por emails**. Estas são as **APIs** e **ferramentas** que funcionaram melhor para mim para encontrar emails de uma empresa:

- [**theHarvester**](https://github.com/laramies/theHarvester) - com APIs
- API de [**https://hunter.io/**](https://hunter.io/) (versão gratuita)
- API de [**https://app.snov.io/**](https://app.snov.io/) (versão gratuita)
- API de [**https://minelead.io/**](https://minelead.io/) (versão gratuita)

### **Procurando vulnerabilidades**

Emails serão úteis mais tarde para **brute-force em logins web e serviços de autenticação** (como SSH). Além disso, eles são necessários para **phishings**. Além disso, essas APIs fornecerão ainda mais **informações sobre a pessoa** por trás do email, o que é útil para a campanha de phishing.

## Vazamentos de Credenciais

Com os **domínios,** **subdomínios** e **emails**, você pode começar a procurar por credenciais vazadas no passado pertencentes a esses emails:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Procurando vulnerabilidades**

Se você encontrar credenciais **vazadas válidas**, isso é uma vitória muito fácil.

## Vazamentos de Segredos

Vazamentos de credenciais estão relacionados a hacks de empresas onde **informações sensíveis foram vazadas e vendidas**. No entanto, as empresas podem ser afetadas por **outros vazamentos** cujas informações não estão nessas bases de dados:

### Vazamentos do Github

Credenciais e APIs podem ser vazadas nos **repositórios públicos** da **empresa** ou dos **usuários** que trabalham para essa empresa no github.\
Você pode usar a **ferramenta** [**Leakos**](https://github.com/carlospolop/Leakos) para **baixar** todos os **repositórios públicos** de uma **organização** e de seus **desenvolvedores** e executar [**gitleaks**](https://github.com/zricethezav/gitleaks) sobre eles automaticamente.

**Leakos** também pode ser usado para executar **gitleaks** contra todo o **texto** fornecido **URLs passadas** para ele, pois às vezes **páginas web também contêm segredos**.

#### Dorks do Github

Verifique também esta **página** para potenciais **dorks do github** que você também poderia pesquisar na organização que está atacando:

{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Vazamentos de Pastas

Às vezes, atacantes ou apenas trabalhadores irão **publicar conteúdo da empresa em um site de paste**. Isso pode ou não conter **informações sensíveis**, mas é muito interessante procurar por isso.\
Você pode usar a ferramenta [**Pastos**](https://github.com/carlospolop/Pastos) para pesquisar em mais de 80 sites de paste ao mesmo tempo.

### Dorks do Google

Dorks do Google, embora antigos, são sempre úteis para encontrar **informações expostas que não deveriam estar lá**. O único problema é que o [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) contém vários **milhares** de possíveis consultas que você não pode executar manualmente. Então, você pode pegar suas 10 favoritas ou pode usar uma **ferramenta como** [**Gorks**](https://github.com/carlospolop/Gorks) **para executá-las todas**.

_Observe que as ferramentas que esperam executar todo o banco de dados usando o navegador Google regular nunca terminarão, pois o Google irá bloquear você muito em breve._

### **Procurando vulnerabilidades**

Se você encontrar credenciais ou tokens de API **vazados válidos**, isso é uma vitória muito fácil.

## Vulnerabilidades de Código Público

Se você descobrir que a empresa tem **código de código aberto**, você pode **analisá-lo** e procurar por **vulnerabilidades** nele.

**Dependendo da linguagem**, existem diferentes **ferramentas** que você pode usar:

{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

Existem também serviços gratuitos que permitem que você **escaneie repositórios públicos**, como:

- [**Snyk**](https://app.snyk.io/)

## [**Metodologia de Pentesting Web**](../../network-services-pentesting/pentesting-web/index.html)

A **maioria das vulnerabilidades** encontradas por caçadores de bugs reside dentro de **aplicações web**, então, neste ponto, eu gostaria de falar sobre uma **metodologia de teste de aplicações web**, e você pode [**encontrar essas informações aqui**](../../network-services-pentesting/pentesting-web/index.html).

Eu também quero fazer uma menção especial à seção [**Ferramentas de Scanners Automáticos de Web de Código Aberto**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), pois, se você não deve esperar que elas encontrem vulnerabilidades muito sensíveis, elas são úteis para implementá-las em **fluxos de trabalho para ter algumas informações iniciais da web.**

## Recapitulação

> Parabéns! Neste ponto, você já realizou **toda a enumeração básica**. Sim, é básico porque muito mais enumeração pode ser feita (veremos mais truques mais tarde).

Então você já:

1. Encontrou todas as **empresas** dentro do escopo
2. Encontrou todos os **ativos** pertencentes às empresas (e realizou alguns scans de vulnerabilidades se estiver no escopo)
3. Encontrou todos os **domínios** pertencentes às empresas
4. Encontrou todos os **subdomínios** dos domínios (algum takeover de subdomínio?)
5. Encontrou todos os **IPs** (de e **não de CDNs**) dentro do escopo.
6. Encontrou todos os **servidores web** e tirou uma **captura de tela** deles (algo estranho que vale uma olhada mais profunda?)
7. Encontrou todos os **ativos de nuvem pública potenciais** pertencentes à empresa.
8. **Emails**, **vazamentos de credenciais** e **vazamentos de segredos** que podem te dar uma **grande vitória muito facilmente**.
9. **Pentesting todas as webs que você encontrou**

## **Ferramentas Automáticas de Recon Completo**

Existem várias ferramentas por aí que realizarão parte das ações propostas contra um determinado escopo.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Um pouco antiga e não atualizada

## **Referências**

- Todos os cursos gratuitos de [**@Jhaddix**](https://twitter.com/Jhaddix) como [**A Metodologia do Caçador de Bugs v4.0 - Edição Recon**](https://www.youtube.com/watch?v=p4JgIu1mceI)

{{#include ../../banners/hacktricks-training.md}}
