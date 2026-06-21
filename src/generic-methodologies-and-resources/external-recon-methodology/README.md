# External Recon Methodology

{{#include ../../banners/hacktricks-training.md}}

## Descoberta de ativos

> Então foi dito a você que tudo pertencente a alguma empresa está dentro do escopo, e você quer descobrir o que essa empresa realmente possui.

O objetivo desta fase é obter todas as **empresas pertencentes à empresa principal** e depois todos os **ativos** dessas empresas. Para isso, vamos:

1. Encontrar as aquisições da empresa principal, isso nos dará as empresas dentro do escopo.
2. Encontrar o ASN (se houver) de cada empresa, isso nos dará os ranges de IP pertencentes a cada empresa
3. Usar reverse whois lookups para શોધar outras entradas (nomes de organização, domínios...) relacionadas à primeira (isso pode ser feito recursivamente)
4. Usar outras técnicas como filtros `org` e `ssl` do shodan para buscar outros ativos (o truque do `ssl` pode ser feito recursivamente).

### **Aquisições**

Antes de tudo, precisamos saber quais **outras empresas são pertencentes à empresa principal**.\
Uma opção é visitar [https://www.crunchbase.com/](https://www.crunchbase.com), **procurar** pela **empresa principal**, e **clicar** em "**acquisitions**". Lá você verá outras empresas adquiridas pela principal.\
Outra opção é visitar a página da **Wikipedia** da empresa principal e procurar por **acquisitions**.\
Para empresas públicas, verifique **arquivos SEC/EDGAR**, páginas de **investor relations**, ou registros corporativos locais (por exemplo, **Companies House** no Reino Unido).\
Para árvores corporativas globais e subsidiárias, tente **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) e a base de dados **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> Ok, neste ponto você deve conhecer todas as empresas dentro do escopo. Vamos descobrir como encontrar seus ativos.

### **ASNs**

Um número de sistema autônomo (**ASN**) é um **número único** atribuído a um **sistema autônomo** (AS) pela **Internet Assigned Numbers Authority (IANA)**.\
Um **AS** consiste em **blocos** de **endereços IP** que têm uma política claramente definida para acessar redes externas e é administrado por uma única organização, mas pode ser composto por vários operadores.

É interessante descobrir se a **empresa atribuiu algum ASN** para encontrar seus **ranges de IP**.\
Será interessante realizar um **teste de vulnerabilidade** contra todos os **hosts** dentro do **escopo** e **procurar domínios** dentro desses IPs.\
Você pode **procurar** por **nome** da empresa, por **IP** ou por **domínio** em [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **ou** [**https://ipinfo.io/**](https://ipinfo.io/).\
**Dependendo da região da empresa, estes links podem ser úteis para coletar mais dados:** [**AFRINIC**](https://www.afrinic.net) **(África),** [**Arin**](https://www.arin.net/about/welcome/region/)**(América do Norte),** [**APNIC**](https://www.apnic.net) **(Ásia),** [**LACNIC**](https://www.lacnic.net) **(América Latina),** [**RIPE NCC**](https://www.ripe.net) **(Europa). De qualquer forma, provavelmente todas as** informações úteis **(ranges de IP e Whois)** já aparecem no primeiro link.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Também, [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s**
enumeração agrega e resume automaticamente ASNs no final do scan.
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
Você pode encontrar os intervalos de IP de uma organização também usando [http://asnlookup.com/](http://asnlookup.com) (ele tem API gratuita).\
Você pode encontrar o IP e o ASN de um domínio usando [http://ipv4info.com/](http://ipv4info.com).

### **Procurando vulnerabilidades**

Neste ponto sabemos **todos os assets dentro do escopo**, então, se você tiver permissão, poderia lançar algum **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) sobre todos os hosts.\
Também, você poderia lançar algumas [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **ou usar serviços como** Shodan, Censys, ou ZoomEye **para encontrar** open ports **e, dependendo do que encontrar, você deve** dar uma olhada neste livro para saber como fazer pentest de vários serviços possíveis em execução.\
**Além disso, pode valer a pena mencionar que você também pode preparar algumas** default username **e** passwords **lists e tentar** bruteforce serviços com [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domains

> Sabemos todas as empresas dentro do escopo e seus assets, é hora de encontrar os domains dentro do escopo.

_Por favor, note que nas técnicas propostas a seguir você também pode encontrar subdomains e essa informação não deve ser subestimada._

Primeiro de tudo, você deve procurar o(s) **main domain** de cada empresa. Por exemplo, para _Tesla Inc._ vai ser _tesla.com_.

### **Reverse DNS**

Como você encontrou todos os intervalos de IP dos domains, você poderia tentar realizar **reverse dns lookups** nesses **IPs para encontrar mais domains dentro do escopo**. Tente usar algum dns server da vítima ou algum dns server bem conhecido (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Para que isso funcione, o administrador precisa habilitar manualmente o PTR.\
Você também pode usar uma ferramenta online para essa informação: [http://ptrarchive.com/](http://ptrarchive.com).\
Para ranges grandes, ferramentas como [**massdns**](https://github.com/blechschmidt/massdns) e [**dnsx**](https://github.com/projectdiscovery/dnsx) são úteis para automatizar reverse lookups e enrichment.

### **Reverse Whois (loop)**

Dentro de um **whois** você pode encontrar muita **informação** interessante como **organisation name**, **address**, **emails**, números de telefone... Mas o que é ainda mais interessante é que você pode encontrar **mais assets relacionados à empresa** se fizer **reverse whois lookups por qualquer um desses campos** (por exemplo, outros registros whois onde o mesmo email aparece).\
Você pode usar ferramentas online como:

- [https://ip.thc.org/](https://ip.thc.org/) - **Free** (Web e API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Free**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Free**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Free**
- [https://www.whoxy.com/](https://www.whoxy.com) - **Free** web, API não é free.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Not free
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Not Free (apenas **100 free** searches)
- [https://www.domainiq.com/](https://www.domainiq.com) - Not Free
- [https://securitytrails.com/](https://securitytrails.com/) - Not free (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - Not free (API)

Você pode automatizar essa tarefa usando [**DomLink** ](https://github.com/vysecurity/DomLink)(requires a whoxy API key).\
Você também pode realizar alguma descoberta automática de reverse whois com [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Note that you can use this technique to discover more domain names every time you find a new domain.**

### **Trackers**

Se você encontrar o **mesmo ID do mesmo tracker** em 2 páginas diferentes, você pode supor que **ambas as páginas** são **managed by the same team**.\
Por exemplo, se você vir o mesmo **Google Analytics ID** ou o mesmo **Adsense ID** em várias páginas.

Há algumas páginas e ferramentas que permitem buscar por esses trackers e mais:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (finds related sites by shared analytics/trackers)

### **Favicon**

Você sabia que podemos encontrar domains e subdomains relacionados ao nosso target procurando pelo mesmo hash de ícone favicon? É exatamente isso que a ferramenta [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py), feita por [@m4ll0k2](https://twitter.com/m4ll0k2), faz. Aqui está como usá-la:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - discover domains with the same favicon icon hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Simplificando, o favihash nos permitirá descobrir domínios que têm o mesmo hash do ícone favicon que o nosso alvo.

Além disso, você também pode buscar tecnologias usando o hash do favicon, como explicado neste [**this blog post**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139). Isso significa que, se você souber o **hash do favicon de uma versão vulnerável de uma tecnologia web**, você pode pesquisar no shodan e **encontrar mais locais vulneráveis**:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
É assim que você pode **calcular o favicon hash** de uma web:
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
Você também pode obter hashes de favicon em escala com [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) e então pivotar em Shodan/Censys.

### **Copyright / Uniq string**

Pesquise dentro das páginas web **strings que possam ser compartilhadas entre diferentes webs na mesma organização**. A **copyright string** pode ser um bom exemplo. Depois pesquise essa string no **google**, em outros **browsers** ou até mesmo no **shodan**: `shodan search http.html:"Copyright string"`

### **CRT Time**

É comum haver um cron job como
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
to renovar todos os certificados de domínio no servidor. Isso significa que, mesmo que a CA usada para isso não defina o horário em que foi gerada no tempo de Validity, é possível **encontrar domínios pertencentes à mesma empresa nos certificate transparency logs**.\
Confira este [**writeup para mais informações**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

Também use logs de **certificate transparency** diretamente:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Informações de Mail DMARC

Você pode usar um web such as [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) ou uma tool such as [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) para encontrar **domains and subdomain sharing the same dmarc information**.\
Outras tools úteis são [**spoofcheck**](https://github.com/BishopFox/spoofcheck) e [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Aparentemente é comum as pessoas atribuírem subdomains a IPs que pertencem a cloud providers e, em algum momento, **perderem esse endereço IP mas esquecerem de remover o registro DNS**. Portanto, apenas **iniciar uma VM** em uma cloud (como Digital Ocean) fará com que você realmente esteja **assumindo alguns subdomain(s)**.

[**Este post**](https://kmsec.uk/blog/passive-takeover/) explica uma história sobre isso e propõe um script que **inicia uma VM no DigitalOcean**, **obtém** o **IPv4** da nova máquina e **procura no Virustotal por registros de subdomain** apontando para ela.

### **Outras formas**

**Note que você pode usar esta técnica para descobrir mais nomes de domínio sempre que encontrar um novo domínio.**

**Shodan**

Como você já conhece o nome da organização que possui o espaço de IPs. Você pode pesquisar por esses dados no shodan usando: `org:"Tesla, Inc."` Verifique os hosts encontrados em busca de novos domains inesperados no certificado TLS.

Você pode acessar o **TLS certificate** da página web principal, obter o **nome da Organisation** e então pesquisar por esse nome dentro dos **TLS certificates** de todas as páginas web conhecidas pelo **shodan** com o filtro : `ssl:"Tesla Motors"` ou usar uma tool como [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)é uma tool que procura por **domains relacionados** com um domínio principal e seus **subdomains**, bem impressionante.

**Passive DNS / Historical DNS**

Dados de Passive DNS são ótimos para encontrar **old and forgotten records** que ainda resolvem ou que podem ser assumidos. Veja:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Procurando vulnerabilidades**

Verifique se há algum [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Talvez alguma empresa esteja **usando algum domain** mas tenha **perdido a posse** dele. Basta registrá-lo (se for barato o suficiente) e avisar a empresa.

Se você encontrar algum **domain com um IP diferente** dos que já encontrou na descoberta de assets, você deve realizar uma **varredura básica de vulnerabilidades** (usando Nessus ou OpenVAS) e alguma [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) com **nmap/masscan/shodan**. Dependendo de quais services estão em execução, você pode encontrar **neste livro alguns truques para "atacá-los"**.\
_Note que às vezes o domínio está hospedado em um IP que não é controlado pelo cliente, então não está no escopo, tenha cuidado._

## Subdomains

> Sabemos todas as companies dentro do escopo, todos os assets de cada company e todos os domains relacionados às companies.

É hora de encontrar todos os possíveis subdomains de cada domain encontrado.

> [!TIP]
> Note que algumas das tools e técnicas para encontrar domains também podem ajudar a encontrar subdomains

### **DNS**

Vamos tentar obter **subdomains** a partir dos registros de **DNS**. Também devemos tentar **Zone Transfer** (se for vulnerável, você deve reportá-la).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

A forma mais rápida de obter muitos subdomínios é pesquisar em fontes externas. As **tools** mais usadas são as seguintes (para melhores resultados, configure as chaves de API):

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
Existem **outras ferramentas/APIs interessantes** que, mesmo não sendo diretamente especializadas em encontrar subdomínios, podem ser úteis para encontrar subdomínios, como:

- [**IP.THC.ORG**](https://ip.thc.org) free API
```bash
curl https://ip.thc.org/tesla.com
```
- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Usa a API [https://sonar.omnisint.io](https://sonar.omnisint.io) para obter subdomínios
```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```
- [**API gratuita JLDC**](https://jldc.me/anubis/subdomains/google.com)
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
- [**gau**](https://github.com/lc/gau)**:** obtém URLs conhecidas do AlienVault's Open Threat Exchange, da Wayback Machine e do Common Crawl para qualquer domínio fornecido.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Eles vasculham a web procurando arquivos JS e extraem subdomínios de lá.
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
- [**securitytrails.com**](https://securitytrails.com/) has a free API para buscar subdomínios e histórico de IP
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

This project offers de graça todos os subdomínios relacionados a programas de bug-bounty. You can access this data also using [chaospy](https://github.com/dr-0x0x/chaospy) or even access the scope used by this project [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

You can find a **comparison** of many of these tools here: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Let's try to find new **subdomains** fazendo brute-forcing em servidores DNS usando possíveis nomes de subdomínio.

For this action you will need some **common subdomains wordlists like**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

And also IPs of good DNS resolvers. In order to generate a list of trusted DNS resolvers you can download the resolvers from [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) and use [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) to filter them. Or you could use: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

The most recommended tools for DNS brute-force are:

- [**massdns**](https://github.com/blechschmidt/massdns): This was the first tool that performed an effective DNS brute-force. It's very fast however it's prone to false positives.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Este acho que usa apenas 1 resolver
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) é um wrapper em torno de `massdns`, escrito em go, que permite enumerar subdomínios válidos usando bruteforce ativo, bem como resolver subdomínios com tratamento de wildcard e suporte fácil a input-output.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): Ele também usa `massdns`.
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) usa asyncio para fazer brute force de nomes de domínio de forma assíncrona.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Segunda Rodada de Força Bruta de DNS

Depois de encontrar subdomínios usando fontes abertas e força bruta, você pode gerar variações dos subdomínios encontrados para tentar encontrar ainda mais. Várias ferramentas são úteis para esse propósito:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Dado os domínios e subdomínios, gera permutações.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): Dados os domínios e subdomínios, gera permutações.
- Você pode obter a **wordlist** de permutações do **goaltdns** [**aqui**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** Dado os domínios e subdomínios, gere permutações. Se nenhum arquivo de permutações for indicado, o gotator usará o seu próprio.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Além de gerar permutações de subdomínios, também pode tentar resolvê-las (mas é melhor usar as ferramentas comentadas anteriormente).
- Você pode obter a **wordlist** de permutações do altdns [**aqui**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Outra ferramenta para realizar permutações, mutações e alteração de subdomínios. Esta ferramenta fará força bruta no resultado (não suporta wildcard de DNS).
- Você pode obter a wordlist de permutações do dmut [**aqui**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Baseado em um domínio, ele **gera novos nomes de subdomínios potenciais** com base em padrões indicados para tentar descobrir mais subdomínios.

#### Geração inteligente de permutações

- [**regulator**](https://github.com/cramppet/regulator): Para mais informações, leia este [**post**](https://cramppet.github.io/regulator/index.html), mas basicamente ele obtém as **partes principais** dos **subdomínios descobertos** e as mistura para encontrar mais subdomínios.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ é um fuzzer de brute-force de subdomínios combinado com um algoritmo guiado por respostas DNS extremamente simples, mas eficaz. Ele utiliza um conjunto fornecido de dados de entrada, como uma wordlist personalizada ou registros históricos de DNS/TLS, para sintetizar com precisão mais nomes de domínio correspondentes e expandi-los ainda mais em um loop com base nas informações coletadas durante a varredura DNS.
```
echo www | subzuf facebook.com
```
### **Fluxo de Trabalho de Descoberta de Subdomínios**

Confira este post do blog que escrevi sobre como **automatizar a descoberta de subdomínios** de um domínio usando **Trickest workflows** para que eu não precise executar manualmente um monte de ferramentas no meu computador:


{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}


{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtual Hosts**

Se você encontrou um endereço IP contendo **uma ou várias páginas web** pertencentes a subdomínios, você pode tentar **encontrar outros subdomínios com webs nesse IP** procurando em **fontes OSINT** por domínios em um IP ou por **brute-forcing de nomes de domínio VHost nesse IP**.

#### OSINT

Você pode encontrar alguns **VHosts em IPs usando** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **ou outras APIs**.

**Brute Force**

Se você suspeitar que algum subdomínio pode estar escondido em um servidor web, você pode tentar fazer brute force dele:

Quando o **IP redireciona para um hostname** (name-based vhosts), faça fuzz do header `Host` diretamente e deixe o ffuf **auto-calibrate** para destacar respostas que diferem do vhost padrão:
```bash
ffuf -u http://10.10.10.10 -H "Host: FUZZ.example.com" \
-w /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -ac
```

```bash
ffuf -c -w /path/to/wordlist -u http://victim.com -H "Host: FUZZ.victim.com"

gobuster vhost -u https://mysite.com -t 50 -w subdomains.txt

wfuzz -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt --hc 400,404,403 -H "Host: FUZZ.example.com" -u http://example.com -t 100

#From https://github.com/allyshka/vhostbrute
vhostbrute.py --url="example.com" --remoteip="10.1.1.15" --base="www.example.com" --vhosts="vhosts_full.list"

#https://github.com/codingo/VHostScan
VHostScan -t example.com
```
> [!TIP]
> Com esta técnica, você pode até ser capaz de acessar endpoints internos/ocultos.

### **CORS Brute Force**

Às vezes, você encontrará páginas que só retornam o cabeçalho _**Access-Control-Allow-Origin**_ quando um domínio/subdomínio válido é definido no cabeçalho _**Origin**_. Nesses cenários, você pode abusar desse comportamento para **descobrir** novos **subdomínios**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

Enquanto procura por **subdomains**, fique atento para ver se ele está **apontando** para algum tipo de **bucket**, e nesse caso [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Além disso, como neste ponto você já conhecerá todos os domains dentro do escopo, tente [**brute force possible bucket names and check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Monitorization**

Você pode **monitorar** se **novos subdomains** de um domain são criados monitorando os Logs de **Certificate Transparency** [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py)faz isso.

### **Looking for vulnerabilities**

Verifique possíveis [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Se o **subdomain** estiver apontando para algum **S3 bucket**, [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Se você encontrar algum **subdomain with an IP different** dos que já encontrou na descoberta de assets, você deve realizar um **basic vulnerability scan** (usando Nessus ou OpenVAS) e algum [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) com **nmap/masscan/shodan**. Dependendo de quais services estiverem rodando, você pode encontrar neste book alguns truques para "attack"á-los.\
_Nota: às vezes o subdomain está hospedado dentro de um IP que não é controlado pelo client, então não está no scope, tenha cuidado._

## IPs

Nas etapas iniciais, você pode ter **found some IP ranges, domains and subdomains**.\
É hora de **recolher todos os IPs** desses ranges e dos **domains/subdomains (DNS queries).**

Usando services dos seguintes **free apis**, você também pode encontrar **previous IPs used by domains and subdomains**. Esses IPs ainda podem pertencer ao client (e podem permitir que você encontre [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

- [**https://securitytrails.com/**](https://securitytrails.com/)

Você também pode verificar domains apontando para um endereço IP específico usando a ferramenta [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Looking for vulnerabilities**

**Port scan all the IPs that doesn’t belong to CDNs** (pois, muito provavelmente, você não encontrará nada interessante ali). Nos services em execução descobertos, você pode ser **capaz de encontrar vulnerabilities**.

**Find a** [**guide**](../pentesting-network/index.html) **about how to scan hosts.**

## Web servers hunting

> Encontramos todas as companies e seus assets e sabemos os ranges de IP, domains e subdomains dentro do scope. É hora de procurar web servers.

Nas etapas anteriores, você provavelmente já realizou algum **recon of the IPs and domains discovered**, então talvez já tenha **found all the possible web servers**. Porém, se ainda não, agora vamos ver alguns **fast tricks to search for web servers** dentro do scope.

Por favor, note que isso será **oriented for web apps discovery**, então você também deve **perform the vulnerability** e **port scanning** (**if allowed** pelo scope).

Um **fast method** para descobrir **ports open** relacionados a servidores **web** usando [**masscan** can be found here](../pentesting-network/index.html#http-port-discovery).\
Outra ferramenta amigável para procurar web servers é [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) e [**httpx**](https://github.com/projectdiscovery/httpx). Você só precisa passar uma lista de domains e ela tentará conectar na porta 80 (http) e 443 (https). Além disso, você pode indicar para tentar outras portas:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Screenshots**

Agora que você descobriu **todos os web servers** presentes no escopo (entre os **IPs** da empresa e todos os **domains** e **subdomains**) você provavelmente **não sabe por onde começar**. Então, vamos simplificar e começar apenas tirando screenshots de todos eles. Só de **dar uma olhada** na **main page** você pode encontrar endpoints **estranhos** que são **mais propensos** a serem **vulnerable**.

Para executar a ideia proposta, você pode usar [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) ou [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Além disso, você pode então usar [**eyeballer**](https://github.com/BishopFox/eyeballer) para analisar todas as **screenshots** e dizer **o que provavelmente contém vulnerabilities** e o que não contém.

## Public Cloud Assets

Para encontrar possíveis cloud assets pertencentes a uma empresa, você deve **começar com uma lista de keywords que identifiquem essa empresa**. Por exemplo, para uma empresa de crypto, você pode usar palavras como: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Você também precisará de wordlists de **common words usados em buckets**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Depois, com essas palavras, você deve gerar **permutations** (veja o [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) para mais informações).

Com as wordlists resultantes, você pode usar tools como [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **ou** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Lembre-se de que, ao procurar por Cloud Assets, você deve p**rocurar por mais do que apenas buckets em AWS**.

### **Looking for vulnerabilities**

Se você encontrar coisas como **open buckets ou cloud functions exposed**, você deve **acessá-las** e tentar ver o que elas oferecem e se você consegue abusar delas.

## Emails

Com os **domains** e **subdomains** dentro do escopo, você basicamente já tem tudo o que **precisa para começar a procurar emails**. Estas são as **APIs** e **tools** que melhor funcionaram para mim para encontrar emails de uma empresa:

- [**theHarvester**](https://github.com/laramies/theHarvester) - com APIs
- API de [**https://hunter.io/**](https://hunter.io/) (versão gratuita)
- API de [**https://app.snov.io/**](https://app.snov.io/) (versão gratuita)
- API de [**https://minelead.io/**](https://minelead.io/) (versão gratuita)

### **Looking for vulnerabilities**

Emails serão úteis mais tarde para **brute-force web logins e auth services** (como SSH). Além disso, eles são necessários para **phishings**. Ademais, essas APIs vão fornecer ainda mais **info sobre a pessoa** por trás do email, o que é útil para a campanha de phishing.

## Credential Leaks

Com os **domains**, **subdomains** e **emails**, você pode começar a procurar por credenciais vazadas no passado pertencentes a esses emails:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Looking for vulnerabilities**

Se você encontrar credenciais **valid leaked**, isso é uma vitória muito fácil.

## Secrets Leaks

Credential leaks estão relacionadas a hacks de empresas em que **sensitive information was leaked and sold**. No entanto, empresas podem ser afetadas por **outros leaks** cujo info não esteja nesses bancos de dados:

### Github Leaks

Credentials e APIs podem vazar nos **public repositories** da **company** ou dos **users** que trabalham nessa github company.\
Você pode usar a **tool** [**Leakos**](https://github.com/carlospolop/Leakos) para **download** de todos os **public repos** de uma **organization** e de seus **developers** e executar [**gitleaks**](https://github.com/zricethezav/gitleaks) sobre eles automaticamente.

**Leakos** também pode ser usado para executar **gitleaks** agains todos os **text** fornecidos em **URLs passed** a ele, já que às vezes **web pages also contains secrets**.

#### Github Dorks

Confira também esta **page** para possíveis **github dorks** que você também pode pesquisar na organization que está atacando:


{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

Às vezes, attackers ou apenas workers vão **publish company content in a paste site**. Isso pode ou não conter **sensitive information**, mas é muito interessante procurar por isso.\
Você pode usar a tool [**Pastos**](https://github.com/carlospolop/Pastos) para pesquisar em mais de 80 paste sites ao mesmo tempo.

### Google Dorks

Old but gold google dorks são sempre úteis para encontrar **exposed information that shouldn't be there**. O único problema é que o [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) contém vários **thousands** de possíveis queries que você não pode executar manualmente. Então, você pode pegar seus 10 favoritos ou pode usar uma **tool such as** [**Gorks**](https://github.com/carlospolop/Gorks) **to run them all**.

_Note que as tools que esperam executar todo o banco de dados usando o navegador regular do Google nunca vão terminar, pois o google irá bloqueá-lo muito muito em breve._

### **Looking for vulnerabilities**

Se você encontrar credenciais **valid leaked** ou API tokens, isso é uma vitória muito fácil.

## Public Code Vulnerabilities

Se você descobrir que a empresa tem **open-source code**, você pode **analisar** isso e procurar por **vulnerabilities** nele.

**Dependendo da language** existem diferentes **tools** que você pode usar:


{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

Também existem serviços gratuitos que permitem **scan public repositories**, como:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

A **maioria das vulnerabilities** encontradas por bug hunters fica dentro de **web applications**, então neste ponto eu gostaria de falar sobre uma **web application testing methodology**, e você pode [**encontrar essas informações aqui**](../../network-services-pentesting/pentesting-web/index.html).

Também quero fazer uma menção especial à seção [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), pois, embora você não deva esperar que elas encontrem vulnerabilities muito sensíveis, elas são úteis para implementá-las em **workflows para obter algumas informações iniciais da web**.

## Recapitulation

> Parabéns! Neste ponto, você já realizou **toda a enumeração básica**. Sim, ela é básica porque muito mais enumeração pode ser feita (veremos mais truques depois).

Então você já:

1. Encontrou todas as **companies** dentro do escopo
2. Encontrou todos os **assets** pertencentes às companies (e realizou algum scan de vuln se estiver no escopo)
3. Encontrou todos os **domains** pertencentes às companies
4. Encontrou todos os **subdomains** dos domains (algum subdomain takeover?)
5. Encontrou todos os **IPs** (de e **não de CDNs**) dentro do escopo.
6. Encontrou todos os **web servers** e tirou uma **screenshot** deles (algo estranho que valha uma análise mais profunda?)
7. Encontrou todos os **potential public cloud assets** pertencentes à empresa.
8. **Emails**, **credentials leaks** e **secret leaks** que podem lhe dar uma **grande vitória muito facilmente**.
9. **Pentesting all the webs you found**

## **Full Recon Automatic Tools**

Há várias tools por aí que executarão parte das ações propostas contra um dado escopo.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Um pouco antigo e não atualizado

## **References**

- Todos os cursos gratuitos de [**@Jhaddix**](https://twitter.com/Jhaddix), como [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)

{{#include ../../banners/hacktricks-training.md}}
