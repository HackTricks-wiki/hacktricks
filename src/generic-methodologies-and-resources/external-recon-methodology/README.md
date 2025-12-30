# Metodologia de Recon Externo

{{#include ../../banners/hacktricks-training.md}}

## Descoberta de ativos

> Então foi dito que tudo pertencente a alguma empresa está dentro do escopo, e você quer descobrir o que essa empresa realmente possui.

O objetivo desta fase é obter todas as **empresas pertencentes à empresa principal** e então todos os **ativos** dessas empresas. Para isso, vamos:

1. Encontrar as aquisições da empresa principal, isso nos dará as empresas dentro do escopo.
2. Encontrar o ASN (se houver) de cada empresa, isso nos dará os intervalos de IP pertencentes a cada empresa.
3. Usar reverse whois lookups para buscar outras entradas (nomes de organização, domínios...) relacionadas à primeira (isso pode ser feito recursivamente).
4. Usar outras técnicas como shodan `org` and `ssl` filters para procurar outros ativos (o truque `ssl` pode ser feito recursivamente).

### **Aquisições**

Antes de tudo, precisamos saber quais **outras empresas são possuídas pela empresa principal**.\
Uma opção é visitar [https://www.crunchbase.com/](https://www.crunchbase.com), **pesquisar** pela **empresa principal**, e **clicar** em "**acquisitions**". Lá você verá outras empresas adquiridas pela principal.\
Outra opção é visitar a página da **Wikipedia** da empresa principal e procurar por **acquisitions**.\
Para empresas públicas, verifique os **SEC/EDGAR filings**, as páginas de **investor relations**, ou registros corporativos locais (por exemplo, **Companies House** no Reino Unido).\
Para árvores corporativas globais e subsidiárias, tente **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) e o banco de dados **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> Ok, neste ponto você deve conhecer todas as empresas dentro do escopo. Vamos descobrir como encontrar seus ativos.

### **ASNs**

Um número de sistema autônomo (**ASN**) é um **número único** atribuído a um **sistema autônomo** (AS) pela **Internet Assigned Numbers Authority (IANA)**.\
Um **AS** consiste em **blocos** de **endereços IP** que têm uma política distintamente definida para acessar redes externas e são administrados por uma única organização, mas podem ser compostos por vários operadores.

É interessante verificar se a **empresa atribuiu algum ASN** para encontrar seus **intervalos de IP.** Será interessante realizar um **vulnerability test** contra todos os **hosts** dentro do **scope** e **procurar por domínios** dentro desses IPs.\
Você pode **buscar** pelo **nome** da empresa, por **IP** ou por **domínio** em [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **ou** [**https://ipinfo.io/**](https://ipinfo.io/).\
**Dependendo da região da empresa, estes links podem ser úteis para coletar mais dados:** [**AFRINIC**](https://www.afrinic.net) **(África),** [**Arin**](https://www.arin.net/about/welcome/region/)**(América do Norte),** [**APNIC**](https://www.apnic.net) **(Ásia),** [**LACNIC**](https://www.lacnic.net) **(América Latina),** [**RIPE NCC**](https://www.ripe.net) **(Europa). De qualquer forma, provavelmente todas as** informações úteis **(intervalos de IP e Whois)** já aparecem no primeiro link.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Além disso, [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s** enumeration agrega e resume automaticamente ASNs ao final do scan.
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

Neste ponto sabemos **todos os assets dentro do scope**, então se você tiver permissão pode lançar alguns **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) sobre todos os hosts.\
Além disso, você pode lançar alguns [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **ou usar serviços como** Shodan, Censys, ou ZoomEye **para encontrar** portas abertas **e dependendo do que você encontrar você deve** consultar este livro sobre como realizar pentesting em vários serviços possíveis em execução.\
**Também, pode valer a pena mencionar que você também pode preparar algumas** default username **e** passwords **lists e tentar** bruteforce serviços com [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domínios

> Sabemos todas as empresas dentro do scope e seus assets, é hora de encontrar os domínios dentro do scope.

_Por favor, note que nas técnicas a seguir propostas você também pode encontrar subdomains e que essa informação não deve ser subestimada._

Primeiro de tudo você deve procurar pelo(s) **main domain** de cada empresa. Por exemplo, para _Tesla Inc._ será _tesla.com_.

### **Reverse DNS**

Como você encontrou todos os intervalos de IP dos domínios, você pode tentar realizar **reverse dns lookups** nesses **IPs para encontrar mais domínios dentro do scope**. Tente usar algum dns server da vítima ou algum dns server conhecido (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Para que isso funcione, o administrador tem de habilitar manualmente o PTR.\
Você também pode usar uma ferramenta online para essa informação: [http://ptrarchive.com/](http://ptrarchive.com).\
Para ranges grandes, ferramentas como [**massdns**](https://github.com/blechschmidt/massdns) e [**dnsx**](https://github.com/projectdiscovery/dnsx) são úteis para automatizar buscas reversas e enriquecimento.

### **Reverse Whois (loop)**

Dentro de um **whois** você pode encontrar muitas **informações** interessantes como **nome da organização**, **endereço**, **emails**, números de telefone... Mas o que é ainda mais interessante é que você pode encontrar **mais ativos relacionados à empresa** se realizar **reverse whois lookups by any of those fields** (por exemplo outros registros whois onde o mesmo email aparece).\
Você pode usar ferramentas online como:

- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Grátis**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Grátis**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Grátis**
- [https://www.whoxy.com/](https://www.whoxy.com/) - **Grátis** web, API paga.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Pago
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Pago (apenas **100** buscas grátis)
- [https://www.domainiq.com/](https://www.domainiq.com) - Pago
- [https://securitytrails.com/](https://securitytrails.com/) - Pago (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - Pago (API)

Você pode automatizar essa tarefa usando [**DomLink** ](https://github.com/vysecurity/DomLink)(requer uma chave API do whoxy).\
Você também pode realizar alguma descoberta automática de reverse whois com [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Note que você pode usar esta técnica para descobrir mais nomes de domínio sempre que encontrar um novo domínio.**

### **Trackers**

Se encontrar o **mesmo ID do mesmo tracker** em 2 páginas diferentes, você pode supor que **ambas as páginas** são **gerenciadas pela mesma equipe**.\
Por exemplo, se você vir o mesmo **Google Analytics ID** ou o mesmo **Adsense ID** em várias páginas.

Existem algumas páginas e ferramentas que permitem buscar por esses trackers e mais:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (finds related sites by shared analytics/trackers)

### **Favicon**

Você sabia que podemos encontrar domínios e subdomínios relacionados ao nosso alvo procurando o mesmo hash do ícone favicon? É exatamente isso que a ferramenta [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) feita por [@m4ll0k2](https://twitter.com/m4ll0k2) faz. Aqui está como usá-la:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - discover domains with the same favicon icon hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Simplificando, favihash nos permitirá descobrir domínios que possuem o mesmo hash do favicon que o nosso alvo.

Além disso, você também pode pesquisar tecnologias usando o hash do favicon como explicado em [**este post do blog**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139). Isso significa que, se você souber o **hash do favicon de uma versão vulnerável de uma tecnologia web** você pode pesquisá-lo no shodan e **encontrar mais locais vulneráveis**:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
Veja como você pode **calculate the favicon hash** de um site:
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
Você também pode obter hashes de favicon em escala com [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) e então pivot em Shodan/Censys.

### **Copyright / Uniq string**

Procure dentro das páginas web por **strings que possam ser compartilhadas entre diferentes sites da mesma organização**. A **copyright string** pode ser um bom exemplo. Depois pesquise essa string no **google**, em outros **navegadores** ou até mesmo no **shodan**: `shodan search http.html:"Copyright string"`

### **CRT Time**

É comum ter um cron job como
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
para renovar todos os certificados de domínio no servidor. Isso significa que mesmo que a CA usada para isso não defina o horário em que foi gerado no campo Validity, é possível **encontrar domínios pertencentes à mesma empresa nos logs de certificate transparency**.\
Check out this [**writeup for more information**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

Also use **certificate transparency** logs directly:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Informações de Mail DMARC

Você pode usar um site como [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) ou uma ferramenta como [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) para encontrar **domínios e subdomínios que compartilham a mesma informação de dmarc**.\
Outras ferramentas úteis são [**spoofcheck**](https://github.com/BishopFox/spoofcheck) e [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Aparentemente é comum que pessoas atribuam subdomínios a IPs que pertencem a provedores de nuvem e, em algum momento, **percam esse endereço IP mas esqueçam de remover o registro DNS**. Portanto, simplesmente **spawning a VM** em uma nuvem (como Digital Ocean) você estará de fato **taking over alguns subdomínios**.

[**This post**](https://kmsec.uk/blog/passive-takeover/) explains a store about it and propose a script that **spawns a VM in DigitalOcean**, **gets** the **IPv4** of the new machine, and **searches in Virustotal for subdomain records** pointing to it.

### **Other ways**

**Note that you can use this technique to discover more domain names every time you find a new domain.**

**Shodan**

Como você já sabe o nome da organização que possui o espaço de IP. Você pode buscar por esse dado no shodan usando: `org:"Tesla, Inc."` Verifique os hosts encontrados por novos domínios inesperados no certificado TLS.

You could access the **TLS certificate** of the main web page, obtain the **Organisation name** and then search for that name inside the **TLS certificates** of all the web pages known by **shodan** with the filter : `ssl:"Tesla Motors"` or use a tool like [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)is a tool that looks for **domains related** with a main domain and **subdomains** of them, pretty amazing.

**Passive DNS / Historical DNS**

Dados de DNS passivo são ótimos para encontrar **registros antigos e esquecidos** que ainda resolvem ou que podem ser tomados. Veja:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Looking for vulnerabilities**

Check for some [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Talvez alguma empresa esteja **usando algum domínio** mas tenha **perdido a propriedade**. Basta registrá-lo (se estiver barato o suficiente) e avisar a empresa.

If you find any **domain with an IP different** from the ones you already found in the assets discovery, you should perform a **basic vulnerability scan** (using Nessus or OpenVAS) and some [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) with **nmap/masscan/shodan**. Depending on which services are running you can find in **this book some tricks to "attack" them**.\
_Note that sometimes the domain is hosted inside an IP that is not controlled by the client, so it's not in the scope, be careful._

## Subdomains

> We know all the companies inside the scope, all the assets of each company and all the domains related to the companies.

É hora de encontrar todos os possíveis subdomínios de cada domínio encontrado.

> [!TIP]
> Observe que algumas das ferramentas e técnicas para encontrar domínios também podem ajudar a encontrar subdomínios

### **DNS**

Vamos tentar obter **subdomínios** a partir dos registros **DNS**. Também devemos tentar um **Zone Transfer** (Se vulnerável, você deve reportar).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

A maneira mais rápida de obter muitos subdomínios é pesquisar em fontes externas. As **ferramentas** mais usadas são as seguintes (para melhores resultados, configure as chaves de API):

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
Existem **outras ferramentas/APIs interessantes** que, mesmo não sendo diretamente especializadas em encontrar subdomains, podem ser úteis para encontrar subdomains, como:

- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Usa a API [https://sonar.omnisint.io](https://sonar.omnisint.io) para obter subdomains
```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```
- [**JLDC API gratuita**](https://jldc.me/anubis/subdomains/google.com)
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
- [**gau**](https://github.com/lc/gau)**:** recupera URLs conhecidas do AlienVault's Open Threat Exchange, do Wayback Machine e do Common Crawl para qualquer domínio.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Eles vasculham a web procurando arquivos JS e extraem subdomains a partir daí.
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
- [**securitytrails.com**](https://securitytrails.com/) has a free API to search for subdomains and IP history
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Este projeto oferece para **free all the subdomains related to bug-bounty programs**. You can access this data also using [chaospy](https://github.com/dr-0x0x/chaospy) or even access the scope used by this project [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

You can find a **comparison** of many of these tools here: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Vamos tentar encontrar novos **subdomínios** brute-forcing servidores DNS usando possíveis nomes de subdomínio.

Para esta ação você precisará de algumas **wordlists comuns de subdomínios, como**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

E também IPs de bons DNS resolvers. Para gerar uma lista de resolvers DNS confiáveis você pode baixar os resolvers de [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) e usar [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) para filtrá-los. Ou você poderia usar: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

The most recommended tools for DNS brute-force are:

- [**massdns**](https://github.com/blechschmidt/massdns): Esta foi a primeira ferramenta que realizou um DNS brute-force efetivo. É muito rápida, no entanto é propensa a falsos positivos.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Este aqui, eu acho, usa apenas 1 resolver.
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) é um wrapper em torno do `massdns`, escrito em go, que permite enumerar subdomínios válidos usando active bruteforce, além de resolver subdomínios com wildcard handling e suporte fácil de entrada/saída.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): Também usa `massdns`.
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) usa asyncio para realizar brute force em nomes de domínio de forma assíncrona.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Segunda rodada de DNS Brute-Force

Após encontrar subdomains usando fontes abertas e brute-forcing, você pode gerar variações dos subdomains encontrados para tentar achar ainda mais. Várias ferramentas são úteis para esse propósito:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Recebe os domains e os subdomains e gera permutações.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): A partir dos domínios e subdomínios, gera permutações.
- Você pode obter a **wordlist** de permutações do goaltdns em [**here**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** A partir dos domínios e subdomínios, gera permutações. Se nenhum arquivo de permutações for indicado, gotator usará o seu próprio.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Além de gerar subdomains permutations, ele também pode tentar resolvê-los (mas é melhor usar as ferramentas comentadas anteriormente).
- Você pode obter altdns permutations **wordlist** em [**here**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Outra ferramenta para realizar permutations, mutations e alteração de subdomínios. Esta ferramenta irá brute force o resultado (não suporta dns wild card).
- Você pode obter a wordlist de permutations do dmut [**aqui**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Com base em um domínio, ele **gera novos nomes potenciais de subdomínios** com base em padrões indicados para tentar descobrir mais subdomínios.

#### Geração inteligente de permutações

- [**regulator**](https://github.com/cramppet/regulator): Para mais info leia este [**post**](https://cramppet.github.io/regulator/index.html) mas basicamente ele irá obter as **partes principais** dos **subdomínios descobertos** e irá misturá-las para encontrar mais subdomínios.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ é um subdomain brute-force fuzzer acoplado a um algoritmo guiado por respostas DNS imensamente simples, mas eficaz. Ele utiliza um conjunto fornecido de dados de entrada, como uma wordlist personalizada ou registros históricos DNS/TLS, para sintetizar com precisão mais nomes de domínio correspondentes e expandi-los ainda mais em um loop com base nas informações coletadas durante o DNS scan.
```
echo www | subzuf facebook.com
```
### **Subdomain Discovery Workflow**

Confira este post no blog que escrevi sobre como **automatizar a descoberta de subdomínios** a partir de um domínio usando **Trickest workflows**, para que eu não precise executar manualmente um monte de ferramentas no meu computador:


{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}


{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtual Hosts**

Se você encontrar um endereço IP contendo **uma ou várias páginas web** pertencentes a subdomínios, pode tentar **encontrar outros subdomínios que hospedam sites nesse IP** procurando em **fontes OSINT** por domínios naquele IP ou fazendo **brute-forcing de nomes de domínio VHost nesse IP**.

#### OSINT

Você pode encontrar alguns **VHosts em IPs usando** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **ou outras APIs**.

**Brute Force**

Se você suspeitar que algum subdomínio esteja oculto em um servidor web, você pode tentar um brute-force:
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
> Com esta técnica você pode até conseguir acessar endpoints internos/ocultos.

### **CORS Brute Force**

Às vezes você encontrará páginas que só retornam o header _**Access-Control-Allow-Origin**_ quando um domain/subdomain válido é definido no _**Origin**_ header. Nesses cenários, você pode abusar desse comportamento para **descobrir** novos **subdomains**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

Enquanto procura por **subdomains** fique atento para ver se está **pointing** para algum tipo de **bucket**, e, nesse caso, [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Além disso, como a essa altura você já conhecerá todos os domínios dentro do scope, tente [**brute force possible bucket names and check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Monitorization**

Você pode **monitorar** se **new subdomains** de um domínio são criados monitorando os **Certificate Transparency** Logs, como o [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py) faz.

### **Looking for vulnerabilities**

Verifique possíveis [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Se o **subdomain** estiver **pointing** para algum **S3 bucket**, [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Se você encontrar qualquer **subdomain with an IP different** dos que já encontrou na descoberta de assets, deve executar um **basic vulnerability scan** (usando Nessus ou OpenVAS) e alguns [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) com **nmap/masscan/shodan**. Dependendo dos serviços que estiverem rodando, você pode encontrar neste livro alguns truques para "attack" them.\
_Note that sometimes the subdomain is hosted inside an IP that is not controlled by the client, so it's not in the scope, be careful._

## IPs

Nas etapas iniciais você pode ter **encontrado alguns IP ranges, domains e subdomains**.\
É hora de **recolher todos os IPs dessas ranges** e para os **domains/subdomains (DNS queries).**

Usando serviços das seguintes **free apis** você também pode encontrar **previous IPs used by domains and subdomains**. Esses IPs ainda podem ser propriedade do cliente (e podem permitir que você encontre [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

- [**https://securitytrails.com/**](https://securitytrails.com/)

Você também pode checar por domains que apontam para um IP específico usando a ferramenta [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Looking for vulnerabilities**

**Port scan all the IPs that doesn’t belong to CDNs** (pois muito provavelmente você não encontrará nada de interesse lá). Nos serviços em execução descobertos você pode **ser capaz de encontrar vulnerabilidades**.

**Find a** [**guide**](../pentesting-network/index.html) **about how to scan hosts.**

## Web servers hunting

> Encontramos todas as empresas e seus assets e sabemos IP ranges, domains e subdomains dentro do scope. É hora de procurar por web servers.

Nos passos anteriores você provavelmente já realizou algum **recon of the IPs and domains discovered**, então talvez já tenha **already found all the possible web servers**. Entretanto, se não, agora vamos ver alguns **fast tricks to search for web servers** dentro do scope.

Por favor, note que isso será **oriented for web apps discovery**, então você deve **perform the vulnerability** e também **port scanning** (**if allowed** pelo scope).

A **fast method** para descobrir **ports open** relacionadas a **web** servers usando [**masscan** can be found here](../pentesting-network/index.html#http-port-discovery).\
Outra ferramenta amigável para procurar web servers é [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) e [**httpx**](https://github.com/projectdiscovery/httpx). Você apenas passa uma lista de domains e ele tentará conectar à porta 80 (http) e 443 (https). Adicionalmente, você pode indicar para tentar outras portas:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Capturas de tela**

Agora que você descobriu **all the web servers** presentes no escopo (entre os **IPs** da empresa e todos os **domains** e **subdomains**) você provavelmente **não sabe por onde começar**. Então, vamos simplificar e começar apenas tirando screenshots de todos eles. Só de **dar uma olhada** na **main page** você pode encontrar endpoints **estranhos** que têm mais probabilidade de serem **vulnerable**.

Para executar a ideia proposta você pode usar [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) ou [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Além disso, você pode usar [**eyeballer**](https://github.com/BishopFox/eyeballer) para analisar todas as **screenshots** e indicar o que provavelmente contém **vulnerabilidades** e o que não contém.

## Ativos em Cloud Públicos

Para encontrar potenciais cloud assets pertencentes a uma empresa você deve **começar com uma lista de palavras-chave que identifiquem essa empresa**. Por exemplo, para uma empresa crypto você pode usar palavras como: "crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">.

Você também vai precisar de wordlists de **palavras comuns usadas em buckets**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Depois, com essas palavras você deve gerar **permutations** (veja o [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) para mais info).

Com as wordlists resultantes você pode usar ferramentas como [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **ou** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Lembre-se que ao procurar por Cloud Assets você deveria l**ook for more than just buckets in AWS**.

### **Procurando vulnerabilidades**

Se você encontrar coisas como **open buckets** ou **cloud functions exposed** você deve **acessá‑las** e tentar ver o que elas oferecem e se você pode abusar delas.

## Emails

Com os **domains** e **subdomains** dentro do escopo você basicamente tem tudo o que precisa para começar a procurar por emails. Estas são as **APIs** e **ferramentas** que funcionaram melhor para mim para encontrar emails de uma empresa:

- [**theHarvester**](https://github.com/laramies/theHarvester) - with APIs
- API of [**https://hunter.io/**](https://hunter.io/) (free version)
- API of [**https://app.snov.io/**](https://app.snov.io/) (free version)
- API of [**https://minelead.io/**](https://minelead.io/) (free version)

### **Procurando vulnerabilidades**

Emails serão úteis mais tarde para **brute-force** logins web e serviços de auth (como SSH). Além disso, são necessários para campanhas de **phishing**. Essas APIs também fornecerão ainda mais **info sobre a pessoa** por trás do email, o que é útil para a campanha de phishing.

## Credential Leaks

Com os **domains,** **subdomains**, e **emails** você pode começar a procurar por credenciais leaked no passado pertencentes àqueles emails:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Procurando vulnerabilidades**

Se você encontrar credenciais leaked válidas, esse é um ganho muito fácil.

## Secrets Leaks

Credential leaks estão relacionados a hacks de empresas onde **informação sensível foi leaked e vendida**. No entanto, empresas podem ser afetadas por outros leaks cujas infos não estão nessas bases de dados:

### Github Leaks

Credenciais e APIs podem estar leaked em repositórios públicos da empresa ou dos usuários que trabalham para essa github company.\
Você pode usar a ferramenta [**Leakos**](https://github.com/carlospolop/Leakos) para **baixar** todos os **public repos** de uma **organization** e de seus **developers** e rodar [**gitleaks**](https://github.com/zricethezav/gitleaks) sobre eles automaticamente.

**Leakos** também pode ser usado para rodar **gitleaks** contra todos os textos das URLs fornecidas a ele, já que às vezes **web pages** também contêm secrets.

#### Github Dorks

Cheque também esta **página** para potenciais **github dorks** que você também poderia buscar na organização que está atacando:


{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

Às vezes atacantes ou funcionários vão **publicar conteúdo da empresa em um site de paste**. Isso pode ou não conter informação sensível, mas é muito interessante procurá‑lo.\
Você pode usar a ferramenta [**Pastos**](https://github.com/carlospolop/Pastos) para buscar em mais de 80 paste sites ao mesmo tempo.

### Google Dorks

Antigos mas eficazes, google dorks são sempre úteis para encontrar **informação exposta que não deveria estar ali**. O problema é que o [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) contém várias **milhares** de queries possíveis que você não pode rodar manualmente. Então, você pode escolher suas 10 favoritas ou usar uma **ferramenta como** [**Gorks**](https://github.com/carlospolop/Gorks) **para rodá‑las todas**.

_Observe que ferramentas que tentam rodar todo o database usando o navegador regular do Google nunca vão terminar, pois o google irá te bloquear muito, muito rápido._

### **Procurando vulnerabilidades**

Se você encontrar credenciais leaked válidas ou API tokens, esse é um ganho muito fácil.

## Public Code Vulnerabilities

Se você descobrir que a empresa tem código open-source você pode **analisá‑lo** e buscar por **vulnerabilidades** nele.

**Dependendo da linguagem** existem diferentes **ferramentas** que você pode usar:


{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

Também há serviços gratuitos que permitem **scanear public repositories**, como:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

A **maioria das vulnerabilidades** encontradas por bug hunters reside dentro de **web applications**, então neste ponto eu gostaria de falar sobre uma **metodologia de testes de aplicações web**, e você pode [**encontrar essa informação aqui**](../../network-services-pentesting/pentesting-web/index.html).

Quero também mencionar especialmente a seção [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), pois, embora você não deva esperar que elas encontrem vulnerabilidades muito sensíveis, elas são úteis para implementar em **workflows** e obter informações web iniciais.

## Recapitulação

> Parabéns! Neste ponto você já realizou **toda a enumeração básica**. Sim, é básica porque muito mais enumeração pode ser feita (veremos mais truques depois).

Então você já:

1. Encontrou todas as **empresas** dentro do escopo
2. Encontrou todos os **ativos** pertencentes às empresas (e realizou algum vuln scan se estiver in scope)
3. Encontrou todos os **domains** pertencentes às empresas
4. Encontrou todos os **subdomains** dos domains (algum subdomain takeover?)
5. Encontrou todos os **IPs** (de CDN e não-CDN) dentro do escopo.
6. Encontrou todos os **web servers** e tirou um **screenshot** deles (algo estranho que mereça uma investigação mais profunda?)
7. Encontrou todos os **potenciais public cloud assets** pertencentes à empresa.
8. **Emails**, **credentials leaks**, e **secrets leaks** que podem te dar um **grande ganho muito facilmente**.
9. **Pentesting** em todos os webs que você encontrou

## **Full Recon Automatic Tools**

Existem várias ferramentas que irão executar parte das ações propostas contra um escopo dado.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Um pouco antigo e sem atualizações

## **Referências**

- Todos os cursos gratuitos de [**@Jhaddix**](https://twitter.com/Jhaddix) como [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)

{{#include ../../banners/hacktricks-training.md}}
