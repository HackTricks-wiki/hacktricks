# Metodologia de Reconhecimento Externo

{{#include ../../banners/hacktricks-training.md}}

## Descoberta de ativos

> Então, disseram que tudo o que pertence a uma empresa está dentro do escopo, e você quer descobrir o que essa empresa realmente possui.

O objetivo desta fase é obter todas as **empresas pertencentes à empresa principal** e, em seguida, todos os **ativos** dessas empresas. Para isso, vamos:<sup>[[1]](#references)</sup>

1. Encontrar as aquisições da empresa principal; isso nos dará as empresas dentro do escopo.
2. Encontrar o ASN (se houver) de cada empresa; isso nos dará os intervalos de IP pertencentes a cada empresa.
3. Usar consultas de reverse whois para buscar outras entradas (nomes de organizações, domínios...) relacionadas à primeira (isso pode ser feito recursivamente).
4. Usar outras técnicas, como os filtros `org`e `ssl` do shodan, para buscar outros ativos (o truque do `ssl` pode ser feito recursivamente).

### **Aquisições**

Antes de tudo, precisamos saber quais **outras empresas pertencem à empresa principal**.\
Uma opção é acessar [https://www.crunchbase.com/](https://www.crunchbase.com), **buscar** a **empresa principal** e **clicar** em "**aquisições**". Lá, você verá outras empresas adquiridas pela empresa principal.\
Outra opção é acessar a página da **Wikipedia** da empresa principal e buscar por **aquisições**.\
Para empresas públicas, consulte os **registros da SEC/EDGAR**, as páginas de **relações com investidores** ou os registros corporativos locais (por exemplo, a **Companies House** no Reino Unido).\
Para árvores corporativas globais e subsidiárias, tente usar o **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) e o banco de dados **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> Ok, neste ponto você deve conhecer todas as empresas dentro do escopo. Vamos descobrir como encontrar os ativos delas.

### **ASNs**

Um número de sistema autônomo (**ASN**) é um **número exclusivo** atribuído a um **sistema autônomo** (AS) pela **Internet Assigned Numbers Authority (IANA)**.\
Um **AS** consiste em **blocos** de **endereços IP** que possuem uma política claramente definida para acessar redes externas e são administrados por uma única organização, mas podem ser formados por vários operadores.

É interessante descobrir se a **empresa recebeu algum ASN** para encontrar seus **intervalos de IP.** Será interessante realizar um **teste de vulnerabilidades** contra todos os **hosts** dentro do **escopo** e **buscar domínios** dentro desses IPs.\
Você pode **buscar** por **nome** da empresa, por **IP** ou por **domínio** em [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **ou** [**https://ipinfo.io/**](https://ipinfo.io/).\
**Dependendo da região da empresa, estes links podem ser úteis para coletar mais dados:** [**AFRINIC**](https://www.afrinic.net) **(África),** [**Arin**](https://www.arin.net/about/welcome/region/)**(América do Norte),** [**APNIC**](https://www.apnic.net) **(Ásia),** [**LACNIC**](https://www.lacnic.net) **(América Latina),** [**RIPE NCC**](https://www.ripe.net) **(Europa). De qualquer forma, provavelmente todas as** informações úteis **(intervalos de IP e Whois)** já aparecem no primeiro link.**
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Além disso, a enumeração do [**BBOT**](https://github.com/blacklanternsecurity/bbot) agrega e resume automaticamente os ASNs ao final da varredura.
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
Você também pode encontrar os intervalos de IP de uma organização usando [http://asnlookup.com/](http://asnlookup.com) (ele possui uma API gratuita).\
Você pode encontrar o IP e o ASN de um domínio usando [http://ipv4info.com/](http://ipv4info.com).

### **Procurando por vulnerabilidades**

Neste ponto, conhecemos **todos os assets dentro do escopo**; portanto, se você tiver autorização, poderá executar algum **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) em todos os hosts.\
Além disso, você poderia executar alguns [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **ou usar serviços como** Shodan, Censys ou ZoomEye **para encontrar** portas abertas **e, dependendo do que encontrar, deverá** consultar este livro para saber como fazer pentest em vários serviços possíveis em execução.\
**Também pode ser válido mencionar que você também pode preparar algumas listas de** nomes de usuário **e** senhas **padrão e tentar fazer** bruteforce em serviços com [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domínios

> Conhecemos todas as empresas dentro do escopo e seus assets; agora é hora de encontrar os domínios dentro do escopo.

_Por favor, observe que, com as técnicas propostas a seguir, você também pode encontrar subdomínios, e essas informações não devem ser subestimadas._

Primeiro, você deve procurar o(s) **domínio(s) principal(is)** de cada empresa. Por exemplo, para a _Tesla Inc._, será _tesla.com_.

### **Reverse DNS**

Como você encontrou todos os intervalos de IP dos domínios, pode tentar realizar **reverse dns lookups** nesses **IPs para encontrar mais domínios dentro do escopo**. Tente usar algum servidor dns da vítima ou algum servidor dns conhecido (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Para que isso funcione, o administrador precisa habilitar o PTR manualmente.\
Você também pode usar uma ferramenta online para obter essas informações: [http://ptrarchive.com/](http://ptrarchive.com).\
Para grandes intervalos, ferramentas como [**massdns**](https://github.com/blechschmidt/massdns) e [**dnsx**](https://github.com/projectdiscovery/dnsx) são úteis para automatizar consultas reversas e enriquecimento.

### **Reverse Whois (loop)**

Dentro de um **whois**, você pode encontrar muitas **informações** interessantes, como **nome da organização**, **endereço**, **e-mails**, números de telefone... Mas o que é ainda mais interessante é que você pode encontrar **mais assets relacionados à empresa** se realizar **consultas reversas de whois usando qualquer um desses campos** (por exemplo, outros registros whois nos quais o mesmo e-mail aparece).\
Você pode usar ferramentas online como:

- [https://ip.thc.org/](https://ip.thc.org/) - **Grátis** (Web e API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Grátis**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Grátis**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Grátis**
- [https://www.whoxy.com/](https://www.whoxy.com) - Web **grátis**, API paga.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Pago
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Pago (apenas **100 consultas grátis**)
- [https://www.domainiq.com/](https://www.domainiq.com) - Pago
- [https://securitytrails.com/](https://securitytrails.com/) - Pago (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - Pago (API)

Você pode automatizar essa tarefa usando o [**DomLink** ](https://github.com/vysecurity/DomLink)(requer uma chave de API do whoxy).\
Você também pode realizar alguma descoberta reversa automática de whois com o [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Observe que você pode usar essa técnica para descobrir mais nomes de domínio sempre que encontrar um novo domínio.**

### **Trackers**

Se você encontrar o **mesmo ID do mesmo tracker** em 2 páginas diferentes, pode supor que **ambas as páginas** são **gerenciadas pela mesma equipe**.\
Por exemplo, se você vir o mesmo **ID do Google Analytics** ou o mesmo **ID do Adsense** em várias páginas.

Há algumas páginas e ferramentas que permitem pesquisar usando esses trackers e outros:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (encontra sites relacionados por meio de analytics/trackers compartilhados)

### **Favicon**

Você sabia que podemos encontrar domínios e subdomínios relacionados ao nosso alvo procurando pelo mesmo hash do ícone favicon? É exatamente isso que a ferramenta [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py), criada por [@m4ll0k2](https://twitter.com/m4ll0k2), faz. Veja como usá-la:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
Em termos simples, favihash nos permite descobrir domínios que têm o mesmo hash de ícone favicon que o nosso alvo.

![saída do favihash usada para descobrir domínios com o mesmo hash de favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

Use um hash de favicon conhecido como pivot no Shodan ou FOFA para encontrar outras instâncias expostas da mesma tecnologia.<sup>[[5]](#references)</sup>
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```
É assim que você pode **calcular o hash do favicon** de um site (MMH3 sobre os bytes do favicon **codificados em base64**):
```python
import mmh3
import requests
import codecs

def fav_hash(url):
response = requests.get(url, timeout=10)
favicon = codecs.encode(response.content, "base64")
fhash = mmh3.hash(favicon)
print(f"{url} : {fhash}")
return fhash
```
Você também pode obter hashes de favicon em escala com [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) e, em seguida, fazer pivot no Shodan/Censys.

Trate as impressões digitais de favicon como pistas e valide-as com sinais adjacentes.<sup>[[3]](#references)[[4]](#references)</sup>

- **Trate o hash como um indicador, não como prova**: MMH3 é compacto; colisões, ícones reutilizados e spoofing deliberado são possíveis.
- **Sonde mais do que** `/favicon.ico`: inspecione caminhos de framework/build, arquivos de manifesto, `browserconfig.xml`, `site.webmanifest`, `apple-touch-icon*`, data URLs inline e tags HTML `<link rel="icon">`.
- **Ativos estáticos podem continuar acessíveis atrás de controles de WAF/SSO/IdP**: solicite o ícone diretamente e analise `ETag`, `Last-Modified`, redirecionamentos e cabeçalhos de cache.
- **Valide as correspondências com sinais adjacentes**: compare o título, o hash do HTML/corpo, os cabeçalhos, os subjects/SANs do certificado TLS, os componentes do produto e as portas expostas.
- **Agrupe pelo hash do HTML/corpo**: um template consistente fortalece a impressão digital; templates mistos sugerem um ícone genérico ou compartilhado.
- **Trate um hash que aparece em assinaturas, portas e produtos não relacionados como um possível honeypot ou placeholder.**
- **Em alvos ambíguos, compare uma página real com um caminho inexistente**, como `/_favicon_probe_<8-hex>`; respostas correspondentes de hospedagem ou parking podem explicar o ícone compartilhado.
- **Faça a triagem inicial a partir de regras de detecção do Nuclei ou de datasets públicos** que mapeiem hashes de favicon para produtos e CPEs.
- **Lembre-se da lacuna de cobertura centrada em IP**: superfícies atrás de CDN, roteadas por SNI, anycast e somente por domínio podem estar ausentes de datasets semelhantes aos do Shodan.

### **Copyright / Uniq string**

Pesquise dentro das páginas web **strings que possam ser compartilhadas entre diferentes sites da mesma organização**. A **string de copyright** pode ser um bom exemplo. Depois, pesquise essa string no **google**, em outros **browsers** ou até mesmo no **shodan**: `shodan search http.html:"Copyright string"`

### **CRT Time**

É comum existir um cron job como
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
para renovar todos os certificados de um servidor ao mesmo tempo. Correlacionar os timestamps dos certificados ou as posições nos logs de certificate-transparency pode revelar domínios relacionados.<sup>[[6]](#references)</sup>

Também use os logs de **certificate transparency** diretamente:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Informações de Mail DMARC

Você pode usar um site como [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) ou uma ferramenta como [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) para encontrar **domínios e subdomínios que compartilham as mesmas informações de dmarc**.\
Outras ferramentas úteis são [**spoofcheck**](https://github.com/BishopFox/spoofcheck) e [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Um registro A abandonado pode se tornar acessível quando um cloud provider reatribui um IP. A pesquisa referenciada demonstra um workflow oportunista que provisiona uma instância e correlaciona seu endereço com dados de passive DNS; teste cenários de takeover somente dentro do escopo autorizado.<sup>[[7]](#references)</sup>

### **Outras formas**

Repita os pivôs de discovery aplicáveis sempre que encontrar um novo domínio: cada resultado pode revelar nomes de certificados adicionais, relacionamentos de passive DNS, correspondências de favicon e identificadores da organização que não estavam visíveis a partir da seed original.<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

Como você já sabe o nome da organização proprietária do espaço de IPs, pode pesquisar esses dados no shodan usando: `org:"Tesla, Inc."` Verifique os hosts encontrados em busca de novos domínios inesperados no certificado TLS.

Você pode acessar o **certificado TLS** da página web principal, obter o **nome da Organização** e então pesquisar esse nome dentro dos **certificados TLS** de todas as páginas web conhecidas pelo **shodan** com o filtro: `ssl:"Tesla Motors"` ou usar uma ferramenta como [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)é uma ferramenta que procura **domínios relacionados** a um domínio principal e os **subdomínios** deles, realmente impressionante.

**Passive DNS / Historical DNS**

Os dados de Passive DNS são excelentes para encontrar **registros antigos e esquecidos** que ainda resolvem ou que podem sofrer takeover. Consulte:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Procurando vulnerabilidades**

Verifique algum caso de [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Talvez alguma empresa esteja **usando um domínio** mas tenha **perdido a propriedade**. Basta registrá-lo (se for barato o suficiente) e informar a empresa.

Se você encontrar algum **domínio com um IP diferente** dos que já encontrou na descoberta de assets, deverá realizar um **basic vulnerability scan** (usando Nessus ou OpenVAS) e algum [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) com **nmap/masscan/shodan**. Dependendo dos serviços em execução, você poderá encontrar **neste livro alguns truques para "atacá-los"**.\
_Note que, às vezes, o domínio está hospedado em um IP que não é controlado pelo cliente; portanto, ele não está no escopo. Tenha cuidado._

## Subdomínios

> Conhecemos todas as empresas dentro do escopo, todos os assets de cada empresa e todos os domínios relacionados às empresas.

É hora de encontrar todos os subdomínios possíveis de cada domínio encontrado.

> [!TIP]
> Observe que algumas das ferramentas e técnicas para encontrar domínios também podem ajudar a encontrar subdomínios

### **DNS**

Vamos tentar obter **subdomínios** a partir dos registros de **DNS**. Também devemos tentar fazer uma **Zone Transfer** (se estiver vulnerável, você deverá reportá-la).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

A maneira mais rápida de obter muitos subdomínios é pesquisar em fontes externas. As **ferramentas** mais utilizadas são as seguintes (para obter melhores resultados, configure as chaves de API):

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

- [**IP.THC.ORG**](https://ip.thc.org) API gratuita
```bash
curl https://ip.thc.org/tesla.com
```
- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Usa a API [https://sonar.omnisint.io](https://sonar.omnisint.io) para obter subdomínios
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
- [**gau**](https://github.com/lc/gau)**:** busca URLs conhecidas do AlienVault's Open Threat Exchange, Wayback Machine e Common Crawl para qualquer domínio especificado.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Vasculham a web em busca de arquivos JS e extraem subdomínios deles.
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
- [**Localizador de subdomínios do Censys**](https://github.com/christophetd/censys-subdomain-finder)
```bash
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
python3 censys-subdomain-finder.py tesla.com
```
- [**DomainTrail.py**](https://github.com/gatete/DomainTrail)
```bash
python3 DomainTrail.py -d example.com
```
- [**securitytrails.com**](https://securitytrails.com/) tem uma API gratuita para pesquisar subdomínios e histórico de IPs
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Este projeto oferece **gratuitamente todos os subdomínios relacionados a programas de bug bounty**. Você também pode acessar esses dados usando [chaospy](https://github.com/dr-0x0x/chaospy) ou até mesmo acessar o escopo usado por este projeto: [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Você pode encontrar uma **comparação** de muitas dessas ferramentas aqui: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **Força bruta de DNS**

Vamos tentar encontrar novos **subdomínios** realizando brute force em servidores DNS usando possíveis nomes de subdomínios.

Para esta ação, você precisará de algumas **wordlists de subdomínios comuns, como**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

E também de IPs de bons resolvers DNS. Para gerar uma lista de resolvers DNS confiáveis, você pode baixar os resolvers de [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) e usar o [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) para filtrá-los. Ou você pode usar: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

As ferramentas mais recomendadas para brute force de DNS são:

- [**massdns**](https://github.com/blechschmidt/massdns): Esta foi a primeira ferramenta a realizar um brute force de DNS eficaz. É muito rápida, mas é propensa a falsos positivos.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Este eu acho que usa apenas 1 resolver
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) é um wrapper em torno do `massdns`, escrito em go, que permite enumerar subdomínios válidos usando active bruteforce, além de resolver subdomínios com tratamento de wildcard e suporte fácil a entrada e saída.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): Ele também usa `massdns`.
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) usa asyncio para realizar brute force de nomes de domínio de forma assíncrona.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Segunda Rodada de Brute-Force de DNS

Após encontrar subdomínios usando fontes abertas e brute-forcing, você pode gerar alterações dos subdomínios encontrados para tentar encontrar ainda mais. Várias ferramentas são úteis para essa finalidade:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Dado os domínios e subdomínios, gera permutações.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): Dado os domínios e subdomínios, gera permutações.
- Você pode obter a **wordlist** de permutações do goaltdns [**aqui**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** Dado os domínios e subdomínios, gera permutações. Se nenhum arquivo de permutações for indicado, o gotator usará o próprio arquivo.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Além de gerar permutações de subdomínios, ele também pode tentar resolvê-las (mas é melhor usar as ferramentas comentadas anteriormente).
- Você pode obter a **wordlist** de permutações do altdns [**aqui**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Outra ferramenta para realizar permutações, mutações e alterações de subdomínios. Essa ferramenta fará brute force do resultado (não oferece suporte a dns wild card).
- Você pode obter a wordlist de permutações do dmut [**aqui**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Com base em um domínio, **gera novos nomes potenciais de subdomínios** com base nos padrões indicados para tentar descobrir mais subdomínios.

#### Geração inteligente de permutations

- [**regulator**](https://github.com/cramppet/regulator): Aprende padrões semelhantes a regex a partir dos subdomínios descobertos e gera nomes candidatos para resolver.<sup>[[8]](#references)</sup>
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ é um subdomain brute-force fuzzer associado a um algoritmo imensamente simples, mas eficaz, guiado por respostas DNS. Ele utiliza um conjunto de dados de entrada fornecido, como uma wordlist personalizada ou registros DNS/TLS históricos, para sintetizar com precisão mais nomes de domínio correspondentes e expandi-los ainda mais em um loop, com base nas informações coletadas durante o DNS scan.
```
echo www | subzuf facebook.com
```
### **Fluxo de Descoberta de Subdomínios**

Os exemplos de workflow do Trickest combinam OSINT, DNS brute force e estágios de permutação para enumeração repetível de subdomínios.<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

Se você encontrou um endereço IP contendo **uma ou várias páginas web** pertencentes a subdomínios, pode tentar **encontrar outros subdomínios com páginas web nesse IP** procurando em **fontes OSINT** por domínios em um IP ou fazendo **brute force de nomes de domínio VHost nesse IP**.

#### OSINT

Você pode encontrar alguns **VHosts em IPs usando** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **ou outras APIs**.

**Brute Force**

Se você suspeita que algum subdomínio possa estar oculto em um servidor web, pode tentar fazer brute force nele:

Para vhosts baseados em nome, faça fuzz do cabeçalho `Host` e use a calibração automática do ffuf para filtrar a resposta padrão.<sup>[[2]](#references)</sup>
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
> Com esta técnica, você pode até conseguir acessar endpoints internos/ocultos.

### **CORS Brute Force**

Às vezes, você encontrará páginas que só retornam o cabeçalho _**Access-Control-Allow-Origin**_ quando um domínio/subdomínio válido é definido no cabeçalho _**Origin**_. Nesses cenários, você pode abusar desse comportamento para **descobrir** novos **subdomínios**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

Ao procurar por **subdomains**, fique atento para verificar se algum está **pointing** para algum tipo de **bucket** e, nesse caso, [**verifique as permissões**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Além disso, como neste ponto você conhecerá todos os domínios dentro do escopo, tente [**fazer brute force de possíveis nomes de buckets e verificar as permissões**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Monitoramento**

Você pode **monitorar** se **novos subdomains** de um domínio são criados monitorando os logs de **Certificate Transparency**, como faz o [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Procurando vulnerabilidades**

Verifique possíveis [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Se o **subdomain** estiver apontando para algum **S3 bucket**, [**verifique as permissões**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Se você encontrar algum **subdomain com um IP diferente** dos que já encontrou na descoberta de assets, deverá realizar um **basic vulnerability scan** (usando Nessus ou OpenVAS) e algum [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) com **nmap/masscan/shodan**. Dependendo dos serviços em execução, você poderá encontrar **neste livro alguns truques para "atacá-los"**.\
_Observe que, às vezes, o subdomain está hospedado em um IP que não é controlado pelo cliente, portanto não está no escopo; tenha cuidado._

## IPs

Nas etapas iniciais, você pode ter **encontrado alguns intervalos de IPs, domínios e subdomains**.\
É hora de **recolher todos os IPs desses intervalos** e dos **domínios/subdomains (consultas DNS).**

Usando os serviços das seguintes **APIs gratuitas**, você também pode encontrar **IPs usados anteriormente por domínios e subdomains**. Esses IPs ainda podem pertencer ao cliente (e podem permitir encontrar [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

- [**https://securitytrails.com/**](https://securitytrails.com/)

Você também pode verificar quais domínios apontam para um endereço IP específico usando a ferramenta [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Procurando vulnerabilidades**

Faça **port scan de todos os IPs que não pertencem a CDNs** (pois, muito provavelmente, você não encontrará nada interessante neles). Nos serviços em execução descobertos, talvez seja **possível encontrar vulnerabilidades**.

**Encontre um** [**guia**](../pentesting-network/index.html) **sobre como fazer scan de hosts.**

## Caça a Web servers

> Encontramos todas as empresas e seus assets e conhecemos os intervalos de IPs, domínios e subdomains dentro do escopo. É hora de procurar por web servers.

Nas etapas anteriores, você provavelmente já realizou algum **recon dos IPs e domínios descobertos**, portanto pode já ter **encontrado todos os web servers possíveis**. No entanto, caso ainda não tenha feito isso, veremos agora alguns **truques rápidos para procurar por web servers** dentro do escopo.

Observe que isso será **orientado à descoberta de web apps**, portanto você também deverá **realizar vulnerability scanning** e **port scanning** (**se permitido** pelo escopo).

Um **método rápido** para descobrir **portas abertas** relacionadas a **web** servers usando [**masscan** pode ser encontrado aqui](../pentesting-network/index.html#http-port-discovery).\
Outra ferramenta amigável para procurar por web servers é o [**httprobe**](https://github.com/tomnomnom/httprobe)**,** o [**fprobe**](https://github.com/theblackturtle/fprobe) e o [**httpx**](https://github.com/projectdiscovery/httpx). Basta fornecer uma lista de domínios, e ela tentará se conectar às portas 80 (http) e 443 (https). Além disso, você pode indicar outras portas para tentar:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Screenshots**

Agora que você descobriu **todos os web servers** presentes no escopo (entre os **IPs** da empresa e todos os **domínios** e **subdomínios**), provavelmente **não sabe por onde começar**. Então, vamos simplificar e começar apenas tirando screenshots de todos eles. Apenas **olhando** para a **página principal**, você pode encontrar endpoints **estranhos** que são mais **propensos** a ser **vulneráveis**.

Para realizar a ideia proposta, você pode usar o [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) ou [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Além disso, você pode usar o [**eyeballer**](https://github.com/BishopFox/eyeballer) para analisar todas as **screenshots** e informar quais **provavelmente contêm vulnerabilidades** e quais não contêm.

## Public Cloud Assets

Para encontrar possíveis cloud assets pertencentes a uma empresa, você deve **começar com uma lista de palavras-chave que identifiquem essa empresa**. Por exemplo, para uma empresa de criptomoedas, você poderia usar palavras como: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Você também precisará de wordlists de **palavras comuns usadas em buckets**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Depois, com essas palavras, você deve gerar **permutações** (consulte o [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) para obter mais informações).

Com as wordlists resultantes, você poderia usar ferramentas como [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **ou** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Lembre-se de que, ao procurar por Cloud Assets, você deve **procurar por mais do que apenas buckets na AWS**.

### **Looking for vulnerabilities**

Se você encontrar coisas como **buckets abertos ou cloud functions expostas**, deverá **acessá-las** e tentar verificar o que elas oferecem e se você pode abusar delas.

## Emails

Com os **domínios** e **subdomínios** dentro do escopo, você basicamente já tem tudo o que **precisa para começar a procurar emails**. Estas são as **APIs** e **ferramentas** que funcionaram melhor para mim na busca por emails de uma empresa:

- [**theHarvester**](https://github.com/laramies/theHarvester) - com APIs
- API do [**https://hunter.io/**](https://hunter.io/) (versão gratuita)
- API do [**https://app.snov.io/**](https://app.snov.io/) (versão gratuita)
- API do [**https://minelead.io/**](https://minelead.io/) (versão gratuita)

### **Looking for vulnerabilities**

Os emails serão úteis mais tarde para fazer **brute-force de logins web e serviços de autenticação** (como SSH). Eles também são necessários para **phishings**. Além disso, essas APIs fornecerão ainda mais **informações sobre a pessoa** por trás do email, o que é útil para a campanha de phishing.

## Credential Leaks

Com os **domínios,** **subdomínios** e **emails**, você pode começar a procurar credenciais que sofreram leak no passado e pertencem a esses emails:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Looking for vulnerabilities**

Se você encontrar credenciais **vazadas válidas**, esta será uma vitória muito fácil.

## Secrets Leaks

Credential leaks estão relacionados a hacks de empresas nos quais **informações sensíveis sofreram leak e foram vendidas**. No entanto, as empresas podem ser afetadas por **outros leaks** cujas informações não estejam presentes nessas databases:

### Github Leaks

Credenciais e APIs podem sofrer leak nos **repositórios públicos** da **empresa** ou dos **usuários** que trabalham para essa empresa no Github.\
Você pode usar a **tool** [**Leakos**](https://github.com/carlospolop/Leakos) para **baixar** todos os **repositórios públicos** de uma **organização** e de seus **desenvolvedores**, e executar o [**gitleaks**](https://github.com/zricethezav/gitleaks) neles automaticamente.

O **Leakos** também pode ser usado para executar o **gitleaks** contra todo o **texto** fornecido pelas **URLs passadas** a ele, pois às vezes **páginas web também contêm secrets**.

#### Github Dorks

Consulte a [GitHub dorks and leaks page](github-leaked-secrets.md) para encontrar possíveis **GitHub dorks** a serem pesquisadas na organização.

### Pastes Leaks

Às vezes, atacantes ou simplesmente funcionários **publicam conteúdo da empresa em um paste site**. Isso pode ou não conter **informações sensíveis**, mas é muito interessante procurar por esse conteúdo.\
Você pode usar a tool [**Pastos**](https://github.com/carlospolop/Pastos) para pesquisar em mais de 80 paste sites ao mesmo tempo.

### Google Dorks

As antigas, mas valiosas, Google dorks são sempre úteis para encontrar **informações expostas que não deveriam estar ali**. O único problema é que o [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) contém vários **milhares** de possíveis queries que você não pode executar manualmente. Portanto, você pode escolher suas 10 favoritas ou usar uma **tool como** [**Gorks**](https://github.com/carlospolop/Gorks) **para executar todas elas**.

_Observe que as tools que tentam executar todo o database usando o navegador Google comum nunca terminarão, pois o Google bloqueará você muito rapidamente._

### **Looking for vulnerabilities**

Se você encontrar credenciais **vazadas válidas** ou API tokens, esta será uma vitória muito fácil.

## Public Code Vulnerabilities

Se você descobrir que a empresa possui **código open-source**, poderá **analisá-lo** e procurar **vulnerabilidades** nele.

**Dependendo da linguagem**, existem diferentes **tools** que você pode usar; consulte a lista de [source-code review tools](../../network-services-pentesting/pentesting-web/code-review-tools.md).

Também existem serviços gratuitos que permitem **analisar repositórios públicos**, como:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

A **maioria das vulnerabilidades** encontradas por bug hunters está dentro de **web applications**. Portanto, neste ponto, gostaria de falar sobre uma **metodologia de teste de web applications**, e você pode [**encontrar essas informações aqui**](../../network-services-pentesting/pentesting-web/index.html).

Também quero fazer uma menção especial à seção [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), pois, embora você não deva esperar que elas encontrem vulnerabilidades muito sensíveis, elas são úteis para implementá-las em **workflows e obter algumas informações iniciais sobre a web.**

## Recapitulation

> Parabéns! Neste ponto, você já realizou **toda a enumeração básica**. Sim, ela é básica porque ainda é possível fazer muito mais enumeração (veremos mais truques posteriormente).

Você já:

1. Encontrou todas as **empresas** dentro do escopo
2. Encontrou todos os **assets** pertencentes às empresas (e realizou algum vuln scan, se estiver no escopo)
3. Encontrou todos os **domínios** pertencentes às empresas
4. Encontrou todos os **subdomínios** dos domínios (algum subdomain takeover?)
5. Encontrou todos os **IPs** (de **CDNs** e **não pertencentes a CDNs**) dentro do escopo.
6. Encontrou todos os **web servers** e tirou uma **screenshot** deles (há algo estranho que mereça uma análise mais aprofundada?)
7. Encontrou todos os **possíveis public cloud assets** pertencentes à empresa.
8. **Emails**, **credential leaks** e **secret leaks** que poderiam proporcionar uma **grande vitória com muita facilidade**.
9. **Realizou pentesting em todas as webs encontradas**

## **Full Recon Automatic Tools**

Existem várias tools que executam parte das ações propostas contra um determinado escopo.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Um pouco antiga e não atualizada

## References

- [1] [Jason Haddix – The Bug Hunter's Methodology v4.0: Recon Edition](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – On Favicons: From Browser Icons to Attack Surface Intelligence](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – Weaponizing favicon.ico for BugBounties, OSINT and what not](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – Discovering Domains via a Time-Correlation Attack on Certificate Transparency](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – Passive Takeover: Uncovering (and Emulating) an Expensive Subdomain Takeover Campaign](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator: A Unique Method of Subdomain Enumeration](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – Full Subdomain Discovery Workflow, Part 1](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – Full Subdomain Brute Force Discovery Using Automated Trickest Workflow, Part 2](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter – favihash output screenshot](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}
