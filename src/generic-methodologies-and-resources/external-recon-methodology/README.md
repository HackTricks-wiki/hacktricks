# Metodologia de Recon Externo

{{#include ../../banners/hacktricks-training.md}}

## Descoberta de ativos

> Então, foi informado que tudo pertencente a uma empresa está dentro do escopo, e você quer descobrir o que essa empresa realmente possui.

O objetivo desta fase é obter todas as **empresas pertencentes à empresa principal** e, em seguida, todos os **ativos** dessas empresas. Para isso, vamos:

1. Encontrar as aquisições da empresa principal; isso nos fornecerá as empresas dentro do escopo.
2. Encontrar o ASN (se houver) de cada empresa; isso nos fornecerá os intervalos de IP pertencentes a cada empresa.
3. Usar consultas de reverse whois para pesquisar outras entradas (nomes de organizações, domínios...) relacionadas à primeira (isso pode ser feito recursivamente).
4. Usar outras técnicas, como os filtros `org` e `ssl` do shodan, para pesquisar outros ativos (o truque do `ssl` pode ser feito recursivamente).

### **Aquisições**

Antes de tudo, precisamos saber quais **outras empresas pertencem à empresa principal**.\
Uma opção é visitar [https://www.crunchbase.com/](https://www.crunchbase.com), **pesquisar** a **empresa principal** e **clicar** em "**acquisitions**". Lá, você verá outras empresas adquiridas pela empresa principal.\
Outra opção é visitar a página da **Wikipedia** da empresa principal e pesquisar por **aquisições**.\
Para empresas públicas, consulte os **documentos SEC/EDGAR**, as páginas de **relações com investidores** ou os registros corporativos locais (por exemplo, a **Companies House** no Reino Unido).\
Para estruturas corporativas globais e subsidiárias, tente o **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) e o banco de dados **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> Ok, neste ponto você deve conhecer todas as empresas dentro do escopo. Vamos descobrir como encontrar os ativos delas.

### **ASNs**

Um número de sistema autônomo (**ASN**) é um **número exclusivo** atribuído a um **sistema autônomo** (AS) pela **Internet Assigned Numbers Authority (IANA)**.\
Um **AS** consiste em **blocos** de **endereços IP** que possuem uma política claramente definida para acessar redes externas e são administrados por uma única organização, mas podem ser compostos por vários operadores.

É interessante descobrir se a **empresa possui algum ASN atribuído** para encontrar seus **intervalos de IP.** Será interessante realizar um **vulnerability test** contra todos os **hosts** dentro do **escopo** e **procurar domínios** dentro desses IPs.\
Você pode **pesquisar** por **nome** da empresa, por **IP** ou por **domínio** em [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **ou** [**https://ipinfo.io/**](https://ipinfo.io/).\
**Dependendo da região da empresa, estes links podem ser úteis para coletar mais dados:** [**AFRINIC**](https://www.afrinic.net) **(África),** [**Arin**](https://www.arin.net/about/welcome/region/)**(América do Norte),** [**APNIC**](https://www.apnic.net) **(Ásia),** [**LACNIC**](https://www.lacnic.net) **(América Latina),** [**RIPE NCC**](https://www.ripe.net) **(Europa). De qualquer forma, provavelmente todas as** informações úteis **(intervalos de IP e Whois)** já aparecem no primeiro link.**
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Além disso, a enumeração do [**BBOT**](https://github.com/blacklanternsecurity/bbot) agrega e resume automaticamente os ASNs ao final do scan.
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
Você também pode encontrar os intervalos de IP de uma organização usando [http://asnlookup.com/](http://asnlookup.com) (possui uma API gratuita).\
Você pode encontrar o IP e o ASN de um domínio usando [http://ipv4info.com/](http://ipv4info.com).

### **Procurando por vulnerabilidades**

Neste ponto, conhecemos **todos os assets dentro do escopo**, portanto, se você tiver permissão, poderá executar algum **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) em todos os hosts.\
Além disso, você pode executar alguns [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **ou usar serviços como** Shodan, Censys ou ZoomEye **para encontrar** portas abertas **e, dependendo do que encontrar, deverá** consultar este livro para saber como fazer pentesting em vários serviços possíveis em execução.\
**Também pode ser importante mencionar que você pode preparar algumas listas de** usernames **e** passwords **padrão e tentar fazer** bruteforce **nos serviços com** [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domínios

> Conhecemos todas as empresas dentro do escopo e seus assets; agora é hora de encontrar os domínios dentro do escopo.

_Por favor, observe que, com as técnicas propostas a seguir, você também pode encontrar subdomínios, e essas informações não devem ser subestimadas._

Primeiro, você deve procurar o(s) **domínio(s) principal(is)** de cada empresa. Por exemplo, para a _Tesla Inc._, será _tesla.com_.

### **Reverse DNS**

Como você encontrou todos os intervalos de IP dos domínios, pode tentar realizar **reverse DNS lookups** nesses **IPs para encontrar mais domínios dentro do escopo**. Tente usar algum servidor DNS da vítima ou algum servidor DNS conhecido (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Para que isso funcione, o administrador precisa habilitar manualmente o PTR.\
Você também pode usar uma ferramenta online para obter essas informações: [http://ptrarchive.com/](http://ptrarchive.com).\
Para intervalos grandes, ferramentas como [**massdns**](https://github.com/blechschmidt/massdns) e [**dnsx**](https://github.com/projectdiscovery/dnsx) são úteis para automatizar reverse lookups e o enriquecimento dos dados.

### **Reverse Whois (loop)**

Dentro de um **whois**, você pode encontrar muitas **informações** interessantes, como **nome da organização**, **endereço**, **e-mails**, números de telefone... Mas o que é ainda mais interessante é que você pode encontrar **mais assets relacionados à empresa** se realizar **reverse whois lookups usando qualquer um desses campos** (por exemplo, outros registros whois onde o mesmo e-mail aparece).\
Você pode usar ferramentas online como:

- [https://ip.thc.org/](https://ip.thc.org/) - **Gratuito** (Web e API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Gratuito**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Gratuito**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Gratuito**
- [https://www.whoxy.com/](https://www.whoxy.com) - Web **gratuita**, API paga.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Pago
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Pago (apenas **100 buscas gratuitas**)
- [https://www.domainiq.com/](https://www.domainiq.com) - Pago
- [https://securitytrails.com/](https://securitytrails.com/) - Pago (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - Pago (API)

Você pode automatizar essa tarefa usando o [**DomLink** ](https://github.com/vysecurity/DomLink)(requer uma chave de API do whoxy).\
Você também pode realizar alguma descoberta automática de reverse whois com o [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Observe que você pode usar esta técnica para descobrir mais nomes de domínio sempre que encontrar um novo domínio.**

### **Trackers**

Se você encontrar o **mesmo ID do mesmo tracker** em 2 páginas diferentes, pode supor que **ambas as páginas** são **gerenciadas pela mesma equipe**.\
Por exemplo, se você vir o mesmo **Google Analytics ID** ou o mesmo **Adsense ID** em várias páginas.

Existem algumas páginas e ferramentas que permitem pesquisar por esses trackers e outros:

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
![favihash - descubra domínios com o mesmo hash do ícone favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Em termos simples, o favihash nos permite descobrir domínios que têm o mesmo hash do ícone favicon do nosso alvo.

Além disso, também é possível pesquisar tecnologias usando o hash do favicon, conforme explicado [**nesta publicação do blog**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139). Isso significa que, se você souber o **hash do favicon de uma versão vulnerável de uma tecnologia web**, poderá pesquisar no shodan e **encontrar mais locais vulneráveis**:
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
Você também pode obter hashes de favicon em escala com [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) e, em seguida, fazer pivoting no Shodan/Censys.

Coisas úteis para lembrar ao usar fingerprints de favicon:

- **Trate o hash como um indicador, não como prova**: MMH3 é compacto e colisões são possíveis; operadores também podem substituir favicons ou reutilizar intencionalmente um ícone enganoso.
- **Faça probing em mais lugares além de** `/favicon.ico`: muitos produtos expõem ícones em caminhos de framework/build ou via `manifest.json`, `site.webmanifest`, `browserconfig.xml`, `apple-touch-icon*`, URLs `data:` inline ou tags HTML `<link rel="icon">`. O próprio caminho pode identificar uma família de produtos.
- **Arquivos estáticos geralmente ficam acessíveis quando a aplicação não está**: controles de WAF/SSO/IdP podem proteger rotas dinâmicas, mas ainda expor ícones estáticos. Sempre solicite o favicon diretamente e analise `ETag`, `Last-Modified`, redirects e headers de cache em busca de indícios fracos de versão/build.
- **Valide os matches com sinais adicionais**: compare o título, o hash do HTML/body, headers, subjects/SANs do certificado TLS, componentes do Shodan/Censys e portas expostas antes de concluir que um favicon identifica um produto.
- **Agrupe por hash de HTML/body ao fazer pivoting em escala**: se a maioria dos hosts que compartilham um favicon convergir para um único template de página, o fingerprint será mais forte; se o mesmo hash se dividir entre muitos templates não relacionados, prefira "genérico/compartilhado/honeypot" em vez de um rótulo de produto.
- **Heurística de honeypot**: se o mesmo hash de favicon aparecer em muitas assinaturas HTML não relacionadas, portas aleatórias e produtos conflitantes, trate-o como um provável honeypot ou placeholder genérico, e não como um fingerprint real de produto.
- **Use um probe de 404 em alvos ambíguos**: busque uma página real e um caminho inexistente, como `/_favicon_probe_<8-hex>`, em um browser. Respostas correspondentes de hosting-provider/parking geralmente explicam melhor os favicons compartilhados do que uma verdadeira sobreposição de produtos.
- **Inicialize os mapeamentos a partir de regras de detecção**: templates do Nuclei e datasets públicos de favicon podem fornecer mapeamentos conhecidos `favicon` ↔ `product` ↔ `CPE`, úteis para triagem rápida após divulgações de CVE.
- **Observação sobre cobertura**: datasets no estilo do Shodan são centrados em IP. Superfícies protegidas por CDN, roteadas por SNI, anycast e somente por domínio podem ser subcontabilizadas; portanto, uma baixa quantidade de hits **não** significa uma baixa implantação no mundo real.

### **Copyright / Uniq string**

Pesquise dentro das páginas web **strings que possam ser compartilhadas entre diferentes sites da mesma organização**. A **string de copyright** pode ser um bom exemplo. Em seguida, pesquise essa string no **google**, em outros **browsers** ou até mesmo no **shodan**: `shodan search http.html:"Copyright string"`

### **CRT Time**

É comum haver um cron job como 恒一
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
para renovar todos os certificados dos domínios no servidor. Isso significa que, mesmo que a CA usada para isso não defina o momento em que ele foi gerado no campo Validity, é possível **encontrar domínios pertencentes à mesma empresa nos certificate transparency logs**.\
Confira este [**writeup para mais informações**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

Use também os logs de **certificate transparency** diretamente:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Informações de Mail DMARC

Você pode usar um site como [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) ou uma ferramenta como [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) para encontrar **domínios e subdomínios que compartilham as mesmas informações de dmarc**.\
Outras ferramentas úteis são [**spoofcheck**](https://github.com/BishopFox/spoofcheck) e [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Aparentemente, é comum que as pessoas atribuam subdomínios a IPs pertencentes a cloud providers e, em algum momento, **percam esse endereço IP, mas esqueçam de remover o registro DNS**. Portanto, basta **iniciar uma VM** em uma cloud (como Digital Ocean) para que você esteja, na prática, **assumindo o controle de algum(ns) subdomínio(s)**.

[**Este post**](https://kmsec.uk/blog/passive-takeover/) explica um caso sobre isso e propõe um script que **inicia uma VM na DigitalOcean**, **obtém** o **IPv4** da nova máquina e **pesquisa no Virustotal por registros de subdomínios** apontando para ela.

### **Outras formas**

**Observe que você pode usar esta técnica para descobrir mais nomes de domínio sempre que encontrar um novo domínio.**

**Shodan**

Como você já sabe o nome da organização proprietária do espaço de IPs, pode pesquisar esses dados no Shodan usando: `org:"Tesla, Inc."` Verifique os hosts encontrados em busca de novos domínios inesperados no certificado TLS.

Você pode acessar o **certificado TLS** da página web principal, obter o **nome da organização** e então pesquisar esse nome dentro dos **certificados TLS** de todas as páginas web conhecidas pelo **Shodan**, usando o filtro: `ssl:"Tesla Motors"` ou uma ferramenta como [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder) é uma ferramenta que procura **domínios relacionados** a um domínio principal e seus **subdomínios**, sendo bastante impressionante.

**Passive DNS / Historical DNS**

Os dados de Passive DNS são excelentes para encontrar **registros antigos e esquecidos** que ainda resolvem ou que podem ser assumidos. Consulte:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Procurando por vulnerabilidades**

Verifique se há algum [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Talvez alguma empresa esteja **usando um domínio**, mas tenha **perdido a propriedade** dele. Basta registrá-lo (se for barato o suficiente) e avisar a empresa.

Se você encontrar algum **domínio com um IP diferente** dos que já encontrou na descoberta de assets, deverá executar um **basic vulnerability scan** (usando Nessus ou OpenVAS) e algum [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) com **nmap/masscan/shodan**. Dependendo dos serviços em execução, você poderá encontrar **neste livro alguns truques para "atacá-los"**.\
_Observe que, às vezes, o domínio está hospedado em um IP que não é controlado pelo cliente, portanto não está no escopo. Tenha cuidado._

## Subdomínios

> Sabemos todas as empresas dentro do escopo, todos os assets de cada empresa e todos os domínios relacionados às empresas.

É hora de encontrar todos os subdomínios possíveis de cada domínio encontrado.

> [!TIP]
> Observe que algumas ferramentas e técnicas para encontrar domínios também podem ajudar a encontrar subdomínios

### **DNS**

Vamos tentar obter **subdomínios** a partir dos registros **DNS**. Também devemos tentar realizar uma **Zone Transfer** (se estiver vulnerável, você deverá reportá-la).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

A forma mais rápida de obter muitos subdomínios é pesquisar em fontes externas. As **ferramentas** mais utilizadas são as seguintes (para obter melhores resultados, configure as API keys):

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
- [**API gratuita do JLDC**](https://jldc.me/anubis/subdomains/google.com)
```bash
curl https://jldc.me/anubis/subdomains/tesla.com | jq -r ".[]"
```
- [**RapidDNS**](https://rapiddns.io) API grátis
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
- [**gau**](https://github.com/lc/gau)**:** busca URLs conhecidas do AlienVault's Open Threat Exchange, da Wayback Machine e do Common Crawl para qualquer domínio.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Eles vasculham a web em busca de arquivos JS e extraem subdomínios deles.
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
- [**securitytrails.com**](https://securitytrails.com/) possui uma API gratuita para pesquisar subdomínios e histórico de IPs
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Este projeto oferece **gratuitamente todos os subdomínios relacionados a programas de bug bounty**. Você também pode acessar esses dados usando [chaospy](https://github.com/dr-0x0x/chaospy) ou até mesmo acessar o escopo usado por este projeto [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Você pode encontrar uma **comparação** de muitas dessas ferramentas aqui: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Vamos tentar encontrar novos **subdomínios** fazendo brute force em servidores DNS usando possíveis nomes de subdomínios.

Para esta ação, você precisará de algumas **wordlists de subdomínios comuns, como**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

E também de IPs de bons resolvers DNS. Para gerar uma lista de resolvers DNS confiáveis, você pode baixar os resolvers de [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) e usar [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) para filtrá-los. Ou você pode usar: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

As ferramentas mais recomendadas para DNS brute force são:

- [**massdns**](https://github.com/blechschmidt/massdns): Esta foi a primeira ferramenta a realizar um DNS brute force eficaz. Ela é muito rápida, porém está sujeita a falsos positivos.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Este, acho que usa apenas 1 resolvedor
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) é um wrapper em torno do `massdns`, escrito em Go, que permite enumerar subdomínios válidos usando bruteforce ativo, além de resolver subdomínios com tratamento de wildcard e suporte fácil de entrada e saída.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): Também usa `massdns`.
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) usa asyncio para realizar brute force de nomes de domínio de forma assíncrona.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Segunda Rodada de Brute-Force de DNS

Após encontrar subdomínios usando fontes abertas e brute-forcing, você pode gerar alterações dos subdomínios encontrados para tentar encontrar ainda mais. Várias ferramentas são úteis para esse propósito:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Dado os domínios e subdomínios, gera permutações.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): Dado os domínios e subdomínios, gera permutações.
- Você pode obter a **wordlist** de permutações do goaltdns [**aqui**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** Dado os domínios e subdomínios, gera permutações. Se nenhum arquivo de permutações for indicado, o gotator usará seu próprio arquivo.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Além de gerar permutações de subdomínios, ele também pode tentar resolvê-las (mas é melhor usar as ferramentas mencionadas anteriormente).
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
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Com base em um domínio, ele **gera novos nomes potenciais de subdomínios** com base nos padrões indicados para tentar descobrir mais subdomínios.

#### Geração inteligente de permutações

- [**regulator**](https://github.com/cramppet/regulator): Para mais informações, leia este [**post**](https://cramppet.github.io/regulator/index.html), mas ele basicamente obtém as **partes principais** dos **subdomínios descobertos** e as combina para encontrar mais subdomínios.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ é um fuzzer de brute-force de subdomínios combinado com um algoritmo extremamente simples, mas eficaz, orientado por respostas DNS. Ele utiliza um conjunto de dados de entrada fornecido, como uma wordlist personalizada ou registros históricos de DNS/TLS, para sintetizar com precisão mais nomes de domínio correspondentes e expandi-los ainda mais em um loop, com base nas informações coletadas durante o DNS scan.
```
echo www | subzuf facebook.com
```
### **Fluxo de Descoberta de Subdomínios**

Confira esta publicação do blog que escrevi sobre como **automatizar a descoberta de subdomínios** de um domínio usando **workflows do Trickest**, para não precisar executar manualmente várias ferramentas no meu computador:


{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}


{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtual Hosts**

Se você encontrou um endereço IP contendo **uma ou várias páginas web** pertencentes a subdomínios, pode tentar **encontrar outros subdomínios com páginas web nesse IP** procurando em **fontes OSINT** por domínios em um IP ou fazendo **brute force de nomes de domínio VHost nesse IP**.

#### OSINT

Você pode encontrar alguns **VHosts em IPs usando** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **ou outras APIs**.

**Brute Force**

Se você suspeitar que algum subdomínio pode estar oculto em um servidor web, pode tentar fazer brute force nele:

Quando o **IP redireciona para um hostname** (vhosts baseados em nome), faça fuzz diretamente no cabeçalho `Host` e deixe o ffuf **calibrar automaticamente** para destacar as respostas que diferem do vhost padrão:
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

Às vezes, você encontrará páginas que só retornam o header _**Access-Control-Allow-Origin**_ quando um domínio/subdomínio válido é definido no header _**Origin**_. Nesses cenários, você pode abusar desse comportamento para **descobrir** novos **subdomínios**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Brute Force de Buckets**

Ao procurar por **subdomains**, fique atento para verificar se algum está **apontando** para algum tipo de **bucket** e, nesse caso, [**verifique as permissões**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Além disso, como neste momento você já conhecerá todos os domínios dentro do escopo, tente [**fazer brute force de possíveis nomes de buckets e verificar as permissões**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Monitoramento**

Você pode **monitorar** se **novos subdomains** de um domínio são criados monitorando os logs de **Certificate Transparency**, como faz o [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Procurando por vulnerabilidades**

Verifique possíveis [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Se o **subdomain** estiver apontando para algum **S3 bucket**, [**verifique as permissões**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Se você encontrar algum **subdomain com um IP diferente** dos que já encontrou na descoberta de assets, deverá realizar um **basic vulnerability scan** (usando Nessus ou OpenVAS) e algum [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) com **nmap/masscan/shodan**. Dependendo de quais serviços estiverem em execução, você poderá encontrar **neste livro alguns truques para "atacá-los"**.\
_Observe que, às vezes, o subdomain está hospedado em um IP que não é controlado pelo cliente, portanto não está no escopo; tenha cuidado._

## IPs

Nas etapas iniciais, você pode ter **encontrado alguns intervalos de IPs, domínios e subdomains**.\
É hora de **recolher todos os IPs desses intervalos** e dos **domínios/subdomains (consultas DNS).**

Usando serviços das seguintes **free APIs**, você também pode encontrar **IPs anteriores usados por domínios e subdomains**. Esses IPs ainda podem pertencer ao cliente (e podem permitir que você encontre [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

- [**https://securitytrails.com/**](https://securitytrails.com/)

Você também pode verificar quais domínios estão apontando para um endereço IP específico usando a ferramenta [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Procurando por vulnerabilidades**

**Faça port scan de todos os IPs que não pertencem a CDNs** (pois, muito provavelmente, você não encontrará nada interessante neles). Nos serviços em execução descobertos, talvez seja **possível encontrar vulnerabilidades**.

**Encontre um** [**guia**](../pentesting-network/index.html) **sobre como fazer scan de hosts.**

## Procurando por web servers

> Encontramos todas as empresas e seus assets e conhecemos os intervalos de IPs, domínios e subdomains dentro do escopo. É hora de procurar por web servers.

Nas etapas anteriores, você provavelmente já realizou algum **recon dos IPs e domínios descobertos**, portanto pode ter **encontrado todos os web servers possíveis**. No entanto, se ainda não tiver feito isso, veremos agora alguns **truques rápidos para procurar por web servers** dentro do escopo.

Observe que isso será **orientado à descoberta de web apps**, portanto você também deverá **realizar vulnerability scanning** e **port scanning** (**se permitido** pelo escopo).

Um **método rápido** para descobrir **portas abertas** relacionadas a **web** servers usando [**masscan** pode ser encontrado aqui](../pentesting-network/index.html#http-port-discovery).\
Outra ferramenta amigável para procurar por web servers é o [**httprobe**](https://github.com/tomnomnom/httprobe)**,** o [**fprobe**](https://github.com/theblackturtle/fprobe) e o [**httpx**](https://github.com/projectdiscovery/httpx). Basta passar uma lista de domínios, e a ferramenta tentará conectar-se às portas 80 (http) e 443 (https). Além disso, você pode indicar outras portas para tentativa:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Screenshots**

Agora que você descobriu **todos os web servers** presentes no escopo (entre os **IPs** da empresa e todos os **domínios** e **subdomínios**), provavelmente **não sabe por onde começar**. Então, vamos simplificar e começar apenas tirando screenshots de todos eles. Apenas **olhando** para a **página principal**, você pode encontrar endpoints **estranhos** mais **propensos** a serem **vulneráveis**.

Para realizar a ideia proposta, você pode usar [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) ou [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Além disso, você pode usar [**eyeballer**](https://github.com/BishopFox/eyeballer) em todas as **screenshots** para indicar **o que provavelmente contém vulnerabilidades** e o que não contém.

## Public Cloud Assets

Para encontrar potenciais cloud assets pertencentes a uma empresa, você deve **começar com uma lista de palavras-chave que identifiquem essa empresa**. Por exemplo, para uma empresa de crypto, você poderia usar palavras como: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Você também precisará de wordlists de **palavras comuns usadas em buckets**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Depois, com essas palavras, você deve gerar **permutações** (consulte o [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) para obter mais informações).

Com as wordlists resultantes, você pode usar ferramentas como [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **ou** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Lembre-se de que, ao procurar por Cloud Assets, você deve **procurar mais do que apenas buckets na AWS**.

### **Procurando por vulnerabilidades**

Se você encontrar coisas como **buckets abertos ou cloud functions expostas**, deverá **acessá-las** e tentar verificar o que elas oferecem e se é possível abusar delas.

## Emails

Com os **domínios** e **subdomínios** dentro do escopo, você basicamente já tem tudo o que **precisa para começar a procurar emails**. Estas são as **APIs** e **ferramentas** que funcionaram melhor para mim na busca por emails de uma empresa:

- [**theHarvester**](https://github.com/laramies/theHarvester) - com APIs
- API de [**https://hunter.io/**](https://hunter.io/) (versão gratuita)
- API de [**https://app.snov.io/**](https://app.snov.io/) (versão gratuita)
- API de [**https://minelead.io/**](https://minelead.io/) (versão gratuita)

### **Procurando por vulnerabilidades**

Os emails serão úteis posteriormente para fazer **brute-force de logins web e serviços de autenticação** (como SSH). Eles também são necessários para **phishings**. Além disso, essas APIs fornecerão ainda mais **informações sobre a pessoa** por trás do email, o que é útil para a campanha de phishing.

## Credential Leaks

Com os **domínios,** **subdomínios** e **emails**, você pode começar a procurar credenciais leaked no passado pertencentes a esses emails:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Procurando por vulnerabilidades**

Se você encontrar credenciais **leaked válidas**, esta será uma vitória muito fácil.

## Secrets Leaks

Credential leaks estão relacionados a ataques contra empresas nos quais **informações sensíveis foram leaked e vendidas**. No entanto, as empresas podem ser afetadas por **outros leaks** cujas informações não estão nessas bases de dados:

### Github Leaks

Credenciais e APIs podem ser leaked nos **repositórios públicos** da **empresa** ou dos **usuários** que trabalham para essa empresa no github.\
Você pode usar a **ferramenta** [**Leakos**](https://github.com/carlospolop/Leakos) para **baixar** todos os **repositórios públicos** de uma **organização** e de seus **desenvolvedores**, além de executar [**gitleaks**](https://github.com/zricethezav/gitleaks) neles automaticamente.

**Leakos** também pode ser usado para executar **gitleaks** contra todo o **texto** fornecido pelas **URLs passadas** a ele, pois às vezes **páginas web também contêm secrets**.

#### Github Dorks

Consulte também esta **página** em busca de possíveis **github dorks** que você também poderia pesquisar na organização que está atacando:


{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

Às vezes, atacantes ou simplesmente funcionários **publicam conteúdo da empresa em um paste site**. Isso pode ou não conter **informações sensíveis**, mas é muito interessante pesquisar por isso.\
Você pode usar a ferramenta [**Pastos**](https://github.com/carlospolop/Pastos) para pesquisar em mais de 80 paste sites simultaneamente.

### Google Dorks

Os antigos, mas valiosos, Google dorks são sempre úteis para encontrar **informações expostas que não deveriam estar ali**. O único problema é que o [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) contém vários **milhares** de consultas possíveis que você não pode executar manualmente. Portanto, você pode escolher suas 10 favoritas ou usar uma **ferramenta como** [**Gorks**](https://github.com/carlospolop/Gorks) **para executar todas elas**.

_Observe que as ferramentas que tentam executar todo o database usando o navegador regular do Google nunca terminarão, pois o Google bloqueará você muito rapidamente._

### **Procurando por vulnerabilidades**

Se você encontrar credenciais **leaked válidas** ou tokens de API, esta será uma vitória muito fácil.

## Public Code Vulnerabilities

Se você descobrir que a empresa possui código **open-source**, poderá **analisá-lo** e procurar por **vulnerabilidades** nele.

**Dependendo da linguagem**, existem diferentes **ferramentas** que você pode usar:


{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

Também existem serviços gratuitos que permitem **fazer scan de repositórios públicos**, como:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

A **maioria das vulnerabilidades** encontradas por bug hunters está dentro de **web applications**, então, neste ponto, gostaria de falar sobre uma **metodologia de teste de web applications**, e você pode [**encontrar essas informações aqui**](../../network-services-pentesting/pentesting-web/index.html).

Também quero fazer uma menção especial à seção [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), pois, embora você não deva esperar que eles encontrem vulnerabilidades muito sensíveis, são úteis para implementá-los em **workflows e obter algumas informações web iniciais.**

## Recapitulation

> Parabéns! Neste ponto, você já realizou **toda a enumeração básica**. Sim, ela é básica porque é possível realizar muito mais enumeração (veremos mais tricks posteriormente).

Você já:

1. Encontrou todas as **empresas** dentro do escopo
2. Encontrou todos os **assets** pertencentes às empresas (e realizou alguns scans de vulnerabilidades, se estiverem no escopo)
3. Encontrou todos os **domínios** pertencentes às empresas
4. Encontrou todos os **subdomínios** dos domínios (algum subdomain takeover?)
5. Encontrou todos os **IPs** (de e **não pertencentes a CDNs**) dentro do escopo.
6. Encontrou todos os **web servers** e tirou uma **screenshot** deles (há algo estranho que mereça uma análise mais aprofundada?)
7. Encontrou todos os **potenciais public cloud assets** pertencentes à empresa.
8. **Emails**, **credential leaks** e **secret leaks** que poderiam proporcionar uma **grande vitória com muita facilidade**.
9. **Realizou pentesting em todos os sites encontrados**

## **Full Recon Automatic Tools**

Existem várias ferramentas que executam parte das ações propostas contra um determinado escopo.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Um pouco antiga e não atualizada

## **References**

- Todos os cursos gratuitos de [**@Jhaddix**](https://twitter.com/Jhaddix), como [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [Bishop Fox – On Favicons: From Browser Icons to Attack Surface Intelligence](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [BishopFox/Favicons](https://github.com/BishopFox/Favicons)

{{#include ../../banners/hacktricks-training.md}}
