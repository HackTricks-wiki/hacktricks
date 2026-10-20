# Metodologia de Reconhecimento Externo

{{#include ../../banners/hacktricks-training.md}}

## Descoberta de ativos

> Então, disseram que tudo o que pertence a uma empresa está dentro do scope, e você quer descobrir o que essa empresa realmente possui.

O objetivo desta fase é identificar todas as **empresas pertencentes à empresa principal** e, em seguida, todos os **ativos** dessas empresas. Para isso, vamos:<sup>[[1]](#references)</sup>

1. Encontrar as aquisições da empresa principal. Isso nos dará as empresas dentro do scope.
2. Encontrar o ASN (se houver) de cada empresa. Isso nos dará os intervalos de IP pertencentes a cada uma.
3. Usar consultas de reverse whois para buscar outras entradas (nomes de organizações, domínios...) relacionadas à primeira (isso pode ser feito recursivamente).
4. Usar outras técnicas, como os filtros `org` e `ssl` do shodan, para buscar outros ativos (o truque de `ssl` pode ser usado recursivamente).

### **Aquisições**

Primeiro, precisamos descobrir **quais outras empresas pertencem à empresa principal**.\
Uma opção é visitar [https://www.crunchbase.com/](https://www.crunchbase.com), **buscar** a **empresa principal** e **clicar** em "**acquisitions**". Lá, você verá outras empresas adquiridas pela empresa principal.\
Outra opção é visitar a página da **Wikipedia** da empresa principal e buscar por **aquisições**.\
Para empresas de capital aberto, consulte os documentos **SEC/EDGAR**, as páginas de **relações com investidores** ou os registros corporativos locais (por exemplo, **Companies House** no Reino Unido).\
Para consultar estruturas corporativas globais e subsidiárias, experimente o **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) e o banco de dados **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> Certo, neste ponto você já deve conhecer todas as empresas dentro do scope. Vamos descobrir como encontrar os ativos delas.

### **ASNs**

Um número de sistema autônomo (**ASN**) é um **número único** atribuído a um **sistema autônomo** (AS) pela **Internet Assigned Numbers Authority (IANA)**.\
Um **AS** consiste em **blocos** de **endereços IP** que têm uma política claramente definida para acessar redes externas e são administrados por uma única organização, mas podem ser compostos por vários operadores.

É interessante descobrir se a **empresa tem algum ASN atribuído** para encontrar seus **intervalos de IP**. Será interessante realizar um **teste de vulnerabilidade** em todos os **hosts** dentro do **scope** e **buscar domínios** nesses IPs.\
Você pode **buscar** por **nome** da empresa, **IP** ou **domínio** em [**https://bgp.he.net/**](https://bgp.he.net) **ou** [**https://ipinfo.io/**](https://ipinfo.io/).\
**Dependendo da região da empresa, estes links podem ser úteis para coletar mais dados:** [**AFRINIC**](https://www.afrinic.net) **(África),** [**Arin**](https://www.arin.net/about/welcome/region/)**(América do Norte),** [**APNIC**](https://www.apnic.net) **(Ásia),** [**LACNIC**](https://www.lacnic.net) **(América Latina),** [**RIPE NCC**](https://www.ripe.net) **(Europa). De qualquer forma, provavelmente todas as informações** úteis **(intervalos de IP e Whois)** já aparecem no primeiro link.

```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```

Além disso, a enumeração **do** [**BBOT**](https://github.com/blacklanternsecurity/bbot) agrega e resume automaticamente os ASNs ao final da varredura.

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

Você também pode encontrar os intervalos de IP de uma organização usando [ASNLookup](https://asnlookup.com/), que oferece um nível gratuito limitado da API.

### **Procurando vulnerabilidades**

Neste ponto, conhecemos **todos os ativos dentro do escopo**, então, se tiver autorização, você pode executar algum **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) em todos os hosts.\
Além disso, você pode executar alguns [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **ou usar serviços como** Shodan, Censys ou ZoomEye **para encontrar** portas abertas **e, dependendo do que encontrar, deve** consultar este livro para saber como fazer pentest em vários serviços que possam estar em execução.\
**Além disso, vale mencionar que você também pode preparar algumas listas de** nomes de usuário **e** senhas **padrão e tentar fazer** bruteforce em serviços com [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domínios

> Conhecemos todas as empresas dentro do escopo e seus ativos; agora é hora de encontrar os domínios dentro do escopo.

_Observe que, nas técnicas propostas a seguir, você também pode encontrar subdomínios, e essas informações não devem ser subestimadas._

Primeiro, você deve procurar o(s) **domínio(s) principal(is)** de cada empresa. Por exemplo, para a _Tesla Inc._, será _tesla.com_.

### **Reverse DNS**

Como você encontrou todos os intervalos de IP dos domínios, pode tentar fazer **consultas de DNS reverso** nesses **IPs para encontrar mais domínios dentro do escopo**. Tente usar algum servidor DNS da vítima ou algum servidor DNS conhecido (1.1.1.1, 8.8.8.8)

```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```

Para que isso funcione, o administrador precisa habilitar manualmente o PTR.\
Você também pode usar [SecurityTrails](https://securitytrails.com/) para obter essas informações, embora os dados históricos de DNS exijam um plano pago.\
Para grandes intervalos, ferramentas como [**massdns**](https://github.com/blechschmidt/massdns) e [**dnsx**](https://github.com/projectdiscovery/dnsx) são úteis para automatizar consultas reversas e enriquecimento.

### **Reverse Whois (loop)**

Em um **whois**, você pode encontrar muitas **informações** interessantes, como **nome da organização**, **endereço**, **emails**, números de telefone... Mas o que é ainda mais interessante é que você pode encontrar **mais ativos relacionados à empresa** realizando **consultas reverse whois com qualquer um desses campos** (por exemplo, outros registros whois nos quais o mesmo email aparece).\
Você pode usar ferramentas online como:

- [https://ip.thc.org/](https://ip.thc.org/) - **Gratuito** (Web e API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Gratuito**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Gratuito**
- [https://www.whoxy.com/](https://www.whoxy.com) - interface web **gratuita**; API paga.
- [https://reversewhois.domaintools.com/](https://reversewhois.domaintools.com) - Pago
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Não gratuito (apenas **100 pesquisas gratuitas**)
- [https://www.domainiq.com/](https://www.domainiq.com) - Não gratuito
- [https://securitytrails.com/](https://securitytrails.com/) - Acesso gratuito limitado à API para DNS/subdomínios atuais; consultas históricas e reversas exigem um plano pago.
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - 500 créditos gratuitos de API no cadastro; depois, pago.

Você pode automatizar essa tarefa usando [**DomLink** ](https://github.com/vysecurity/DomLink)(requer uma chave de API do whoxy).\
Você também pode realizar algumas descobertas automáticas de reverse whois com [amass](https://github.com/owasp-amass/amass): `amass intel -d tesla.com -whois`

**Observe que você pode usar esta técnica para descobrir mais nomes de domínio sempre que encontrar um novo domínio.**

### **Trackers**

Se você encontrar o **mesmo ID do mesmo tracker** em 2 páginas diferentes, pode supor que **ambas as páginas** são **gerenciadas pela mesma equipe**.\
Por exemplo, se você encontrar o mesmo **ID do Google Analytics** ou o mesmo **ID do Adsense** em várias páginas.

Há algumas páginas e ferramentas que permitem pesquisar esses trackers e outros:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](https://spyonweb.net/)
- [**StackScan**](https://www.stackscan.com) - serviço web e API **pago** ([preços](https://www.stackscan.com/pricing)); atualmente, não há um plano gratuito anunciado. Faça pivôs usando qualquer ativo servido, não apenas IDs de trackers: um caminho de script, o nome de um bundle hospedado localmente ou o host de onde um ativo é carregado, retornando todos os sites que o contêm

A API retorna a stack de um único domínio, o que é útil para confirmar se um ativo candidato pertence ao mesmo conjunto de ativos:

```bash
curl -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Id: $WORKSPACE" \
  "https://api.stackscan.com/v1/tech-lookup/domains/lookup?domain=tesla.com"
```

Retorna cada tecnologia detectada com sua categoria. O pivotamento de assets atualmente está disponível apenas para web; a API permite consultas por domínio.

### **Favicon**

Você sabia que podemos encontrar domínios e subdomínios relacionados ao nosso alvo procurando pelo mesmo hash de ícone favicon? É exatamente isso que a ferramenta [favihash.py](https://github.com/m4ll0k/BBTz/blob/master/favihash.py), criada por [@m4ll0k2](https://twitter.com/m4ll0k2), faz. Veja como usá-la:

```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```

![Resultados do Favihash usados para descobrir domínios que compartilham um hash de favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Em termos simples, o Favihash nos permite descobrir domínios que têm o mesmo hash do ícone favicon que o nosso alvo.

![Saída do Favihash usada para descobrir domínios com o mesmo hash de favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

Use um hash de favicon conhecido como pivot no Shodan ou no FOFA para encontrar outras instâncias expostas da mesma tecnologia.<sup>[[5]](#references)</sup>

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

You também pode obter hashes de favicon em escala com [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) e depois pivotar no Shodan/Censys.

Trate as impressões digitais de favicon como pistas e valide-as com sinais ao redor.<sup>[[3]](#references)[[4]](#references)</sup>

- **Trate o hash como um indicador, não como prova**: o MMH3 é compacto; colisões, ícones reutilizados e falsificação deliberada são possíveis.
- **Investigue mais do que** `/favicon.ico`: verifique caminhos de framework/build, arquivos manifest, `browserconfig.xml`, `site.webmanifest`, `apple-touch-icon*`, URLs de dados inline e tags HTML `<link rel="icon">`.
- **Ativos estáticos podem continuar acessíveis por trás de controles de WAF/SSO/IdP**: solicite o ícone diretamente e examine `ETag`, `Last-Modified`, redirecionamentos e cabeçalhos de cache.
- **Valide as correspondências com sinais ao redor**: compare o título, o hash do HTML/corpo, os cabeçalhos, os nomes de sujeitos/SANs do certificado TLS, os componentes do produto e as portas expostas.
- **Agrupe pelo hash do HTML/corpo**: um template consistente reforça a impressão digital; templates variados sugerem um ícone genérico ou compartilhado.
- **Trate um hash que apareça em assinaturas, portas e produtos sem relação entre si como um possível honeypot ou placeholder.**
- **Em alvos ambíguos, compare uma página real com um caminho inexistente**, como `/_favicon_probe_<8-hex>`; respostas idênticas de hospedagem ou estacionamento de domínio podem explicar o ícone compartilhado.
- **Inicie a triagem com regras de detecção do Nuclei ou conjuntos de dados públicos** que associem hashes de favicon a produtos e CPEs.
- **Lembre-se da lacuna de cobertura centrada em IP**: superfícies protegidas por CDN, roteadas por SNI, anycast e somente por domínio podem estar ausentes de conjuntos de dados semelhantes aos do Shodan.

### **Copyright / string única**

Pesquise nas páginas da web **strings que possam ser compartilhadas por diferentes sites da mesma organização**. A **string de copyright** pode ser um bom exemplo. Depois, pesquise essa string no **Google**, em outros **navegadores** ou até no **Shodan**: `shodan search http.html:"Copyright string"`

### **Tempo do CRT**

É comum ter um cron job como o seguinte

```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```

para renovar todos os certificados de um servidor ao mesmo tempo. Correlacionar timestamps de certificados ou posições nos logs de Certificate Transparency pode revelar domínios relacionados.<sup>[[6]](#references)</sup>

Use também diretamente os logs de **Certificate Transparency**:

- [https://crt.sh/](https://crt.sh/)
- [https://sslmate.com/certspotter/](https://sslmate.com/certspotter/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Informações de DMARC de e-mail

Você pode usar um site como [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) ou uma ferramenta como [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) para encontrar **domínios e subdomínios que compartilham as mesmas informações de DMARC**.\
Outro serviço útil é o [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Um registro A abandonado pode voltar a ficar acessível quando um provedor de cloud reatribui um IP. A pesquisa referenciada demonstra um fluxo de trabalho oportunista que provisiona uma instância e correlaciona seu endereço com dados de DNS passivo; teste cenários de takeover somente dentro do escopo autorizado.<sup>[[7]](#references)</sup>

### **Outras formas**

Repita os pivôs de descoberta aplicáveis sempre que encontrar um novo domínio: cada resultado pode revelar nomes de certificados adicionais, relações de DNS passivo, correspondências de favicon e identificadores de organização que não estavam visíveis a partir do seed original.<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

Como você já sabe o nome da organização proprietária do espaço de IP, pode pesquisar esses dados no Shodan usando: `org:"Tesla, Inc."` Verifique os hosts encontrados em busca de novos domínios inesperados no certificado TLS.

Você pode acessar o **certificado TLS** da página web principal, obter o **nome da organização** e então pesquisar esse nome nos **certificados TLS** de todas as páginas web conhecidas pelo **Shodan** com o filtro: `ssl:"Tesla Motors"` ou usar uma ferramenta como [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)é uma ferramenta que procura **domínios relacionados** a um domínio principal e **subdomínios** deles; é incrível.

**DNS passivo / DNS histórico**

Dados de DNS passivo são ótimos para encontrar **registros antigos e esquecidos** que ainda resolvem ou que podem sofrer takeover. Confira:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://www.domaintools.com/platform](https://www.domaintools.com/platform)
- [https://docs.domaintools.com/dnsdb/](https://docs.domaintools.com/dnsdb/)

### **Procurando vulnerabilidades**

Verifique se há algum [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Talvez alguma empresa esteja **usando um domínio**, mas tenha **perdido a propriedade** dele. Basta registrá-lo (se for barato o suficiente) e avisar a empresa.

Se encontrar algum **domínio com um IP diferente** dos que você já encontrou na descoberta de ativos, faça um **scan básico de vulnerabilidades** (usando Nessus ou OpenVAS) e um [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) com **nmap/masscan/shodan**. Dependendo dos serviços em execução, você pode encontrar **neste livro alguns truques para "atacá-los"**.\
_Observe que, às vezes, o domínio está hospedado em um IP que não é controlado pelo cliente e, portanto, não está no escopo; tome cuidado._

## Subdomínios

> Conhecemos todas as empresas dentro do escopo, todos os ativos de cada empresa e todos os domínios relacionados às empresas.

É hora de encontrar todos os subdomínios possíveis de cada domínio encontrado.

> [!TIP]
> Observe que algumas ferramentas e técnicas para encontrar domínios também podem ajudar a encontrar subdomínios

### **DNS**

Vamos tentar obter **subdomínios** a partir dos registros **DNS**. Também devemos tentar um **Zone Transfer** (se estiver vulnerável, você deve reportá-lo).

```bash
dnsrecon -a -d tesla.com
```

### **OSINT**

Para APIs e plataformas que abrangem infraestrutura, reputação, registros de vazamentos e enriquecimento além da descoberta de subdomínios, consulte o [catálogo de APIs de reconhecimento e inteligência contra ameaças](reconnaissance-and-threat-intelligence-apis.md).

A maneira mais rápida de obter muitos subdomínios é pesquisar em fontes externas. As **ferramentas** mais usadas são as seguintes (para obter melhores resultados, configure as chaves de API):


- [**BBOT**](https://github.com/blacklanternsecurity/bbot)

```bash
# subdomains
bbot -t tesla.com -f subdomain-enum

# subdomains (passive only)
bbot -t tesla.com -f subdomain-enum -rf passive

# subdomains + port scan + web screenshots
bbot -t tesla.com -f subdomain-enum -m naabu gowitness -n my_scan -o .
```

- [**Amass**](https://github.com/owasp-amass/amass)

```bash
amass enum [-active] [-ip] -d tesla.com
amass enum -d tesla.com | grep tesla.com # To just list subdomains
```

- [**subfinder**](https://github.com/projectdiscovery/subfinder)

```bash
# Subfinder, use -silent to only have subdomains in the output
./subfinder-linux-amd64 -d tesla.com [-silent]
```

- [**findomain**](https://github.com/Findomain/Findomain)

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

Existem **outras ferramentas/APIs interessantes** que, mesmo não sendo especializadas diretamente em encontrar subdomínios, podem ser úteis para encontrá-los, como:

- [**IP.THC.ORG**](https://ip.thc.org) API gratuita

```bash
curl https://ip.thc.org/tesla.com
```

- [**API gratuita do AnubisDB**](https://github.com/jonluca/Anubis-DB)

```bash
curl https://anubisdb.com/anubis/subdomains/tesla.com | jq -r ".[]"
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

- [**gau**](https://github.com/lc/gau)**:** busca URLs conhecidas do AlienVault's Open Threat Exchange, da Wayback Machine e do Common Crawl para qualquer domínio fornecido.

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

- [**SecurityTrails**](https://securitytrails.com/) oferece acesso gratuito limitado à API para dados atuais de DNS e subdomínios; dados históricos de DNS/IP exigem um plano pago.
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)
- [**activedns.net**](https://activedns.net/)

Este projeto oferece **gratuitamente todos os subdomínios relacionados a programas de bug bounty**. Você também pode acessar esses dados usando [chaospy](https://github.com/Moaaz-0x/chaospy) ou até mesmo acessar o escopo usado por este projeto [https://github.com/projectdiscovery/public-bugbounty-programs](https://github.com/projectdiscovery/public-bugbounty-programs)

Você pode encontrar uma **comparação** de muitas dessas ferramentas aqui: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Vamos tentar encontrar novos **subdomínios** fazendo brute force em servidores DNS com possíveis nomes de subdomínio.

Para esta ação, você precisará de algumas **wordlists de subdomínios comuns, como**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Você também precisará de IPs de bons resolvedores DNS. Para gerar uma lista de resolvedores DNS confiáveis, você pode baixar os resolvedores em [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) e usar [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) para filtrá-los. Ou você pode usar: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

As ferramentas mais recomendadas para DNS brute-force são:

- [**massdns**](https://github.com/blechschmidt/massdns): Esta foi a primeira ferramenta a realizar brute force de DNS de forma eficaz. É muito rápida, mas propensa a falsos positivos.

```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```

- [**gobuster**](https://github.com/OJ/gobuster): Este, acho que, usa apenas 1 resolver

```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```

- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) é um wrapper para `massdns`, escrito em Go, que permite enumerar subdomínios válidos usando bruteforce ativo, além de resolver subdomínios com tratamento de wildcard e suporte simples a entrada e saída.

```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```

- [**puredns**](https://github.com/d3mondev/puredns): Também usa `massdns`.

```
puredns bruteforce all.txt domain.com
```

- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) usa asyncio para fazer brute force de nomes de domínio de forma assíncrona.

```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```

### Segunda rodada de brute-force de DNS

Depois de encontrar subdomínios usando fontes abertas e brute-force, você pode gerar variações dos subdomínios encontrados para tentar encontrar ainda mais. Várias ferramentas são úteis para esse propósito:

- [**dnsgen**](https://github.com/AlephNullSK/dnsgen)**:** Gera permutações a partir dos domínios e subdomínios fornecidos.

```bash
cat subdomains.txt | dnsgen -
```

- [**goaltdns**](https://github.com/subfinder/goaltdns): Recebe domínios e subdomínios e gera permutações.
  - Você pode obter a **wordlist** de permutações do goaltdns [**aqui**](https://github.com/subfinder/goaltdns/blob/master/words.txt).

```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```

- [**gotator**](https://github.com/Josue87/gotator)**:** Dada uma lista de domínios e subdomínios, gera permutações. Se nenhum arquivo de permutações for indicado, o gotator usará o próprio.

```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```

- [**altdns**](https://github.com/infosec-au/altdns): Além de gerar permutações de subdomínios, também pode tentar resolvê-los (mas é melhor usar as ferramentas mencionadas anteriormente).
  - Você pode obter a **wordlist** de permutações do altdns [**aqui**](https://github.com/infosec-au/altdns/blob/master/words.txt).

```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```

- [**dmut**](https://github.com/bp0lr/dmut): Outra ferramenta para realizar permutações, mutações e alterações de subdomínios. Essa ferramenta fará brute force dos resultados (não oferece suporte a DNS wildcard).
  - Você pode obter a wordlist de permutações do dmut [**aqui**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).

```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
    --dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```

- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Com base em um domínio, **gera novos nomes potenciais de subdomínios** usando os padrões indicados para tentar descobrir mais subdomínios.

#### Geração inteligente de permutações

- [**regulator**](https://github.com/cramppet/regulator): Aprende padrões semelhantes a regex a partir dos subdomínios descobertos e gera nomes candidatos para resolver.<sup>[[8]](#references)</sup>

```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```

- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ é um fuzzer de brute force de subdomínios, combinado com um algoritmo extremamente simples, mas eficaz, guiado por respostas DNS. Ele utiliza um conjunto de dados de entrada fornecido, como uma wordlist personalizada ou registros históricos de DNS/TLS, para sintetizar com precisão mais nomes de domínio correspondentes e expandi-los ainda mais em um loop, com base nas informações coletadas durante a varredura de DNS.

```
echo www | subzuf facebook.com
```

### **Fluxo de trabalho para descoberta de subdomínios**

Os exemplos de fluxo de trabalho do Trickest combinam OSINT, brute force de DNS e etapas de permutação para enumeração repetível de subdomínios.<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

Se você encontrou um endereço IP com **uma ou várias páginas web** pertencentes a subdomínios, pode tentar **encontrar outros subdomínios com sites nesse IP** consultando **fontes OSINT** em busca de domínios associados a um IP ou fazendo **brute force de nomes de domínio VHost nesse IP**.

#### OSINT

Você pode encontrar alguns **VHosts em IPs usando** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **ou outras APIs**.

**Brute Force**

Se suspeitar que algum subdomínio está oculto em um servidor web, você pode tentar fazer brute force:

Para vhosts baseados em nome, aplique fuzzing ao cabeçalho `Host` e use a calibração automática do ffuf para filtrar a resposta padrão.<sup>[[2]](#references)</sup>

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

### **Brute Force de Buckets**

Ao procurar **subdomínios**, fique atento para ver se algum **aponta** para algum tipo de **bucket** e, nesse caso, [**verifique as permissões**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Além disso, como neste ponto você conhecerá todos os domínios dentro do escopo, tente [**fazer brute force de possíveis nomes de bucket e verificar as permissões**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Monitoramento**

Você pode **monitorar** a criação de **novos subdomínios** de um domínio monitorando os logs de **Certificate Transparency**, como faz o [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Procurando vulnerabilidades**

Verifique se há possíveis [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Se o **subdomínio** apontar para algum **bucket S3**, [**verifique as permissões**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Se encontrar algum **subdomínio com um IP diferente** dos que já encontrou na descoberta de ativos, faça uma **varredura básica de vulnerabilidades** (usando Nessus ou OpenVAS) e uma [**varredura de portas**](../pentesting-network/index.html#discovering-hosts-from-the-outside) com **nmap/masscan/shodan**. Dependendo dos serviços em execução, você poderá encontrar **neste livro algumas técnicas para "atacá-los"**.\
_Observe que, às vezes, o subdomínio está hospedado em um IP que não é controlado pelo cliente e, portanto, está fora do escopo. Tenha cuidado._

## IPs

Nas etapas iniciais, você pode ter **encontrado alguns intervalos de IPs, domínios e subdomínios**.\
É hora de **reunir todos os IPs desses intervalos** e dos **domínios/subdomínios (consultas DNS).**

Usando serviços como os seguintes, você também pode encontrar **IPs usados anteriormente por domínios e subdomínios**. Esses IPs ainda podem pertencer ao cliente (e permitir que você encontre [**bypasses do CloudFlare**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

- [**SecurityTrails**](https://securitytrails.com/) (os dados históricos de DNS/IP exigem um plano pago)

Você também pode verificar quais domínios apontam para um endereço IP específico usando a ferramenta [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Procurando vulnerabilidades**

**Faça uma varredura de portas em todos os IPs que não pertencem a CDNs** (pois provavelmente você não encontrará nada de interessante neles). Nos serviços em execução que forem descobertos, talvez **seja possível encontrar vulnerabilidades**.

**Encontre um** [**guia**](../pentesting-network/index.html) **sobre como fazer varreduras de hosts.**

## Caça a servidores web

> Encontramos todas as empresas e seus ativos, e conhecemos os intervalos de IPs, domínios e subdomínios dentro do escopo. É hora de procurar servidores web.

Nas etapas anteriores, você provavelmente já fez um pouco de **recon dos IPs e domínios descobertos**, então talvez **já tenha encontrado todos os possíveis servidores web**. No entanto, se ainda não os encontrou, vamos ver agora algumas **técnicas rápidas para procurar servidores web** dentro do escopo.

Observe que isto será **voltado à descoberta de web apps**, então você também deve **fazer a varredura de vulnerabilidades** e a **varredura de portas** (**se permitido** pelo escopo).

Um **método rápido** para descobrir **portas abertas** relacionadas a servidores **web** usando [**masscan pode ser encontrado aqui**](../pentesting-network/index.html#http-port-discovery).\
Outra ferramenta prática para procurar servidores web é o [**httprobe**](https://github.com/tomnomnom/httprobe)**,** o [**fprobe**](https://github.com/theblackturtle/fprobe) e o [**httpx**](https://github.com/projectdiscovery/httpx). Basta passar uma lista de domínios, e a ferramenta tentará se conectar às portas 80 (http) e 443 (https). Além disso, você pode indicar outras portas para tentar:

```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```

### **Capturas de tela**

Agora que você descobriu **todos os servidores web** presentes no escopo (entre os **IPs** da empresa e todos os **domínios** e **subdomínios**), provavelmente **não sabe por onde começar**. Então, vamos simplificar e começar tirando capturas de tela de todos eles. Só de **olhar** para a **página principal**, você pode encontrar endpoints **estranhos**, mais **propensos** a serem **vulneráveis**.

Para executar a ideia proposta, você pode usar [**EyeWitness**](https://github.com/RedSiege/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) ou [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Além disso, você pode usar [**eyeballer**](https://github.com/BishopFox/eyeballer) para analisar todas as **capturas de tela** e indicar **quais provavelmente contêm vulnerabilidades** e quais não contêm.

## Ativos de Cloud pública

Para encontrar possíveis ativos de cloud pertencentes a uma empresa, você deve **começar com uma lista de palavras-chave que identifiquem essa empresa**. Por exemplo, para uma empresa de criptomoedas, você pode usar palavras como: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Você também vai precisar de wordlists de **palavras comuns usadas em buckets**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Em seguida, com essas palavras, você deve gerar **permutações** (consulte a [**Segunda rodada de DNS Brute-Force**](#second-dns-bruteforce-round) para mais informações).

Com as wordlists resultantes, você pode usar ferramentas como [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **ou** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Lembre-se de que, ao procurar ativos de Cloud, você deve procurar **mais do que apenas buckets no AWS**.

### **Procurando vulnerabilidades**

Se encontrar itens como **buckets abertos ou funções de cloud expostas**, você deve **acessá-los** e tentar ver o que oferecem e se é possível abusar deles.

## Emails

Com os **domínios** e **subdomínios** dentro do escopo, você basicamente já tem tudo o que **precisa para começar a procurar emails**. Estas são as **APIs** e **ferramentas** que funcionaram melhor para mim na busca por emails de uma empresa:

- [**theHarvester**](https://github.com/laramies/theHarvester) - com APIs
- API de [**https://hunter.io/**](https://hunter.io/) (versão gratuita)
- API de [**https://app.snov.io/**](https://app.snov.io/) (versão gratuita)
- API de [**https://minelead.io/**](https://minelead.io/) (versão gratuita)

### **Procurando vulnerabilidades**

Os emails serão úteis mais tarde para fazer **brute-force em logins web e serviços de autenticação** (como SSH). Eles também são necessários para **phishing**. Além disso, essas APIs fornecerão ainda mais **informações sobre a pessoa** por trás do email, o que é útil para a campanha de phishing.

## Credential Leaks

Com os **domínios,** **subdomínios** e **emails**, você pode começar a procurar credenciais que foram leaked no passado e que pertencem a esses emails:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Procurando vulnerabilidades**

Se encontrar credenciais **leaked válidas**, será uma vitória fácil.

## Secrets Leaks

Credential leaks estão relacionados a ataques a empresas nos quais **informações confidenciais foram leaked e vendidas**. No entanto, as empresas podem ser afetadas por **outros leaks** cujas informações não estão nesses bancos de dados:

### Github Leaks

Credenciais e APIs podem ser leaked nos **repositórios públicos** da **empresa** ou dos **usuários** que trabalham nessa empresa no github.\
Você pode usar a **ferramenta** [**Leakos**](https://github.com/carlospolop/Leakos) para **baixar** todos os **repositórios públicos** de uma **organização** e de seus **desenvolvedores** e executar [**gitleaks**](https://github.com/gitleaks/gitleaks) neles automaticamente.

**Leakos** também pode ser usado para executar **gitleaks** em todas as **URLs de texto** fornecidas a ele, pois às vezes **páginas web também contêm secrets**.

#### Github Dorks

Consulte a [página GitHub dorks and leaks](github-leaked-secrets.md) para encontrar possíveis **GitHub dorks** para pesquisar na organização.

### Pastes Leaks

Às vezes, atacantes ou simplesmente funcionários **publicam conteúdo da empresa em um site de paste**. Esse conteúdo pode ou não conter **informações confidenciais**, mas é muito interessante procurá-lo.\
Você pode usar a ferramenta [**Pastos**](https://github.com/carlospolop/Pastos) para pesquisar em mais de 80 sites de paste ao mesmo tempo.

### Google Dorks

Os antigos, mas valiosos, Google dorks são sempre úteis para encontrar **informações expostas que não deveriam estar ali**. O único problema é que o [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) contém vários **milhares** de consultas possíveis que você não pode executar manualmente. Então, você pode escolher suas 10 favoritas ou usar uma **ferramenta como** [**Gorks**](https://github.com/carlospolop/Gorks) **para executá-las todas**.

_Note que as ferramentas que tentam executar todo o banco de dados usando o navegador regular do Google nunca terminarão, pois o Google vai bloqueá-las muito, muito rapidamente._

### **Procurando vulnerabilidades**

Se encontrar credenciais ou tokens de API **leaked válidos**, será uma vitória fácil.

## Vulnerabilidades em código público

Se você descobriu que a empresa tem **código open source**, pode **analisá-lo** e procurar **vulnerabilidades** nele.

**Dependendo da linguagem**, há diferentes **ferramentas** que você pode usar; consulte a lista de [ferramentas de revisão de código-fonte](../../network-services-pentesting/pentesting-web/code-review-tools.md).

Também existem serviços gratuitos que permitem **analisar repositórios públicos**, como:

- [**Snyk**](https://app.snyk.io/)

## [**Metodologia de Pentesting Web**](../../network-services-pentesting/pentesting-web/index.html)

A **maioria das vulnerabilidades** encontradas por bug hunters está em **aplicações web**, então, neste ponto, gostaria de falar sobre uma **metodologia de teste de aplicações web**. Você pode [**encontrar essas informações aqui**](../../network-services-pentesting/pentesting-web/index.html).

Também quero destacar a seção [**ferramentas open source de scanners web automatizados**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), pois, embora você não deva esperar que elas encontrem vulnerabilidades muito sensíveis, são úteis para incorporá-las a **workflows que forneçam algumas informações iniciais sobre a web.**

## Recapitulação

> Parabéns! Neste ponto, você já realizou **toda a enumeração básica**. Sim, é básica porque há muito mais enumeração que pode ser feita (veremos mais truques adiante).

Você já:

1. Encontrou todas as **empresas** dentro do escopo
2. Encontrou todos os **ativos** pertencentes às empresas (e fez algumas análises de vulnerabilidades, se estiverem no escopo)
3. Encontrou todos os **domínios** pertencentes às empresas
4. Encontrou todos os **subdomínios** dos domínios (algum subdomain takeover?)
5. Encontrou todos os **IPs** (de CDNs e **não de CDNs**) dentro do escopo.
6. Encontrou todos os **servidores web** e tirou uma **captura de tela** de cada um (algo estranho que mereça uma análise mais profunda?)
7. Encontrou todos os **possíveis ativos de cloud pública** pertencentes à empresa.
8. **Emails**, **credential leaks** e **secret leaks** que podem proporcionar uma **grande vitória com facilidade**.
9. **Fez Pentesting em todos os sites encontrados**

## **Ferramentas automáticas completas de Recon**

Existem várias ferramentas que executam parte das ações propostas em um determinado escopo.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Um pouco antiga e sem atualizações

## References

- [1] [Jason Haddix – A metodologia do Bug Hunter v4.0: edição Recon](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – Sobre favicons: de ícones de navegador a inteligência de superfície de ataque](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – Transformando favicon.ico em arma para BugBounties, OSINT e muito mais](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – Descobrindo domínios por meio de um ataque de correlação temporal em Certificate Transparency](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – Takeover passivo: descobrindo (e emulando) uma campanha cara de subdomain takeover](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator: um método exclusivo de enumeração de subdomínios](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – Workflow completo para descoberta de subdomínios, parte 1](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – Descoberta completa de subdomínios por brute-force usando workflow automatizado do Trickest, parte 2](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter – captura de tela da saída do favihash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}
