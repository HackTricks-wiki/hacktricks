# Metodologia de Reconhecimento Externo

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<img src="../../.gitbook/assets/i3.png" alt="" data-size="original">\
**Dica de bug bounty**: **inscreva-se** no **Intigriti**, uma plataforma premium de **bug bounty criada por hackers, para hackers**! Junte-se a nós em [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) hoje e comece a ganhar recompensas de até **$100.000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

## Descoberta de Ativos

> Então, disseram que tudo que pertence a uma determinada empresa está dentro do escopo, e você quer descobrir o que essa empresa realmente possui.

O objetivo desta fase é obter todas as **empresas pertencentes à empresa principal** e, em seguida, todos os **ativos** dessas empresas. Para fazer isso, vamos:

1. Encontrar as aquisições da empresa principal, isso nos dará as empresas dentro do escopo.
2. Encontrar o ASN (se houver) de cada empresa, isso nos dará os intervalos de IP de propriedade de cada empresa.
3. Usar pesquisas de whois reverso para procurar outras entradas (nomes de organizações, domínios...) relacionadas à primeira (isso pode ser feito recursivamente).
4. Usar outras técnicas como filtros `org` e `ssl` do shodan para procurar outros ativos (o truque `ssl` pode ser feito recursivamente).

### **Aquisições**

Antes de tudo, precisamos saber quais **outras empresas são de propriedade da empresa principal**.\
Uma opção é visitar [https://www.crunchbase.com/](https://www.crunchbase.com), **procurar** pela **empresa principal** e **clicar** em "**aquisições**". Lá você verá outras empresas adquiridas pela principal.\
Outra opção é visitar a página do **Wikipedia** da empresa principal e procurar por **aquisições**.

> Ok, neste ponto você deve saber todas as empresas dentro do escopo. Vamos descobrir como encontrar seus ativos.

### **ASN**

Um número de sistema autônomo (**ASN**) é um **número único** atribuído a um **sistema autônomo** (AS) pela **Internet Assigned Numbers Authority (IANA)**.\
Um **AS** consiste em **blocos** de **endereços IP** que possuem uma política claramente definida para acessar redes externas e são administrados por uma única organização, mas podem ser compostos por vários operadores.

É interessante descobrir se a **empresa atribuiu algum ASN** para encontrar seus **intervalos de IP**. Será interessante realizar um **teste de vulnerabilidade** contra todos os **hosts** dentro do **escopo** e **procurar por domínios** dentro desses IPs.\
Você pode **procurar** pelo **nome da empresa**, pelo **IP** ou pelo **domínio** em [**https://bgp.he.net/**](https://bgp.he.net)**.**\
**Dependendo da região da empresa, esses links podem ser úteis para reunir mais dados:** [**AFRINIC**](https://www.afrinic.net) **(África),** [**Arin**](https://www.arin.net/about/welcome/region/)**(América do Norte),** [**APNIC**](https://www.apnic.net) **(Ásia),** [**LACNIC**](https://www.lacnic.net) **(América Latina),** [**RIPE NCC**](https://www.ripe.net) **(Europa). De qualquer forma, provavelmente todas as informações úteis (intervalos de IP e Whois)** já aparecem no primeiro link.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Também, a enumeração de subdomínios do [**BBOT**](https://github.com/blacklanternsecurity/bbot) automaticamente agrega e resume os ASNs ao final da varredura.
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

### **Procurando por vulnerabilidades**

Neste ponto, conhecemos **todos os ativos dentro do escopo**, então, se permitido, você pode executar algum **scanner de vulnerabilidades** (Nessus, OpenVAS) em todos os hosts.\
Além disso, você pode executar algumas [**varreduras de porta**](../pentesting-network/#discovering-hosts-from-the-outside) **ou usar serviços como** shodan **para encontrar** portas abertas **e, dependendo do que encontrar, você deve** dar uma olhada neste livro para saber como testar vários serviços possíveis em execução.\
**Também pode valer a pena mencionar que você também pode preparar algumas** listas de nomes de usuário e senhas padrão e tentar** forçar a entrada em serviços com [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domínios

> Sabemos todas as empresas dentro do escopo e seus ativos, é hora de encontrar os domínios dentro do escopo.

_Por favor, note que nas técnicas propostas a seguir, você também pode encontrar subdomínios e essa informação não deve ser subestimada._

Em primeiro lugar, você deve procurar o(s) **domínio(s) principal(is)** de cada empresa. Por exemplo, para a _Tesla Inc._ será _tesla.com_.

### **DNS reverso**

Como você encontrou todos os intervalos de IP dos domínios, pode tentar realizar **pesquisas de DNS reverso** nesses **IPs para encontrar mais domínios dentro do escopo**. Tente usar algum servidor DNS da vítima ou algum servidor DNS bem conhecido (1.1.1.1, 8.8.8.8).
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Para que isso funcione, o administrador deve habilitar manualmente o PTR.\
Você também pode usar uma ferramenta online para essa informação: [http://ptrarchive.com/](http://ptrarchive.com)

### **Reverse Whois (loop)**

Dentro de um **whois**, você pode encontrar muitas informações interessantes, como o nome da organização, endereço, e-mails, números de telefone... Mas o que é ainda mais interessante é que você pode encontrar **mais ativos relacionados à empresa** se você realizar **pesquisas de whois reverso por qualquer um desses campos** (por exemplo, outros registros de whois onde o mesmo e-mail aparece).\
Você pode usar ferramentas online como:

* [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Grátis**
* [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Grátis**
* [https://www.reversewhois.io/](https://www.reversewhois.io) - **Grátis**
* [https://www.whoxy.com/](https://www.whoxy.com) - Web **grátis**, API não grátis.
* [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Não grátis
* [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Não grátis (apenas **100 pesquisas grátis**)
* [https://www.domainiq.com/](https://www.domainiq.com) - Não grátis

Você pode automatizar essa tarefa usando [**DomLink** ](https://github.com/vysecurity/DomLink)(requer uma chave de API whoxy).\
Você também pode realizar alguma descoberta automática de whois reverso com [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Observe que você pode usar essa técnica para descobrir mais nomes de domínio toda vez que encontrar um novo domínio.**

### **Trackers**

Se você encontrar o **mesmo ID do mesmo tracker** em 2 páginas diferentes, você pode supor que **ambas as páginas** são **gerenciadas pela mesma equipe**.\
Por exemplo, se você vir o mesmo **ID do Google Analytics** ou o mesmo **ID do Adsense** em várias páginas.

Existem algumas páginas e ferramentas que permitem que você pesquise por esses trackers e mais:

* [**Udon**](https://github.com/dhn/udon)
* [**BuiltWith**](https://builtwith.com)
* [**Sitesleuth**](https://www.sitesleuth.io)
* [**Publicwww**](https://publicwww.com)
* [**SpyOnWeb**](http://spyonweb.com)

### **Favicon**

Você sabia que podemos encontrar domínios e subdomínios relacionados ao nosso alvo procurando pelo mesmo hash de ícone de favicon? Isso é exatamente o que a ferramenta [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) feita por [@m4ll0k2](https://twitter.com/m4ll0k2) faz. Veja como usar:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - descubra domínios com o mesmo hash de ícone de favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Simplificando, o favihash nos permitirá descobrir domínios que possuem o mesmo hash de ícone de favicon que nosso alvo.

Além disso, você também pode pesquisar tecnologias usando o hash de favicon, conforme explicado neste [**post de blog**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139). Isso significa que se você conhece o **hash do favicon de uma versão vulnerável de uma tecnologia web**, você pode pesquisar no shodan e **encontrar mais lugares vulneráveis**:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
Assim é como você pode **calcular o hash do favicon** de um site:
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
### **Direitos autorais / String única**

Procure dentro das páginas da web **strings que possam ser compartilhadas em diferentes sites na mesma organização**. A **string de direitos autorais** pode ser um bom exemplo. Em seguida, pesquise essa string no **Google**, em outros **navegadores** ou até mesmo no **Shodan**: `shodan search http.html:"string de direitos autorais"`

### **Tempo CRT**

É comum ter um trabalho cron, como
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
Renovar todos os certificados de domínio no servidor. Isso significa que, mesmo que a CA usada para isso não defina a hora em que foi gerada no tempo de validade, é possível **encontrar domínios pertencentes à mesma empresa nos logs de transparência de certificados**. Confira este [**artigo para mais informações**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

### **Assumir passivamente**

Aparentemente, é comum as pessoas atribuírem subdomínios a IPs que pertencem a provedores de nuvem e, em algum momento, **perderem esse endereço IP, mas esquecem de remover o registro DNS**. Portanto, apenas **iniciando uma VM** em uma nuvem (como a Digital Ocean), você estará realmente **assumindo o controle de alguns subdomínios**.

[**Este post**](https://kmsec.uk/blog/passive-takeover/) explica uma história sobre isso e propõe um script que **inicia uma VM na DigitalOcean**, **obtém** o **IPv4** da nova máquina e **procura no Virustotal por registros de subdomínios** apontando para ela.

### **Outras maneiras**

**Observe que você pode usar essa técnica para descobrir mais nomes de domínio toda vez que encontrar um novo domínio.**

**Shodan**

Como você já sabe o nome da organização que possui o espaço IP. Você pode pesquisar por esses dados no shodan usando: `org:"Tesla, Inc."` Verifique os hosts encontrados em busca de novos domínios inesperados no certificado TLS.

Você pode acessar o **certificado TLS** da página da web principal, obter o **nome da organização** e, em seguida, procurar por esse nome dentro dos **certificados TLS** de todas as páginas da web conhecidas pelo **shodan** com o filtro: `ssl:"Tesla Motors"`

**Assetfinder**

[**Assetfinder**](https://github.com/tomnomnom/assetfinder) é uma ferramenta que procura por **domínios relacionados** com um domínio principal e **subdomínios** deles, muito incrível.

### **Procurando por vulnerabilidades**

Verifique se há algum [assumir o controle de domínio](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Talvez alguma empresa esteja **usando um domínio**, mas **perdeu a propriedade**. Basta registrá-lo (se for barato o suficiente) e informar a empresa.

Se você encontrar algum **domínio com um IP diferente** dos que já encontrou na descoberta de ativos, deve realizar uma **verificação básica de vulnerabilidades** (usando Nessus ou OpenVAS) e uma [**verificação de porta**](../pentesting-network/#discovering-hosts-from-the-outside) com **nmap/masscan/shodan**. Dependendo dos serviços em execução, você pode encontrar em **este livro alguns truques para "atacá-los"**.\
_Obs: às vezes, o domínio está hospedado dentro de um IP que não é controlado pelo cliente, portanto, não está no escopo, tenha cuidado._

<img src="../../.gitbook/assets/i3.png" alt="" data-size="original">\
**Dica de bug bounty**: **inscreva-se** no **Intigriti**, uma plataforma premium de **bug bounty criada por hackers, para hackers**! Junte-se a nós em [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) hoje e comece a ganhar recompensas de até **$100.000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

## Subdomínios

> Sabemos todas as empresas dentro do escopo, todos os ativos de cada empresa e todos os domínios relacionados às empresas.

É hora de encontrar todos os possíveis subdomínios de cada domínio encontrado.

### **DNS**

Vamos tentar obter **subdomínios** dos registros **DNS**. Também devemos tentar a **Transferência de Zona** (se vulnerável, você deve relatá-la).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

A maneira mais rápida de obter muitos subdomínios é pesquisar em fontes externas. As **ferramentas** mais usadas são as seguintes (para obter melhores resultados, configure as chaves da API):

* [**BBOT**](https://github.com/blacklanternsecurity/bbot)
```bash
# subdomains
bbot -t tesla.com -f subdomain-enum

# subdomains (passive only)
bbot -t tesla.com -f subdomain-enum -rf passive

# subdomains + port scan + web screenshots
bbot -t tesla.com -f subdomain-enum -m naabu gowitness -n my_scan -o .
```
* [**Amass**](https://github.com/OWASP/Amass)

Amass é uma ferramenta de reconhecimento de rede que ajuda a mapear a superfície de ataque de uma organização. Ele usa técnicas de inteligência de fontes abertas e ativas para descobrir nomes de domínio, subdomínios, endereços IP e portas abertas. A ferramenta é altamente configurável e pode ser usada para realizar varreduras de rede em larga escala ou para focar em alvos específicos.
```bash
amass enum [-active] [-ip] -d tesla.com
amass enum -d tesla.com | grep tesla.com # To just list subdomains
```
* [**subfinder**](https://github.com/projectdiscovery/subfinder)

Subfinder é uma ferramenta de reconhecimento de subdomínios que usa fontes públicas para encontrar subdomínios de um determinado domínio. Ele pode ser usado para encontrar subdomínios de um alvo específico durante a fase de reconhecimento externo.
```bash
# Subfinder, use -silent to only have subdomains in the output
./subfinder-linux-amd64 -d tesla.com [-silent]
```
* [**findomain**](https://github.com/Edu4rdSHL/findomain/)

O **findomain** é uma ferramenta de reconhecimento de subdomínios que usa uma abordagem de busca passiva. Ele encontra subdomínios usando vários mecanismos de busca na web e verifica se eles estão online. É uma ferramenta muito útil para encontrar subdomínios que podem ser usados em ataques de phishing ou para encontrar possíveis pontos de entrada em um sistema.
```bash
# findomain, use -silent to only have subdomains in the output
./findomain-linux -t tesla.com [--quiet]
```
* [**OneForAll**](https://github.com/shmilylty/OneForAll/tree/master/docs/en-us)

O OneForAll é uma ferramenta de reconhecimento de domínio que pode ser usada para coletar informações de subdomínios, endereços IP e emails relacionados a um domínio específico. Ele usa várias fontes de dados, como motores de busca, certificados SSL e registros DNS, para coletar informações. A ferramenta é altamente personalizável e pode ser facilmente integrada a outras ferramentas de reconhecimento de domínio.
```bash
python3 oneforall.py --target tesla.com [--dns False] [--req False] [--brute False] run
```
* [**assetfinder**](https://github.com/tomnomnom/assetfinder)

O **assetfinder** é uma ferramenta de reconhecimento de ativos que ajuda a encontrar subdomínios de um domínio específico. Ele usa várias fontes de dados, incluindo certificados SSL, registros DNS e resultados de pesquisa na web para encontrar subdomínios. É uma ferramenta útil para expandir sua superfície de ataque e encontrar possíveis pontos de entrada em um alvo.
```bash
assetfinder --subs-only <domain>
```
* [**Sudomy**](https://github.com/Screetsec/Sudomy)

Sudomy é uma ferramenta de reconhecimento de subdomínios escrita em Python que usa várias fontes para coletar informações sobre subdomínios. Ele tem uma ampla gama de recursos, incluindo a capacidade de realizar consultas de DNS em massa, verificar a presença de subdomínios em várias fontes, como Wayback Machine, Common Crawl, Virus Total, etc. Além disso, ele também pode verificar a presença de subdomínios em vários provedores de hospedagem, como AWS, Heroku, etc. Sudomy é uma ferramenta muito útil para coletar informações sobre subdomínios e pode ser facilmente integrada em pipelines de CI/CD.
```bash
# It requires that you create a sudomy.api file with API keys
sudomy -d tesla.com
```
* [**vita**](https://github.com/junnlikestea/vita)

Vita é uma ferramenta de reconhecimento externo que usa várias fontes de informação para coletar informações sobre um alvo. Ele pode ser usado para coletar informações sobre subdomínios, endereços IP, endereços de e-mail, nomes de usuário, senhas e muito mais. A ferramenta é altamente personalizável e pode ser facilmente integrada a outras ferramentas de reconhecimento externo.
```
vita -d tesla.com
```
* [**theHarvester**](https://github.com/laramies/theHarvester)

O theHarvester é uma ferramenta de código aberto que permite coletar informações de e-mail, subdomínios, hosts, nomes de usuários e outras informações relevantes de diferentes fontes públicas, como motores de busca, servidores DNS e arquivos de configuração. É uma ferramenta útil para a fase de reconhecimento externo, pois ajuda a coletar informações sobre a infraestrutura de uma organização e seus funcionários.
```bash
theHarvester -d tesla.com -b "anubis, baidu, bing, binaryedge, bingapi, bufferoverun, censys, certspotter, crtsh, dnsdumpster, duckduckgo, fullhunt, github-code, google, hackertarget, hunter, intelx, linkedin, linkedin_links, n45ht, omnisint, otx, pentesttools, projectdiscovery, qwant, rapiddns, rocketreach, securityTrails, spyse, sublist3r, threatcrowd, threatminer, trello, twitter, urlscan, virustotal, yahoo, zoomeye"
```
Existem **outras ferramentas/APIs interessantes** que, mesmo que não sejam diretamente especializadas em encontrar subdomínios, podem ser úteis para encontrá-los, como:

* [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Usa a API [https://sonar.omnisint.io](https://sonar.omnisint.io) para obter subdomínios.
```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```
* [**API gratuita JLDC**](https://jldc.me/anubis/subdomains/google.com)
```bash
curl https://jldc.me/anubis/subdomains/tesla.com | jq -r ".[]"
```
* [**RapidDNS**](https://rapiddns.io) API gratuito
```bash
# Get Domains from rapiddns free API
rapiddns(){
 curl -s "https://rapiddns.io/subdomain/$1?full=1" \
  | grep -oE "[\.a-zA-Z0-9-]+\.$1" \
  | sort -u
}
rapiddns tesla.com
```
* [**https://crt.sh/**](https://crt.sh)

Este site é uma ferramenta de busca de certificados SSL/TLS. Ele permite que você pesquise certificados emitidos para um determinado domínio, bem como certificados emitidos por uma determinada autoridade de certificação. Isso pode ser útil para encontrar subdomínios de um determinado domínio, bem como para identificar possíveis vulnerabilidades de segurança.
```bash
# Get Domains from crt free API
crt(){
 curl -s "https://crt.sh/?q=%25.$1" \
  | grep -oE "[\.a-zA-Z0-9-]+\.$1" \
  | sort -u
}
crt tesla.com
```
* [**gau**](https://github.com/lc/gau)**:** busca URLs conhecidas do AlienVault's Open Threat Exchange, do Wayback Machine e do Common Crawl para qualquer domínio fornecido.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
* [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **e** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Eles vasculham a web em busca de arquivos JS e extraem subdomínios a partir deles.
```bash
# Get only subdomains from SubDomainizer
python3 SubDomainizer.py -u https://tesla.com | grep tesla.com

# Get only subdomains from subscraper, this already perform recursion over the found results
python subscraper.py -u tesla.com | grep tesla.com | cut -d " " -f
```
* [**Shodan**](https://www.shodan.io/)

Shodan é um mecanismo de busca que permite aos usuários encontrar dispositivos conectados à internet, como servidores, roteadores, câmeras de segurança, entre outros. Ele também permite que os usuários pesquisem por informações específicas sobre esses dispositivos, como versões de software, endereços IP e portas abertas. Shodan é frequentemente usado por hackers para encontrar vulnerabilidades em sistemas conectados à internet.
```bash
# Get info about the domain
shodan domain <domain>
# Get other pages with links to subdomains
shodan search "http.html:help.domain.com"
```
* [**Censys subdomain finder**](https://github.com/christophetd/censys-subdomain-finder)

Este é um script Python que usa a API do Censys para encontrar subdomínios de um determinado domínio. Ele também pode ser usado para encontrar subdomínios de um domínio específico que estejam hospedados em um determinado provedor de nuvem. O script é fácil de usar e pode ser executado em um terminal.
```
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
python3 censys-subdomain-finder.py tesla.com
```
* [**securitytrails.com**](https://securitytrails.com/) tem uma API gratuita para procurar subdomínios e histórico de IP
* [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Este projeto oferece gratuitamente todos os subdomínios relacionados a programas de recompensa por bugs. Você também pode acessar esses dados usando [chaospy](https://github.com/dr-0x0x/chaospy) ou acessar o escopo usado por este projeto [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Você pode encontrar uma **comparação** de muitas dessas ferramentas aqui: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **Força bruta de DNS**

Vamos tentar encontrar novos **subdomínios** forçando servidores DNS usando possíveis nomes de subdomínio.

Para esta ação, você precisará de algumas **listas de palavras comuns de subdomínios, como**:

* [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
* [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
* [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
* [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
* [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

E também IPs de bons resolvers DNS. Para gerar uma lista de resolvers DNS confiáveis, você pode baixar os resolvers de [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) e usar [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) para filtrá-los. Ou você pode usar: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

As ferramentas mais recomendadas para força bruta de DNS são:

* [**massdns**](https://github.com/blechschmidt/massdns): Esta foi a primeira ferramenta que realizou uma força bruta de DNS efetiva. É muito rápido, no entanto, é propenso a falsos positivos.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
* [**gobuster**](https://github.com/OJ/gobuster): Este usa apenas 1 resolvedor.
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
* [**shuffledns**](https://github.com/projectdiscovery/shuffledns) é um wrapper em torno do `massdns`, escrito em go, que permite enumerar subdomínios válidos usando brute force ativo, bem como resolver subdomínios com tratamento de wildcard e suporte fácil de entrada-saída.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
* [**puredns**](https://github.com/d3mondev/puredns): Ele também utiliza o `massdns`.
```
puredns bruteforce all.txt domain.com
```
* [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) utiliza asyncio para forçar nomes de domínio de forma assíncrona.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Segunda rodada de DNS Brute-Force

Depois de encontrar subdomínios usando fontes abertas e brute-force, você pode gerar alterações dos subdomínios encontrados para tentar encontrar ainda mais. Várias ferramentas são úteis para esse propósito:

* [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Dado os domínios e subdomínios, gera permutações.
```bash
cat subdomains.txt | dnsgen -
```
* [**goaltdns**](https://github.com/subfinder/goaltdns): Dado os domínios e subdomínios, gera permutações.
  * Você pode obter a lista de permutações do goaltdns em **wordlist** [**aqui**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
* [**gotator**](https://github.com/Josue87/gotator)**:** Dado os domínios e subdomínios, gera permutações. Se nenhum arquivo de permutações for indicado, o gotator usará o próprio arquivo.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
* [**altdns**](https://github.com/infosec-au/altdns): Além de gerar permutações de subdomínios, também pode tentar resolvê-los (mas é melhor usar as ferramentas comentadas anteriormente).
  * Você pode obter a lista de palavras para permutações do altdns **aqui** (https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
* [**dmut**](https://github.com/bp0lr/dmut): Outra ferramenta para realizar permutações, mutações e alterações de subdomínios. Esta ferramenta irá forçar bruta o resultado (não suporta wildcard dns).
  * Você pode obter a lista de palavras de permutação do dmut [**aqui**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
    --dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
* [**alterx**](https://github.com/projectdiscovery/alterx)**:** Com base em um domínio, ele **gera novos nomes potenciais de subdomínios** com base em padrões indicados para tentar descobrir mais subdomínios.

#### Geração inteligente de permutações

* [**regulator**](https://github.com/cramppet/regulator): Para mais informações, leia este [**post**](https://cramppet.github.io/regulator/index.html), mas basicamente ele irá pegar as **partes principais** dos **subdomínios descobertos** e irá misturá-las para encontrar mais subdomínios.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
* [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ é um fuzzer de força bruta de subdomínios acoplado a um algoritmo imensamente simples, mas eficaz, guiado por respostas DNS. Ele utiliza um conjunto fornecido de dados de entrada, como uma lista de palavras personalizada ou registros históricos de DNS/TLS, para sintetizar com precisão mais nomes de domínio correspondentes e expandi-los ainda mais em um loop com base nas informações coletadas durante a varredura DNS.
```
echo www | subzuf facebook.com
```
### **Fluxo de Descoberta de Subdomínios**

Confira este post que escrevi sobre como **automatizar a descoberta de subdomínios** de um domínio usando **fluxos de trabalho Trickest** para que eu não precise lançar manualmente um monte de ferramentas no meu computador:

{% embed url="https://trickest.com/blog/full-subdomain-discovery-using-workflow/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

{% embed url="https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

### **VHosts / Hosts Virtuais**

Se você encontrou um endereço IP contendo **uma ou várias páginas da web** pertencentes a subdomínios, você pode tentar **encontrar outros subdomínios com páginas da web nesse IP** procurando em **fontes OSINT** por domínios em um IP ou **forçando a descoberta de nomes de domínio VHost nesse IP**.

#### OSINT

Você pode encontrar alguns **VHosts em IPs usando** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **ou outras APIs**.

**Força Bruta**

Se você suspeita que algum subdomínio pode estar oculto em um servidor da web, você pode tentar forçar a descoberta:
```bash
ffuf -c -w /path/to/wordlist -u http://victim.com -H "Host: FUZZ.victim.com"

gobuster vhost -u https://mysite.com -t 50 -w subdomains.txt

wfuzz -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt --hc 400,404,403 -H "Host: FUZZ.example.com" -u http://example.com -t 100

#From https://github.com/allyshka/vhostbrute
vhostbrute.py --url="example.com" --remoteip="10.1.1.15" --base="www.example.com" --vhosts="vhosts_full.list"

#https://github.com/codingo/VHostScan
VHostScan -t example.com
```
{% hint style="info" %}
Com esta técnica, você pode até mesmo acessar endpoints internos/ocultos.
{% endhint %}

### **CORS Brute Force**

Às vezes, você encontrará páginas que só retornam o cabeçalho _**Access-Control-Allow-Origin**_ quando um domínio/subdomínio válido é definido no cabeçalho _**Origin**_. Nesses cenários, você pode abusar desse comportamento para **descobrir** novos **subdomínios**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Força Bruta de Buckets**

Ao procurar por **subdomínios**, fique atento para ver se ele está **apontando** para algum tipo de **bucket**, e nesse caso [**verifique as permissões**](../../network-services-pentesting/pentesting-web/buckets/)**.**\
Além disso, como nesse ponto você conhecerá todos os domínios dentro do escopo, tente [**forçar possíveis nomes de buckets e verificar as permissões**](../../network-services-pentesting/pentesting-web/buckets/).

### **Monitoramento**

Você pode **monitorar** se **novos subdomínios** de um domínio são criados monitorando os **Logs de Transparência de Certificado** que o [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py) faz.

### **Procurando por vulnerabilidades**

Verifique possíveis [**apropriações de subdomínio**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Se o **subdomínio** estiver apontando para algum **bucket S3**, [**verifique as permissões**](../../network-services-pentesting/pentesting-web/buckets/).

Se você encontrar algum **subdomínio com um IP diferente** dos que já encontrou na descoberta de ativos, você deve realizar uma **verificação básica de vulnerabilidades** (usando Nessus ou OpenVAS) e uma [**verificação de porta**](../pentesting-network/#discovering-hosts-from-the-outside) com **nmap/masscan/shodan**. Dependendo dos serviços em execução, você pode encontrar em **este livro alguns truques para "atacá-los"**.\
_Obs: às vezes, o subdomínio está hospedado dentro de um IP que não é controlado pelo cliente, portanto, não está no escopo, tenha cuidado._

## IPs

Nos passos iniciais, você pode ter **encontrado alguns intervalos de IP, domínios e subdomínios**.\
É hora de **recolher todos os IPs desses intervalos** e dos **domínios/subdomínios (consultas DNS).**

Usando serviços das seguintes **APIs gratuitas**, você também pode encontrar **IPs anteriores usados por domínios e subdomínios**. Esses IPs ainda podem ser de propriedade do cliente (e podem permitir que você encontre [**bypasses do CloudFlare**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

* [**https://securitytrails.com/**](https://securitytrails.com/)

### **Procurando por vulnerabilidades**

**Verifique as portas de todos os IPs que não pertencem a CDNs** (já que você provavelmente não encontrará nada interessante lá). Nos serviços em execução descobertos, você pode ser **capaz de encontrar vulnerabilidades**.

**Encontre um** [**guia**](../pentesting-network/) **sobre como escanear hosts.**

## Caça a servidores web

> Encontramos todas as empresas e seus ativos e conhecemos os intervalos de IP, domínios e subdomínios dentro do escopo. É hora de procurar por servidores web.

Nos passos anteriores, você provavelmente já realizou alguma **recon dos IPs e domínios descobertos**, então você pode ter **encontrado todos os possíveis servidores web**. No entanto, se você não o fez, agora vamos ver alguns **truques rápidos para procurar servidores web** dentro do escopo.

Por favor, note que isso será **orientado para a descoberta de aplicativos da web**, então você deve **realizar a verificação de vulnerabilidades** e **verificação de porta** também (**se permitido pelo escopo**).

Um **método rápido** para descobrir **portas abertas** relacionadas a **servidores web usando [**masscan** pode ser encontrado aqui](../pentesting-network/#http-port-discovery).\
Outra ferramenta amigável para procurar servidores web é [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) e [**httpx**](https://github.com/projectdiscovery/httpx). Você apenas passa uma lista de domínios e ele tentará se conectar à porta 80 (http) e 443 (https). Além disso, você pode indicar para tentar outras portas:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Capturas de tela**

Agora que você descobriu **todos os servidores web** presentes no escopo (entre os **IPs** da empresa e todos os **domínios** e **subdomínios**), provavelmente **não sabe por onde começar**. Então, vamos simplificar e começar apenas tirando capturas de tela de todos eles. Apenas **dando uma olhada** na **página principal**, você pode encontrar **endpoints estranhos** que são mais **propensos** a serem **vulneráveis**.

Para realizar a ideia proposta, você pode usar [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/) ou [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Além disso, você pode usar [**eyeballer**](https://github.com/BishopFox/eyeballer) para percorrer todas as **capturas de tela** e dizer o que é **provável conter vulnerabilidades** e o que não é.

## Ativos de nuvem pública

Para encontrar possíveis ativos de nuvem pertencentes a uma empresa, você deve **começar com uma lista de palavras-chave que identifiquem essa empresa**. Por exemplo, para uma empresa de criptomoedas, você pode usar palavras como: `"crypto", "wallet", "dao", "<nome_do_domínio>", <"nomes_de_subdomínios">`.

Você também precisará de listas de palavras comuns usadas em buckets:

* [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
* [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
* [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Em seguida, com essas palavras, você deve gerar **permutações** (verifique a seção [**Segunda rodada de brute-force DNS**](./#second-dns-bruteforce-round) para mais informações).

Com as listas de palavras resultantes, você pode usar ferramentas como [**cloud\_enum**](https://github.com/initstring/cloud\_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **ou** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Lembre-se de que, ao procurar Ativos de Nuvem, você deve **procurar mais do que apenas buckets na AWS**.

### **Procurando por vulnerabilidades**

Se você encontrar coisas como **buckets abertos ou funções de nuvem expostas**, você deve **acessá-los** e tentar ver o que eles oferecem e se você pode abusar deles.

## E-mails

Com os **domínios** e **subdomínios** dentro do escopo, você basicamente tem tudo o que precisa para começar a procurar por e-mails. Estes são os **APIs** e **ferramentas** que funcionaram melhor para mim para encontrar e-mails de uma empresa:

* [**theHarvester**](https://github.com/laramies/theHarvester) - com APIs
* API de [**https://hunter.io/**](https://hunter.io/) (versão gratuita)
* API de [**https://app.snov.io/**](https://app.snov.io/) (versão gratuita)
* API de [**https://minelead.io/**](https://minelead.io/) (versão gratuita)

### **Procurando por vulnerabilidades**

Os e-mails serão úteis mais tarde para **brute-force em logins web e serviços de autenticação** (como SSH). Além disso, eles são necessários para **phishings**. Além disso, essas APIs fornecerão ainda mais **informações sobre a pessoa** por trás do e-mail, o que é útil para a campanha de phishing.

## Vazamentos de credenciais

Com os **domínios**, **subdomínios** e **e-mails**, você pode começar a procurar por credenciais vazadas no passado pertencentes a esses e-mails:

* [https://leak-lookup.com](https://leak-lookup.com/account/login)
* [https://www.dehashed.com/](https://www.dehashed.com/)

### **Procurando por vulnerabilidades**

Se você encontrar credenciais vazadas **válidas**, isso é uma vitória
