# Metodologija eksternog izviđanja

{{#include ../../banners/hacktricks-training.md}}

## Otkrivanje asseta

> Dakle, rečeno vam je da je sve što pripada nekoj kompaniji u scope-u i želite da utvrdite šta ta kompanija zapravo poseduje.

Cilj ove faze je da pronađemo sve **kompanije u vlasništvu glavne kompanije**, a zatim i sve **asset-e** tih kompanija. Da bismo to uradili, potrebno je da:

1. Pronađemo akvizicije glavne kompanije, što će nam dati kompanije koje su u scope-u.
2. Pronađemo ASN (ako postoji) svake kompanije, što će nam dati IP opsege u vlasništvu svake kompanije
3. Koristimo reverse whois lookups za pretragu drugih unosa (nazivi organizacija, domeni...) povezanih sa prvim unosom (ovo se može raditi rekurzivno)
4. Koristimo druge tehnike, kao što su shodan `org` i `ssl` filteri, za pretragu drugih asseta (trik sa `ssl` može se raditi rekurzivno).

### **Akvizicije**

Pre svega, treba da saznamo koje **druge kompanije su u vlasništvu glavne kompanije**.\
Jedna opcija je da posetite [https://www.crunchbase.com/](https://www.crunchbase.com), **pretražite** **glavnu kompaniju** i **kliknete** na "**acquisitions**". Tamo ćete videti druge kompanije koje je glavna kompanija preuzela.\
Druga opcija je da posetite stranicu glavne kompanije na **Wikipedia**-i i pretražite **acquisitions**.\
Za javne kompanije proverite **SEC/EDGAR filings**, stranice za **investor relations** ili lokalne registre kompanija (npr. **Companies House** u UK).\
Za globalna korporativna stabla i podružnice pokušajte sa **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) i bazom **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> U redu, u ovom trenutku bi trebalo da znate sve kompanije koje su u scope-u. Hajde da utvrdimo kako da pronađemo njihove assete.

### **ASN-ovi**

Autonomni sistemski broj (**ASN**) je **jedinstveni broj** dodeljen **autonomnom sistemu** (AS) od strane **Internet Assigned Numbers Authority (IANA)**.\
**AS** se sastoji od **blokova** **IP adresa** koji imaju jasno definisanu politiku pristupa eksternim mrežama i kojima upravlja jedna organizacija, ali ih može činiti više operatora.

Korisno je utvrditi da li je **kompaniji dodeljen neki ASN**, kako bismo pronašli njene **IP opsege.** Biće korisno izvršiti **vulnerability test** nad svim **hostovima** unutar **scope-a** i **potražiti domene** unutar tih IP adresa.\
Možete **pretraživati** po **nazivu kompanije**, **IP adresi** ili **domenu** na [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **ili** [**https://ipinfo.io/**](https://ipinfo.io/).\
**U zavisnosti od regiona u kojem se kompanija nalazi, ovi linkovi mogu biti korisni za prikupljanje dodatnih podataka:** [**AFRINIC**](https://www.afrinic.net) **(Afrika),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Severna Amerika),** [**APNIC**](https://www.apnic.net) **(Azija),** [**LACNIC**](https://www.lacnic.net) **(Latinska Amerika),** [**RIPE NCC**](https://www.ripe.net) **(Evropa). U svakom slučaju, verovatno se sve** korisne informacije **(IP opsezi i Whois)** već pojavljuju na prvom linku.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Takođe, [**BBOT**](https://github.com/blacklanternsecurity/bbot)**-ova** enumeracija automatski objedinjuje i sažima ASN-ove na kraju skeniranja.
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
IP opsege organizacije možete pronaći i pomoću [http://asnlookup.com/](http://asnlookup.com) (ima besplatan API).\
IP adresu i ASN domena možete pronaći pomoću [http://ipv4info.com/](http://ipv4info.com).

### **Traženje ranjivosti**

U ovom trenutku znamo **sve resurse unutar opsega**, pa, ako vam je dozvoljeno, možete pokrenuti neki **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) nad svim hostovima.\
Takođe, možete pokrenuti [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **ili koristiti servise kao što su** Shodan, Censys ili ZoomEye **da pronađete** otvorene portove **i, u zavisnosti od onoga što pronađete, trebalo bi da** pogledate u ovoj knjizi kako da pentestujete različite moguće servise koji rade.\
**Takođe, vredi pomenuti da možete pripremiti i** liste podrazumevanih korisničkih imena **i** lozinki **i pokušati da** bruteforce-ujete servise pomoću [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domeni

> Znamo sve kompanije unutar opsega i njihove resurse; vreme je da pronađemo domene unutar opsega.

_Napomena: pomoću sledećih predloženih tehnika možete pronaći i poddomene, a te informacije ne treba potcenjivati._

Pre svega, trebalo bi da pronađete **glavni domen**(e) svake kompanije. Na primer, za _Tesla Inc._ to će biti _tesla.com_.

### **Reverse DNS**

Pošto ste pronašli sve IP opsege domena, možete pokušati da izvršite **reverse DNS lookups** nad tim **IP adresama kako biste pronašli još domena unutar opsega**. Pokušajte da koristite neki DNS server žrtve ili neki poznati DNS server (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
For this to work, administrator mora ručno da omogući PTR.\
Možete koristiti i online alat za ove informacije: [http://ptrarchive.com/](http://ptrarchive.com).\
Za velike opsege, alati kao što su [**massdns**](https://github.com/blechschmidt/massdns) i [**dnsx**](https://github.com/projectdiscovery/dnsx) korisni su za automatizovanje reverse lookups i enrichment-a.

### **Reverse Whois (loop)**

U okviru **whois**-a možete pronaći mnogo zanimljivih **informacija**, kao što su **naziv organizacije**, **adresa**, **email adrese**, brojevi telefona... Ali još je zanimljivije to što možete pronaći **dodatne assete povezane sa kompanijom** ako izvršite **reverse whois lookups koristeći bilo koje od tih polja** (na primer, druge whois registre u kojima se pojavljuje ista email adresa).\
Možete koristiti online alate kao što su:

- [https://ip.thc.org/](https://ip.thc.org/) - **Besplatno** (Web i API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Besplatno**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Besplatno**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Besplatno**
- [https://www.whoxy.com/](https://www.whoxy.com) - **Besplatan** web, API nije besplatan.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Nije besplatno
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Nije besplatno (samo **100 besplatnih** pretraga)
- [https://www.domainiq.com/](https://www.domainiq.com) - Nije besplatno
- [https://securitytrails.com/](https://securitytrails.com/) - Nije besplatno (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - Nije besplatno (API)

Ovaj zadatak možete automatizovati pomoću alata [**DomLink** ](https://github.com/vysecurity/DomLink)(zahteva whoxy API ključ).\
Takođe možete izvršiti automatsko reverse whois otkrivanje pomoću alata [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Imajte na umu da ovu tehniku možete koristiti za otkrivanje dodatnih naziva domena svaki put kada pronađete novi domen.**

### **Trackers**

Ako pronađete **isti ID istog tracker-a** na 2 različite stranice, možete pretpostaviti da **obema stranicama** upravlja **isti tim**.\
Na primer, ako na nekoliko stranica vidite isti **Google Analytics ID** ili isti **Adsense ID**.

Postoje stranice i alati koji vam omogućavaju da pretražujete na osnovu ovih tracker-a i drugih podataka:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (pronalazi povezane sajtove na osnovu zajedničke analytics/trackers konfiguracije)

### **Favicon**

Da li ste znali da možemo pronaći povezane domene i poddomene našeg cilja tako što ćemo potražiti isti hash favicon ikone? Upravo to radi alat [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py), koji je napravio [@m4ll0k2](https://twitter.com/m4ll0k2). Evo kako se koristi:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - otkrivanje domena sa istim hashom favicon ikone](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Jednostavno rečeno, favihash nam omogućava da otkrijemo domene koji imaju isti hash favicon ikone kao naš target.

Pored toga, možete pretraživati i tehnologije koristeći hash favicon ikone, kao što je objašnjeno u [**ovom blog postu**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139). To znači da, ako znate **hash favicon ikone ranjive verzije web tehnologije**, možete pretražiti Shodan i **pronaći još ranjivih mesta**:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```
Ovo je način na koji možete **izračunati favicon hash** web stranice (MMH3 nad **base64-enkodiranim** bajtovima favicona):
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
Favicon hash-eve možete dobiti i u velikom obimu pomoću [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`), a zatim izvršiti pivot u Shodan/Censys.

Korisne stvari koje treba zapamtiti pri korišćenju favicon fingerprint-a:<sup>[[3]](#references)[[4]](#references)</sup>

- **Tretirajte hash kao indikator, a ne kao dokaz**: MMH3 je kompaktan i kolizije su moguće; operatori takođe mogu zameniti favicon ili namerno ponovo koristiti obmanjujuću ikonu.
- **Proverite više od** `/favicon.ico`: mnogi proizvodi izlažu ikone u framework/build putanjama ili putem `manifest.json`, `site.webmanifest`, `browserconfig.xml`, `apple-touch-icon*`, inline `data:` URL-ova ili HTML `<link rel="icon">` tagova. Sama putanja može fingerprint-ovati familiju proizvoda.
- **Static fajlovi su često dostupni kada aplikacija nije**: WAF/SSO/IdP kontrole mogu štititi dinamičke rute, ali i dalje izlagati static ikone. Uvek direktno zatražite favicon i pregledajte `ETag`, `Last-Modified`, redirects i cache headers radi slabih nagoveštaja o verziji/build-u.
- **Validirajte podudaranja okolnim signalima**: uporedite title, HTML/body hash, headers, TLS certificate subjects/SANs, Shodan/Censys komponente i izložene portove pre nego što zaključite da favicon identifikuje proizvod.
- **Grupišite prema HTML/body hash-u pri pivotovanju u velikom obimu**: ako se većina hostova koji dele favicon svodi na jedan page template, fingerprint je pouzdaniji; ako se isti hash deli na mnogo nepovezanih template-a, koristite oznaku „generic/shared/honeypot“ umesto oznake proizvoda.
- **Honeypot heuristika**: ako se isti favicon hash pojavljuje na mnogim nepovezanim HTML signature-ima, nasumičnim portovima i neusaglašenim proizvodima, tretirajte ga kao verovatni honeypot ili generički placeholder, a ne kao stvarni product fingerprint.
- **Koristite 404 probe na nejasnim target-ima**: preuzmite stvarnu stranicu i nepostojeću putanju, kao što je `/_favicon_probe_<8-hex>`, u browser-u. Podudarni hosting-provider/parking odgovori često bolje objašnjavaju deljene favicon-e nego stvarno preklapanje proizvoda.
- **Bootstrap-ujte mappings iz detection rules**: Nuclei templates i javni favicon datasets mogu obezbediti poznata `favicon` ↔ `product` ↔ `CPE` mapiranja koja su korisna za brzo triage-ovanje nakon objavljivanja CVE-ova.
- **Napomena o pokrivenosti**: Shodan-style datasets su IP-centric. Površine iza CDN-a, SNI-routed, anycast i domain-only površine mogu biti nedovoljno zastupljene, tako da mali broj pogodaka **ne znači** malu realnu deployment zastupljenost.

### **Copyright / Uniq string**

Pretražite unutar web stranica **string-ove koji bi mogli biti deljeni između različitih web sajtova u istoj organizaciji**. **Copyright string** može biti dobar primer. Zatim potražite taj string na **google-u**, u drugim **browser-ima** ili čak u **shodan-u**: `shodan search http.html:"Copyright string"`

### **CRT Time**

Uobičajeno je imati cron job kao što je
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
da obnovi sve sertifikate domena na serveru. To znači da je, čak i ako CA korišćen za ovo ne postavi vreme generisanja u vreme važenja, moguće **pronaći domene koji pripadaju istoj kompaniji u certificate transparency logovima**.\
Pogledajte [**ovaj writeup za više informacija**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

Takođe direktno koristite **certificate transparency** logove:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Informacije o Mail DMARC-u

Možete koristiti web stranicu kao što je [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) ili alat kao što je [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) da pronađete **domene i poddomene koji dele iste DMARC informacije**.\
Drugi korisni alati su [**spoofcheck**](https://github.com/BishopFox/spoofcheck) i [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Očigledno je uobičajeno da ljudi dodele poddomene IP adresama koje pripadaju cloud provajderima i da u nekom trenutku **izgube tu IP adresu, ali zaborave da uklone DNS zapis**. Zato ćete, jednostavnim **pokretanjem VM-a** u cloud-u (kao što je Digital Ocean), zapravo **preuzeti neke poddomene**.

[**Ovaj tekst**](https://kmsec.uk/blog/passive-takeover/) objašnjava slučaj u vezi s tim i predlaže skriptu koja **pokreće VM u DigitalOcean-u**, **dobavlja** **IPv4** adresu nove mašine i **pretražuje Virustotal u potrazi za zapisima poddomena** koji upućuju na nju.

### **Drugi načini**

**Imajte na umu da ovu tehniku možete koristiti za otkrivanje dodatnih naziva domena svaki put kada pronađete novi domen.**

**Shodan**

Kao što već znate naziv organizacije koja poseduje IP prostor, te podatke možete pretraživati u shodan-u koristeći: `org:"Tesla, Inc."` Proverite pronađene hostove u potrazi za novim neočekivanim domenima u TLS sertifikatu.

Možete pristupiti **TLS sertifikatu** glavne web stranice, dobiti **Organisation name**, a zatim pretražiti taj naziv unutar **TLS sertifikata** svih web stranica poznatih alatu **shodan**, pomoću filtera: `ssl:"Tesla Motors"` ili koristiti alat kao što je [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)je alat koji pronalazi **domene povezane** sa glavnim domenom i njihove **poddomene**, prilično neverovatno.

**Passive DNS / Historical DNS**

Podaci iz Passive DNS-a su odlični za pronalaženje **starih i zaboravljenih zapisa** koji se i dalje razrešavaju ili mogu biti preuzeti. Pogledajte:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Traženje ranjivosti**

Proverite da li postoji neki [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Možda neka kompanija **koristi neki domen**, ali je **izgubila vlasništvo nad njim**. Jednostavno ga registrujte (ako je dovoljno jeftin) i obavestite kompaniju.

Ako pronađete bilo koji **domen sa IP adresom različitom** od onih koje ste već pronašli tokom otkrivanja asseta, trebalo bi da izvršite **osnovno skeniranje ranjivosti** (pomoću Nessus-a ili OpenVAS-a) i neki [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) pomoću **nmap/masscan/shodan** alata. U zavisnosti od servisa koji rade, u **ovoj knjizi možete pronaći neke trikove za njihov „napad“**.\
_Napomena: ponekad je domen hostovan unutar IP adrese koju klijent ne kontroliše, pa nije u scope-u; budite oprezni._

## Poddomene

> Znamo sve kompanije koje su u scope-u, sve assete svake kompanije i sve domene povezane sa kompanijama.

Vreme je da pronađemo sve moguće poddomene svakog pronađenog domena.

> [!TIP]
> Imajte na umu da neki alati i tehnike za pronalaženje domena mogu pomoći i u pronalaženju poddomena

### **DNS**

Pokušajmo da dobijemo **poddomene** iz **DNS** zapisa. Takođe bi trebalo da pokušamo sa **Zone Transfer** (ako je ranjiv, trebalo bi da ga prijavite).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Najbrži način za pronalaženje velikog broja poddomena jeste pretraga eksternih izvora. Najčešće korišćeni **alati** su sledeći (za bolje rezultate konfigurišite API ključeve):

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
Postoje **drugi zanimljivi alati/API-jevi** koji, iako nisu direktno specijalizovani za pronalaženje poddomena, mogu biti korisni za pronalaženje poddomena, kao što su:

- [**IP.THC.ORG**](https://ip.thc.org) besplatni API
```bash
curl https://ip.thc.org/tesla.com
```
- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Koristi API [https://sonar.omnisint.io](https://sonar.omnisint.io) za pronalaženje poddomena
```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```
- [**JLDC besplatni API**](https://jldc.me/anubis/subdomains/google.com)
```bash
curl https://jldc.me/anubis/subdomains/tesla.com | jq -r ".[]"
```
- [**RapidDNS**](https://rapiddns.io) besplatni API
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
- [**gau**](https://github.com/lc/gau)**:** preuzima poznate URL-ove sa AlienVault-ovog Open Threat Exchange-a, Wayback Machine-a i Common Crawl-a za dati domen.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Pretražuju web u potrazi za JS datotekama i iz njih izdvajaju subdomene.
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
- [**Censys pronalazač poddomena**](https://github.com/christophetd/censys-subdomain-finder)
```bash
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
python3 censys-subdomain-finder.py tesla.com
```
- [**DomainTrail.py**](https://github.com/gatete/DomainTrail)
```bash
python3 DomainTrail.py -d example.com
```
- [**securitytrails.com**](https://securitytrails.com/) ima besplatan API za pretragu poddomena i istorije IP adresa
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Ovaj projekat besplatno nudi **sve poddomene povezane sa bug-bounty programima**. Ovim podacima možete pristupiti i koristeći [chaospy](https://github.com/dr-0x0x/chaospy), ili čak pristupiti scope-u koji koristi ovaj projekat [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

**Poređenje** mnogih ovih alata možete pronaći ovde: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Pokušajmo da pronađemo nove **poddomaine** vršeći brute-force DNS servera koristeći moguće nazive poddomena.

Za ovu radnju biće vam potrebni neki **uobičajeni wordlists poddomena, kao što su**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Takođe i IP adrese dobrih DNS resolvera. Da biste generisali listu pouzdanih DNS resolvera, možete preuzeti resolvere sa [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) i koristiti [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) da ih filtrirate. Ili možete koristiti: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Najpreporučeniji alati za DNS brute-force su:

- [**massdns**](https://github.com/blechschmidt/massdns): Ovo je bio prvi alat koji je efikasno vršio DNS brute-force. Veoma je brz, ali je sklon false positive rezultatima.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Za ovaj mislim da koristi samo 1 resolver
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) je omotač oko `massdns`, napisan u jeziku Go, koji omogućava enumeraciju validnih poddomena pomoću aktivnog brute-force-a, kao i razrešavanje poddomena uz rukovanje wildcard-ima i jednostavnu podršku za ulaz i izlaz.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): Takođe koristi `massdns`.
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) koristi asyncio za asinhroni brute force naziva domena.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Drugi DNS Brute-Force krug

Nakon pronalaženja poddomena korišćenjem open sources i brute-forcinga, možete generisati izmene pronađenih poddomena kako biste pokušali da pronađete još više njih. Nekoliko alata je korisno za ovu svrhu:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Na osnovu domena i poddomena generiše permutacije.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): Na osnovu domena i poddomena generiše permutacije.
- Možete preuzeti goaltdns permutations **wordlist** [**ovde**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** Na osnovu domena i poddomena generiše permutacije. Ako nije navedena datoteka sa permutacijama, gotator će koristiti sopstvenu.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Pored generisanja permutacija poddomena, može i da pokuša da ih razreši (ali je bolje koristiti prethodno komentarisane alate).
- altdns **wordlist** sa permutacijama možete pronaći [**ovde**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Još jedan alat za izvršavanje permutacija, mutacija i izmena subdomena. Ovaj alat će izvršiti brute force rezultata (ne podržava DNS wildcard).
- dmut wordlist za permutacije možete pronaći [**ovde**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Na osnovu domena **generiše nova potencijalna imena subdomena** na osnovu naznačenih obrazaca kako bi pokušao da otkrije još subdomena.

#### Generisanje pametnih permutacija

- [**regulator**](https://github.com/cramppet/regulator): Za više informacija pročitajte ovu [**objavu**](https://cramppet.github.io/regulator/index.html), ali on u osnovi uzima **glavne delove** iz **otkrivenih subdomena** i kombinuje ih kako bi pronašao još subdomena.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ je fuzzer za brute-force pronalaženje poddomena, uparen sa izuzetno jednostavnim, ali efikasnim algoritmom vođenim DNS odgovorima. Koristi dostavljeni skup ulaznih podataka, kao što su prilagođena wordlist ili istorijski DNS/TLS zapisi, kako bi precizno generisao dodatna odgovarajuća imena domena i još ih proširivao u petlji, na osnovu informacija prikupljenih tokom DNS skeniranja.
```
echo www | subzuf facebook.com
```
### **Subdomain Discovery Workflow**

Pogledajte ovaj blog post koji sam napisao o tome kako da **automatizujete subdomain discovery** sa domena pomoću **Trickest workflows**, tako da ne moram ručno da pokrećem veliki broj alata na svom računaru:

{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}

{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtual Hosts**

Ako pronađete IP adresu koja sadrži **jednu ili više web stranica** koje pripadaju poddomenima, možete pokušati da **pronađete druge poddomene sa web stranicama na toj IP adresi** tako što ćete potražiti **OSINT izvore** za domene na određenoj IP adresi ili izvršiti **brute-forcing VHost imena domena na toj IP adresi**.

#### OSINT

Neke **VHosts na IP adresama možete pronaći pomoću** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **ili drugih API-ja**.

**Brute Force**

Ako sumnjate da je neki poddomen skriven na web serveru, možete pokušati da izvršite brute force:

Kada **IP adresa preusmerava na hostname** (name-based vhosts), direktno fuzzujte `Host` header i dozvolite alatu ffuf da izvrši **auto-calibrate** kako bi istakao odgovore koji se razlikuju od podrazumevanog vhost-a:<sup>[[2]](#references)</sup>
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
> Ovom tehnikom možda čak možete pristupiti internim/skrivenim endpointima.

### **CORS Brute Force**

Ponekad ćete pronaći stranice koje vraćaju header _**Access-Control-Allow-Origin**_ samo kada je validan domen/poddomen postavljen u headeru _**Origin**_. U ovim scenarijima možete zloupotrebiti ovo ponašanje da **otkrijete** nove **poddome­ne**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Brute force bucket-a**

Dok tražite **poddomenе**, obratite pažnju na to da li neki **pokazuje** na bilo koju vrstu **bucket-a**, i u tom slučaju [**proverite dozvole**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Takođe, pošto ćete u ovom trenutku znati sve domene unutar obuhvata, pokušajte da [**brute force-om pronađete moguća imena bucket-a i proverite dozvole**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Praćenje**

Možete **pratiti** da li se kreiraju **novi poddomeni** nekog domena praćenjem **Certificate Transparency** Logs, što radi [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Traženje ranjivosti**

Proverite moguće slučajeve [**subdomain takeover-a**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Ako **poddomen** pokazuje na neki **S3 bucket**, [**proverite dozvole**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Ako pronađete bilo koji **poddomen sa IP adresom različitom** od onih koje ste već pronašli tokom otkrivanja resursa, trebalo bi da izvršite **osnovno skeniranje ranjivosti** (koristeći Nessus ili OpenVAS) i neki [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) pomoću **nmap/masscan/shodan**. U zavisnosti od toga koji servisi rade, u **ovoj knjizi možete pronaći neke trikove za njihovo „napadanje“**.\
_Napomena: poddomen je ponekad hostovan unutar IP adrese koju klijent ne kontroliše, pa nije u obuhvatu; budite pažljivi._

## IP adrese

U početnim koracima možda ste **pronašli neke opsege IP adresa, domene i poddomene**.\
Vreme je da **prikupite sve IP adrese iz tih opsega** i za **domene/poddomene (DNS upiti).**

Korišćenjem servisa iz sledećih **besplatnih API-ja** takođe možete pronaći **prethodne IP adrese koje su koristili domeni i poddomeni**. Ove IP adrese možda još uvek pripadaju klijentu (i mogu vam omogućiti da pronađete [**CloudFlare bypass-e**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

- [**https://securitytrails.com/**](https://securitytrails.com/)

Takođe možete proveriti domene koji pokazuju na određenu IP adresu pomoću alata [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Traženje ranjivosti**

**Izvršite port scan svih IP adresa koje ne pripadaju CDN-ovima** (jer vrlo verovatno tamo nećete pronaći ništa zanimljivo). U otkrivenim servisima koji rade možda ćete **moći da pronađete ranjivosti**.

**Pronađite** [**vodič**](../pentesting-network/index.html) **o tome kako skenirati hostove.**

## Potraga za web serverima

> Pronašli smo sve kompanije i njihove resurse i znamo opsege IP adresa, domene i poddomene unutar obuhvata. Vreme je da potražimo web servere.

U prethodnim koracima ste verovatno već izvršili određeni **recon IP adresa i otkrivenih domena**, tako da ste možda **već pronašli sve moguće web servere**. Međutim, ako niste, sada ćemo videti neke **brze trikove za traženje web servera** unutar obuhvata.

Imajte na umu da će ovo biti **usmereno na otkrivanje web aplikacija**, pa bi trebalo da izvršite i **skeniranje ranjivosti** i **port scanning** (**ako je dozvoljeno** obuhvatom).

**Brz metod** za otkrivanje **otvorenih portova** povezanih sa **web** serverima pomoću alata [**masscan** može se pronaći ovde](../pentesting-network/index.html#http-port-discovery).\
Još jedan jednostavan alat za traženje web servera je [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) i [**httpx**](https://github.com/projectdiscovery/httpx). Prosleđujete mu samo listu domena, a on će pokušati da se poveže na portove 80 (http) i 443 (https). Dodatno, možete navesti i druge portove koje treba pokušati:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Screenshots**

Sada kada ste otkrili **sve web servere** prisutne u obuhvatu (među **IP** adresama kompanije i svim **domenima** i **subdomenima**), verovatno **ne znate odakle da počnete**. Zato ćemo to pojednostaviti i početi tako što ćemo napraviti screenshots svih njih. Samim **gledanjem** u **glavnu stranicu** možete pronaći **neobične** endpoint-e koji su **podložniji** tome da budu **ranjivi**.

Da biste sproveli predloženu ideju, možete koristiti [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) ili [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Pored toga, možete koristiti [**eyeballer**](https://github.com/BishopFox/eyeballer) nad svim **screenshots** kako bi vam rekao **šta verovatno sadrži ranjivosti**, a šta ne.

## Public Cloud Assets

Da biste pronašli potencijalne cloud assets koji pripadaju kompaniji, trebalo bi da **počnete sa listom keywords koji identifikuju tu kompaniju**. Na primer, za crypto kompaniju možete koristiti reči kao što su: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Takođe će vam biti potrebne wordlists sa **uobičajenim rečima koje se koriste u bucket-ima**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Zatim bi pomoću tih reči trebalo da generišete **permutations** (pogledajte [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) za više informacija).

Sa dobijenim wordlists možete koristiti alate kao što su [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **ili** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Zapamtite da prilikom traženja Cloud Assets treba da **tražite više od samo bucket-a u AWS-u**.

### **Looking for vulnerabilities**

Ako pronađete stvari kao što su **otvoreni bucket-i ili izložene cloud funkcije**, trebalo bi da im **pristupite** i pokušate da vidite šta vam nude i da li možete da ih zloupotrebite.

## Emails

Sa **domenima** i **subdomenima** unutar obuhvata, u osnovi imate sve što vam je **potrebno da počnete da tražite email adrese**. Ovo su **API-ji** i **alati** koji su meni najbolje funkcionisali za pronalaženje email adresa kompanije:

- [**theHarvester**](https://github.com/laramies/theHarvester) - sa API-jima
- API od [**https://hunter.io/**](https://hunter.io/) (besplatna verzija)
- API od [**https://app.snov.io/**](https://app.snov.io/) (besplatna verzija)
- API od [**https://minelead.io/**](https://minelead.io/) (besplatna verzija)

### **Looking for vulnerabilities**

Email adrese će vam kasnije biti korisne za **brute-force web logina i auth servisa** (kao što je SSH). Takođe su potrebne za **phishing**. Pored toga, ovi API-ji će vam pružiti još više **informacija o osobi** koja stoji iza email adrese, što je korisno za phishing kampanju.

## Credential Leaks

Sa **domenima,** **subdomenima** i **email adresama** možete početi da tražite credential-e koji su ranije leak-ovani, a pripadaju tim email adresama:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Looking for vulnerabilities**

Ako pronađete **važeće leak-ovane** credential-e, to je veoma laka pobeda.

## Secrets Leaks

Credential leaks su povezani sa hack-ovima kompanija pri kojima su **osetljive informacije leak-ovane i prodate**. Međutim, kompanije mogu biti pogođene i **drugim leak-ovima** čije se informacije ne nalaze u tim bazama:

### Github Leaks

Credential-i i API-ji mogu biti leak-ovani u **javnim repository-jima** **kompanije** ili **korisnika** koji rade za tu github kompaniju.\
Možete koristiti **tool** [**Leakos**](https://github.com/carlospolop/Leakos) da **download-ujete** sve **public repos** jedne **organization** i njenih **developers**, a zatim automatski pokrenete [**gitleaks**](https://github.com/zricethezav/gitleaks) nad njima.

**Leakos** se takođe može koristiti za pokretanje **gitleaks** nad svim **text** sadržajem koji se nalazi na **URLs prosleđenim** alatu, jer i **web stranice ponekad sadrže secrets**.

#### Github Dorks

Pogledajte i ovu **stranicu** za potencijalne **github dorks** koje možete pretraživati i u organizaciji koju napadate:

{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

Ponekad će napadači ili samo zaposleni **objaviti sadržaj kompanije na paste sajtu**. On može, ali i ne mora da sadrži **osetljive informacije**, ali je veoma interesantno pretražiti ga.\
Možete koristiti tool [**Pastos**](https://github.com/carlospolop/Pastos) za istovremenu pretragu na više od 80 paste sajtova.

### Google Dorks

Stari, ali korisni google dorks uvek su upotrebljivi za pronalaženje **izloženih informacija koje ne bi trebalo da budu tamo**. Jedini problem je što [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) sadrži nekoliko **hiljada** mogućih upita koje ne možete ručno pokrenuti. Zato možete izabrati svojih omiljenih 10 ili koristiti **tool kao što je** [**Gorks**](https://github.com/carlospolop/Gorks) **da ih sve pokrenete**.

_Napomena: alati koji pokušavaju da koriste celu bazu preko standardnog Google browser-a nikada neće završiti, jer će vas Google veoma brzo blokirati._

### **Looking for vulnerabilities**

Ako pronađete **važeće leak-ovane** credential-e ili API tokene, to je veoma laka pobeda.

## Public Code Vulnerabilities

Ako otkrijete da kompanija ima **open-source code**, možete ga **analizirati** i tražiti **ranjivosti** u njemu.

**U zavisnosti od jezika**, možete koristiti različite **alate**:

{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

Postoje i besplatni servisi koji omogućavaju da **skenirate public repositories**, kao što je:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

**Većina ranjivosti** koje bug hunters pronalaze nalazi se unutar **web aplikacija**, pa bih u ovom trenutku želeo da govorim o **metodologiji testiranja web aplikacija**, a te [**informacije možete pronaći ovde**](../../network-services-pentesting/pentesting-web/index.html).

Takođe želim posebno da pomenem odeljak [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), jer, iako ne treba očekivati da pronađu veoma osetljive ranjivosti, korisni su za uključivanje u **workflows kako bi se dobile početne informacije o web-u.**

## Recapitulation

> Čestitamo! U ovom trenutku ste već obavili **sve osnovne enumeracije**. Da, osnovne su zato što se može obaviti još mnogo enumeracije (više trikova ćemo videti kasnije).

Dakle, već ste:

1. Pronašli sve **kompanije** unutar obuhvata
2. Pronašli sve **asset-e** koji pripadaju kompanijama (i obavili vuln scan ako je u obuhvatu)
3. Pronašli sve **domene** koji pripadaju kompanijama
4. Pronašli sve **subdomene** domena (da li postoji subdomain takeover?)
5. Pronašli sve **IP adrese** (sa i **bez CDN-ova**) unutar obuhvata.
6. Pronašli sve **web servere** i napravili njihov **screenshot** (da li postoji nešto neobično što vredi detaljnije pogledati?)
7. Pronašli sve **potencijalne public cloud asset-e** koji pripadaju kompaniji.
8. **Emails**, **credential leaks** i **secret leaks** koji bi vam veoma lako mogli doneti **veliku pobedu**.
9. Obavili **Pentesting nad svim pronađenim web sajtovima**

## **Full Recon Automatic Tools**

Postoji nekoliko alata koji će izvršiti deo predloženih radnji nad datim obuhvatom.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Prilično star i nije ažuriran

## References

- [1] Svi besplatni kursevi autora [**@Jhaddix**](https://twitter.com/Jhaddix), kao što je [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Bishop Fox – On Favicons: From Browser Icons to Attack Surface Intelligence](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)

{{#include ../../banners/hacktricks-training.md}}
