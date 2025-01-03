# Методологія зовнішнього розвідки

{{#include ../../banners/hacktricks-training.md}}

## Виявлення активів

> Вам сказали, що все, що належить якійсь компанії, знаходиться в межах обсягу, і ви хочете з'ясувати, що насправді належить цій компанії.

Мета цього етапу - отримати всі **компанії, що належать головній компанії** та всі **активи** цих компаній. Для цього ми будемо:

1. Знайти придбання головної компанії, це дасть нам компанії в межах обсягу.
2. Знайти ASN (якщо є) кожної компанії, це дасть нам діапазони IP, що належать кожній компанії.
3. Використати зворотні whois запити для пошуку інших записів (імен організацій, доменів...) пов'язаних з першим (це можна робити рекурсивно).
4. Використати інші техніки, такі як shodan `org` та `ssl` фільтри для пошуку інших активів (трик `ssl` можна робити рекурсивно).

### **Придбання**

По-перше, нам потрібно знати, які **інші компанії належать головній компанії**.\
Один з варіантів - відвідати [https://www.crunchbase.com/](https://www.crunchbase.com), **пошукати** **головну компанію** та **натиснути** на "**придбання**". Там ви побачите інші компанії, придбані головною.\
Інший варіант - відвідати сторінку **Вікіпедії** головної компанії та знайти **придбання**.

> Добре, на цьому етапі ви повинні знати всі компанії в межах обсягу. Давайте з'ясуємо, як знайти їх активи.

### **ASN**

Номер автономної системи (**ASN**) - це **унікальний номер**, призначений **автономній системі** (AS) **Управлінням Інтернету (IANA)**.\
**AS** складається з **блоків** **IP-адрес**, які мають чітко визначену політику доступу до зовнішніх мереж і адмініструються однією організацією, але можуть складатися з кількох операторів.

Цікаво дізнатися, чи **компанія призначила будь-який ASN**, щоб знайти її **діапазони IP.** Було б цікаво провести **тест на вразливість** проти всіх **хостів** в межах **обсягу** та **шукати домени** в цих IP.\
Ви можете **шукати** за назвою компанії, за **IP** або за **доменом** на [**https://bgp.he.net/**](https://bgp.he.net)**.**\
**Залежно від регіону компанії, ці посилання можуть бути корисними для збору додаткових даних:** [**AFRINIC**](https://www.afrinic.net) **(Африка),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Північна Америка),** [**APNIC**](https://www.apnic.net) **(Азія),** [**LACNIC**](https://www.lacnic.net) **(Латинська Америка),** [**RIPE NCC**](https://www.ripe.net) **(Європа). В будь-якому випадку, ймовірно, вся** корисна інформація **(діапазони IP та Whois)** вже з'являється за першим посиланням.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Також, [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s** підрахунок піддоменів автоматично агрегує та підсумовує ASN в кінці сканування.
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
Ви можете знайти IP-діапазони організації також за допомогою [http://asnlookup.com/](http://asnlookup.com) (він має безкоштовний API).\
Ви можете знайти IP та ASN домену, використовуючи [http://ipv4info.com/](http://ipv4info.com).

### **Шукання вразливостей**

На цьому етапі ми знаємо **всі активи в межах обсягу**, тому, якщо вам дозволено, ви можете запустити деякі **сканери вразливостей** (Nessus, OpenVAS) на всіх хостах.\
Також ви можете запустити деякі [**сканування портів**](../pentesting-network/#discovering-hosts-from-the-outside) **або використовувати сервіси, такі як** shodan **для знаходження** відкритих портів **і в залежності від того, що ви знайдете, вам слід** ознайомитися з цією книгою, щоб дізнатися, як провести пентест кількох можливих сервісів.\
**Також варто згадати, що ви можете підготувати деякі** списки стандартних імен користувачів **та** паролів **і спробувати** брутфорсити сервіси за допомогою [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Домені

> Ми знаємо всі компанії в межах обсягу та їх активи, час знайти домени в межах обсягу.

_Зверніть увагу, що в наступних запропонованих техніках ви також можете знайти піддомени, і цю інформацію не слід недооцінювати._

Перш за все, вам слід шукати **основний домен**(и) кожної компанії. Наприклад, для _Tesla Inc._ це буде _tesla.com_.

### **Зворотний DNS**

Оскільки ви знайшли всі IP-діапазони доменів, ви можете спробувати виконати **зворотні DNS-запити** на цих **IP, щоб знайти більше доменів в межах обсягу**. Спробуйте використовувати деякий DNS-сервер жертви або деякий відомий DNS-сервер (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Для цього адміністратор має вручну увімкнути PTR.\
Ви також можете використовувати онлайн-інструмент для цієї інформації: [http://ptrarchive.com/](http://ptrarchive.com)

### **Зворотний Whois (loop)**

У **whois** ви можете знайти багато цікавої **інформації**, такої як **назва організації**, **адреса**, **електронні адреси**, номери телефонів... Але що ще цікавіше, так це те, що ви можете знайти **більше активів, пов'язаних з компанією**, якщо ви виконаєте **зворотні whois запити за будь-яким з цих полів** (наприклад, інші реєстрації whois, де з'являється та сама електронна адреса).\
Ви можете використовувати онлайн-інструменти, такі як:

- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Безкоштовно**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Безкоштовно**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Безкоштовно**
- [https://www.whoxy.com/](https://www.whoxy.com) - **Безкоштовно** веб, не безкоштовний API.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Не безкоштовно
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Не безкоштовно (лише **100 безкоштовних** запитів)
- [https://www.domainiq.com/](https://www.domainiq.com) - Не безкоштовно

Ви можете автоматизувати це завдання, використовуючи [**DomLink** ](https://github.com/vysecurity/DomLink)(потрібен ключ API whoxy).\
Ви також можете виконати деяке автоматичне виявлення зворотного whois за допомогою [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Зверніть увагу, що ви можете використовувати цю техніку, щоб виявити більше доменних імен щоразу, коли ви знаходите новий домен.**

### **Трекери**

Якщо ви знайдете **той самий ID того самого трекера** на 2 різних сторінках, ви можете припустити, що **обидві сторінки** **керуються однією командою**.\
Наприклад, якщо ви бачите той самий **ID Google Analytics** або той самий **ID Adsense** на кількох сторінках.

Є кілька сторінок і інструментів, які дозволяють вам шукати за цими трекерами та іншими:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)

### **Favicon**

Чи знали ви, що ми можемо знайти пов'язані домени та піддомени нашої цілі, шукаючи той самий хеш значка favicon? Це саме те, що робить інструмент [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py), створений [@m4ll0k2](https://twitter.com/m4ll0k2). Ось як його використовувати:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - виявлення доменів з однаковим хешем значка фавікону](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Простими словами, favihash дозволить нам виявити домени, які мають однаковий хеш значка фавікону з нашим об'єктом.

Більше того, ви також можете шукати технології, використовуючи хеш значка фавікону, як пояснено в [**цьому блозі**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139). Це означає, що якщо ви знаєте **хеш значка фавікону вразливої версії веб-технології**, ви можете шукати в shodan і **знайти більше вразливих місць**:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
Ось як ви можете **обчислити хеш фавікону** веб-сайту:
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
### **Авторське право / Унікальний рядок**

Шукайте на веб-сторінках **рядки, які можуть бути спільними для різних веб-сайтів в одній організації**. **Рядок авторського права** може бути хорошим прикладом. Потім шукайте цей рядок у **google**, в інших **браузерах** або навіть у **shodan**: `shodan search http.html:"Copyright string"`

### **Час CRT**

Зазвичай є завдання cron, таке як
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
щоб оновити всі сертифікати доменів на сервері. Це означає, що навіть якщо CA, що використовується для цього, не встановлює час, коли він був згенерований, у часі дії, можливо **знайти домени, що належать одній компанії, у журналах прозорості сертифікатів**.\
Перегляньте цей [**звіт для отримання додаткової інформації**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

### Інформація про Mail DMARC

Ви можете використовувати веб-сайт, такий як [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com), або інструмент, такий як [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains), щоб знайти **домени та піддомени, що мають однакову інформацію DMARC**.

### **Пасивне захоплення**

Здається, що звичайно люди призначають піддомени IP-адресам, які належать постачальникам хмарних послуг, і в якийсь момент **втрачають цю IP-адресу, але забувають видалити запис DNS**. Тому, просто **створивши віртуальну машину** у хмарі (такій як Digital Ocean), ви фактично **захоплюєте деякі піддомени**.

[**Цей пост**](https://kmsec.uk/blog/passive-takeover/) пояснює історію про це і пропонує скрипт, який **створює віртуальну машину в DigitalOcean**, **отримує** **IPv4** нової машини і **шукає в Virustotal записи піддоменів**, що вказують на неї.

### **Інші способи**

**Зверніть увагу, що ви можете використовувати цю техніку, щоб виявити більше доменних імен щоразу, коли ви знаходите новий домен.**

**Shodan**

Як ви вже знаєте, назву організації, що володіє IP-простором. Ви можете шукати за цими даними в shodan, використовуючи: `org:"Tesla, Inc."` Перевірте знайдені хости на наявність нових несподіваних доменів у сертифікаті TLS.

Ви можете отримати **TLS сертифікат** основної веб-сторінки, отримати **назву організації** і потім шукати цю назву в **TLS сертифікатах** всіх веб-сторінок, відомих **shodan**, з фільтром: `ssl:"Tesla Motors"` або використати інструмент, такий як [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder**](https://github.com/tomnomnom/assetfinder) - це інструмент, який шукає **домени, пов'язані** з основним доменом та **піддоменами** з них, досить вражаюче.

### **Шукання вразливостей**

Перевірте наявність деякого [захоплення домену](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Можливо, якась компанія **використовує якийсь домен**, але вони **втратили право власності**. Просто зареєструйте його (якщо достатньо дешевий) і дайте знати компанії.

Якщо ви знайдете будь-який **домен з IP, відмінним** від тих, які ви вже знайшли під час виявлення активів, вам слід виконати **базове сканування вразливостей** (використовуючи Nessus або OpenVAS) і деяке [**сканування портів**](../pentesting-network/#discovering-hosts-from-the-outside) з **nmap/masscan/shodan**. Залежно від того, які сервіси працюють, ви можете знайти в **цьому посібнику деякі хитрощі для "атаки" на них**.\
&#xNAN;_&#x4E;ote, що іноді домен розміщений на IP, який не контролюється клієнтом, тому він не входить до сфери дії, будьте обережні._

## Піддомени

> Ми знаємо всі компанії в межах сфери дії, всі активи кожної компанії та всі домени, пов'язані з компаніями.

Час знайти всі можливі піддомени кожного знайденого домену.

> [!TIP]
> Зверніть увагу, що деякі інструменти та техніки для знаходження доменів також можуть допомогти знайти піддомени

### **DNS**

Спробуємо отримати **піддомени** з **DNS** записів. Ми також повинні спробувати **Zone Transfer** (якщо вразливий, ви повинні про це повідомити).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Найшвидший спосіб отримати багато піддоменів - це пошук у зовнішніх джерелах. Найбільш використовувані **інструменти** такі:

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
Є **інші цікаві інструменти/API**, які, навіть якщо не спеціалізуються безпосередньо на знаходженні піддоменів, можуть бути корисними для їх знаходження, такі як:

- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Використовує API [https://sonar.omnisint.io](https://sonar.omnisint.io) для отримання піддоменів
```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```
- [**JLDC безкоштовне API**](https://jldc.me/anubis/subdomains/google.com)
```bash
curl https://jldc.me/anubis/subdomains/tesla.com | jq -r ".[]"
```
- [**RapidDNS**](https://rapiddns.io) безкоштовне API
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
- [**gau**](https://github.com/lc/gau)**:** отримує відомі URL з Open Threat Exchange AlienVault, Wayback Machine та Common Crawl для будь-якого заданого домену.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Вони сканують веб, шукаючи JS файли та витягують піддомени звідти.
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
- [**securitytrails.com**](https://securitytrails.com/) має безкоштовний API для пошуку піддоменів та історії IP
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Цей проект пропонує **безкоштовно всі піддомени, пов'язані з програмами bug-bounty**. Ви також можете отримати доступ до цих даних, використовуючи [chaospy](https://github.com/dr-0x0x/chaospy) або навіть отримати доступ до обсягу, використаного цим проектом [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Ви можете знайти **порівняння** багатьох з цих інструментів тут: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Спробуємо знайти нові **піддомени**, брутфорсуючи DNS-сервери, використовуючи можливі імена піддоменів.

Для цієї дії вам знадобляться деякі **загальні списки слів піддоменів, такі як**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

А також IP-адреси хороших DNS-резолверів. Щоб згенерувати список надійних DNS-резолверів, ви можете завантажити резолвери з [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) і використовувати [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) для їх фільтрації. Або ви можете використовувати: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Найбільш рекомендовані інструменти для брутфорсу DNS:

- [**massdns**](https://github.com/blechschmidt/massdns): Це був перший інструмент, який виконував ефективний брутфорс DNS. Він дуже швидкий, однак схильний до хибнопозитивних результатів.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Я думаю, що цей інструмент використовує лише 1 резолвер.
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) є обгорткою навколо `massdns`, написаною на go, яка дозволяє вам перераховувати дійсні піддомени, використовуючи активний брутфорс, а також вирішувати піддомени з обробкою диких символів та простим підтримкою вводу-виводу.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): Він також використовує `massdns`.
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) використовує asyncio для асинхронного брутфорсу доменних імен.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Другий раунд брутфорсу DNS

Після того, як ви знайшли піддомени, використовуючи відкриті джерела та брутфорс, ви можете згенерувати варіації знайдених піддоменів, щоб спробувати знайти ще більше. Для цієї мети корисні кілька інструментів:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Задані домени та піддомени генерують перестановки.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): Задані домени та піддомени генерують перестановки.
- Ви можете отримати перестановки goaltdns **wordlist** [**тут**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** Дано домени та піддомени, генерує перестановки. Якщо файл перестановок не вказано, gotator використає свій власний.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Окрім генерації пермутацій піддоменів, він також може спробувати їх розв'язати (але краще використовувати попередньо згадані інструменти).
- Ви можете отримати пермутації altdns **wordlist** [**тут**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Ще один інструмент для виконання перестановок, мутацій та змін піддоменів. Цей інструмент буде брутфорсити результат (він не підтримує dns wild card).
- Ви можете отримати список слів для перестановок dmut [**тут**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** На основі домену він **генерує нові потенційні імена піддоменів** на основі вказаних шаблонів, щоб спробувати виявити більше піддоменів.

#### Генерація розумних перестановок

- [**regulator**](https://github.com/cramppet/regulator): Для отримання додаткової інформації прочитайте цей [**пост**](https://cramppet.github.io/regulator/index.html), але він в основному отримає **основні частини** з **виявлених піддоменів** і змішає їх, щоб знайти більше піддоменів.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ є фуззером для брутфорсу піддоменів, поєднаним з надзвичайно простим, але ефективним алгоритмом, що керується відповідями DNS. Він використовує наданий набір вхідних даних, таких як спеціально підібраний список слів або історичні записи DNS/TLS, щоб точно синтезувати більше відповідних доменних імен і розширювати їх ще далі в циклі на основі інформації, зібраної під час сканування DNS.
```
echo www | subzuf facebook.com
```
### **Процес виявлення піддоменів**

Перегляньте цей блог-пост, який я написав про те, як **автоматизувати виявлення піддоменів** з домену, використовуючи **Trickest workflows**, щоб мені не потрібно було вручну запускати купу інструментів на моєму комп'ютері:

{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}

{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Віртуальні хости**

Якщо ви знайшли IP-адресу, що містить **одну або кілька веб-сторінок**, що належать піддоменам, ви можете спробувати **знайти інші піддомени з веб-сайтами на цьому IP**, шукаючи в **OSINT джерелах** домени на IP або **брутфорсити доменні імена VHost на цьому IP**.

#### OSINT

Ви можете знайти деякі **VHosts на IP, використовуючи** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **або інші API**.

**Брутфорс**

Якщо ви підозрюєте, що деякий піддомен може бути прихований на веб-сервері, ви можете спробувати його брутфорсити:
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
> З цією технікою ви навіть можете отримати доступ до внутрішніх/прихованих кінцевих точок.

### **CORS Brute Force**

Іноді ви можете знайти сторінки, які повертають лише заголовок _**Access-Control-Allow-Origin**_, коли в заголовку _**Origin**_ встановлено дійсний домен/піддомен. У цих сценаріях ви можете зловживати цією поведінкою, щоб **виявити** нові **піддомени**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

Під час пошуку **субдоменів** звертайте увагу, чи вказують вони на будь-який тип **бакету**, і в такому випадку [**перевірте дозволи**](../../network-services-pentesting/pentesting-web/buckets/)**.**\
Також, оскільки на цьому етапі ви будете знати всі домени в межах обсягу, спробуйте [**зламати можливі імена бакетів і перевірити дозволи**](../../network-services-pentesting/pentesting-web/buckets/).

### **Моніторинг**

Ви можете **моніторити**, чи створюються **нові субдомени** домену, моніторячи **Журнали прозорості сертифікатів**, що робить [**sublert**](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Пошук вразливостей**

Перевірте на можливі [**взяття субдоменів під контроль**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Якщо **субдомен** вказує на якийсь **S3 бакет**, [**перевірте дозволи**](../../network-services-pentesting/pentesting-web/buckets/).

Якщо ви знайдете будь-який **субдомен з IP, відмінним** від тих, що ви вже знайшли під час виявлення активів, вам слід виконати **базове сканування вразливостей** (використовуючи Nessus або OpenVAS) і деяке [**сканування портів**](../pentesting-network/#discovering-hosts-from-the-outside) з **nmap/masscan/shodan**. Залежно від того, які сервіси працюють, ви можете знайти в **цьому посібнику деякі хитрощі для "атаки" на них**.\
&#xNAN;_&#x4E;ote that sometimes the subdomain is hosted inside an IP that is not controlled by the client, so it's not in the scope, be careful._

## IPs

На початкових етапах ви могли **знайти деякі діапазони IP, домени та субдомени**.\
Час **зібрати всі IP з цих діапазонів** та для **доменів/субдоменів (DNS запити).**

Використовуючи сервіси з наступних **безкоштовних API**, ви також можете знайти **попередні IP, які використовувалися доменами та субдоменами**. Ці IP можуть все ще належати клієнту (і можуть дозволити вам знайти [**обхідні шляхи CloudFlare**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

- [**https://securitytrails.com/**](https://securitytrails.com/)

Ви також можете перевірити домени, що вказують на конкретну IP-адресу, використовуючи інструмент [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Пошук вразливостей**

**Скануйте порти всіх IP, які не належать CDN** (оскільки ви, ймовірно, не знайдете нічого цікавого там). У виявлених запущених сервісах ви можете **знайти вразливості**.

**Знайдіть** [**посібник**](../pentesting-network/) **про те, як сканувати хости.**

## Полювання на веб-сервери

> Ми знайшли всі компанії та їх активи, і ми знаємо діапазони IP, домени та субдомени в межах обсягу. Час шукати веб-сервери.

На попередніх етапах ви, ймовірно, вже виконали деяке **розвідку виявлених IP та доменів**, тому ви могли **вже знайти всі можливі веб-сервери**. Однак, якщо ви цього не зробили, ми зараз розглянемо деякі **швидкі хитрощі для пошуку веб-серверів** в межах обсягу.

Зверніть увагу, що це буде **орієнтовано на виявлення веб-додатків**, тому вам слід **виконати сканування вразливостей** та **сканування портів** також (**якщо дозволено** обсягом).

**Швидкий метод** для виявлення **відкритих портів**, пов'язаних з **веб** серверами, використовуючи [**masscan** можна знайти тут](../pentesting-network/#http-port-discovery).\
Ще один зручний інструмент для пошуку веб-серверів - це [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) та [**httpx**](https://github.com/projectdiscovery/httpx). Ви просто передаєте список доменів, і він спробує підключитися до порту 80 (http) та 443 (https). Додатково, ви можете вказати спробувати інші порти:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Скриншоти**

Тепер, коли ви виявили **всі веб-сервери**, що знаходяться в межах (серед **IP** компанії та всіх **доменів** і **піддоменів**), ви, напевно, **не знаєте, з чого почати**. Тож давайте спростимо і просто почнемо робити скриншоти всіх з них. Просто **подивившись** на **головну сторінку**, ви можете знайти **незвичайні** кінцеві точки, які більш **схильні** бути **вразливими**.

Для реалізації запропонованої ідеї ви можете використовувати [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) або [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Більше того, ви можете використовувати [**eyeballer**](https://github.com/BishopFox/eyeballer), щоб переглянути всі **скриншоти** і вказати, **що, ймовірно, міститиме вразливості**, а що ні.

## Публічні хмарні активи

Щоб знайти потенційні хмарні активи, що належать компанії, вам слід **почати з переліку ключових слів, які ідентифікують цю компанію**. Наприклад, для криптокомпанії ви можете використовувати такі слова: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Вам також знадобляться словники **поширених слів, що використовуються в бакетах**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Потім, з цими словами, ви повинні згенерувати **пермутації** (перевірте [**Другий раунд DNS брутфорсу**](./#second-dns-bruteforce-round) для отримання додаткової інформації).

З отриманими словниками ви можете використовувати такі інструменти, як [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **або** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Пам'ятайте, що, шукаючи хмарні активи, вам слід **шукати більше, ніж просто бакети в AWS**.

### **Шукання вразливостей**

Якщо ви знайдете такі речі, як **відкриті бакети або хмарні функції**, вам слід **доступитися до них** і спробувати подивитися, що вони вам пропонують і чи можете ви їх зловживати.

## Електронні листи

З **доменами** та **піддоменами** в межах ви, по суті, маєте все, що вам **потрібно для початку пошуку електронних листів**. Ось **API** та **інструменти**, які найкраще працювали для мене, щоб знайти електронні листи компанії:

- [**theHarvester**](https://github.com/laramies/theHarvester) - з API
- API [**https://hunter.io/**](https://hunter.io/) (безкоштовна версія)
- API [**https://app.snov.io/**](https://app.snov.io/) (безкоштовна версія)
- API [**https://minelead.io/**](https://minelead.io/) (безкоштовна версія)

### **Шукання вразливостей**

Електронні листи знадобляться пізніше для **брутфорсу веб-логінів та авторизаційних сервісів** (таких як SSH). Крім того, вони потрібні для **фішингів**. Більше того, ці API нададуть вам ще більше **інформації про особу**, що стоїть за електронною поштою, що корисно для фішингової кампанії.

## Витоки облікових даних

З **доменами,** **піддоменами** та **електронними листами** ви можете почати шукати облікові дані, які були витікали в минулому і належать цим електронним листам:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Шукання вразливостей**

Якщо ви знайдете **дійсні витіклі** облікові дані, це дуже легка перемога.

## Витоки секретів

Витоки облікових даних пов'язані з злом компаній, де **конфіденційна інформація була витікала та продавалася**. Однак компанії можуть бути піддані **іншим витокам**, інформація про які не міститься в цих базах даних:

### Витоки з Github

Облікові дані та API можуть бути витікали в **публічних репозиторіях** **компанії** або **користувачів**, які працюють на цю компанію в github.\
Ви можете використовувати **інструмент** [**Leakos**](https://github.com/carlospolop/Leakos), щоб **завантажити** всі **публічні репозиторії** **організації** та її **розробників** та автоматично запустити [**gitleaks**](https://github.com/zricethezav/gitleaks) на них.

**Leakos** також можна використовувати для запуску **gitleaks** проти всього **тексту**, наданого **URL-адресами**, оскільки іноді **веб-сторінки також містять секрети**.

#### Dorks Github

Перевірте також цю **сторінку** на предмет потенційних **github dorks**, які ви також могли б шукати в організації, яку ви атакуєте:

{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Витоки з Paste

Іноді зловмисники або просто працівники **публікують вміст компанії на сайті для вставок**. Це може або не може містити **конфіденційну інформацію**, але це дуже цікаво шукати.\
Ви можете використовувати інструмент [**Pastos**](https://github.com/carlospolop/Pastos), щоб шукати більш ніж на 80 сайтах для вставок одночасно.

### Dorks Google

Старі, але золоті dorks Google завжди корисні для знаходження **викритої інформації, якої не повинно бути**. Єдина проблема в тому, що [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) містить кілька **тисяч** можливих запитів, які ви не можете виконати вручну. Тож ви можете взяти свої улюблені 10 або ви можете використовувати **інструмент, такий як** [**Gorks**](https://github.com/carlospolop/Gorks) **для їх виконання**.

_Зверніть увагу, що інструменти, які намагаються виконати всю базу даних, використовуючи звичайний браузер Google, ніколи не закінчаться, оскільки Google заблокує вас дуже-дуже швидко._

### **Шукання вразливостей**

Якщо ви знайдете **дійсні витіклі** облікові дані або токени API, це дуже легка перемога.

## Публічні вразливості коду

Якщо ви виявили, що компанія має **відкритий код**, ви можете **проаналізувати** його та шукати **вразливості** в ньому.

**Залежно від мови** існують різні **інструменти**, які ви можете використовувати:

{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

Існують також безкоштовні сервіси, які дозволяють вам **сканувати публічні репозиторії**, такі як:

- [**Snyk**](https://app.snyk.io/)

## [**Методологія пентестингу веб**](../../network-services-pentesting/pentesting-web/)

**Більшість вразливостей**, виявлених мисливцями за помилками, знаходяться всередині **веб-додатків**, тому на цьому етапі я хотів би поговорити про **методологію тестування веб-додатків**, і ви можете [**знайти цю інформацію тут**](../../network-services-pentesting/pentesting-web/).

Я також хочу зробити особливе зауваження до розділу [**Веб автоматизовані сканери відкритих джерел**](../../network-services-pentesting/pentesting-web/#automatic-scanners), оскільки, якщо ви не повинні очікувати, що вони знайдуть вам дуже чутливі вразливості, вони стануть у нагоді для реалізації їх у **робочих процесах, щоб отримати деяку початкову веб-інформацію.**

## Резюме

> Вітаємо! На цьому етапі ви вже виконали **всі основні перерахування**. Так, це базове, оскільки можна виконати ще багато перерахувань (пізніше побачимо більше трюків).

Отже, ви вже:

1. Знайшли всі **компанії** в межах
2. Знайшли всі **активи**, що належать компаніям (і виконали деяке сканування вразливостей, якщо це в межах)
3. Знайшли всі **домени**, що належать компаніям
4. Знайшли всі **піддомени** доменів (чи є якісь захоплення піддоменів?)
5. Знайшли всі **IP** (з і **не з CDN**) в межах.
6. Знайшли всі **веб-сервери** та зробили **скриншот** з них (чи є щось незвичайне, що варто детальніше розглянути?)
7. Знайшли всі **потенційні публічні хмарні активи**, що належать компанії.
8. **Електронні листи**, **витоки облікових даних** та **витоки секретів**, які можуть дати вам **велику перемогу дуже легко**.
9. **Пентестинг всіх веб-сайтів, які ви знайшли**

## **Повні автоматизовані інструменти розвідки**

Існує кілька інструментів, які виконуватимуть частину запропонованих дій проти заданого обсягу.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Трохи старий і не оновлюється

## **Посилання**

- Всі безкоштовні курси [**@Jhaddix**](https://twitter.com/Jhaddix), такі як [**Методологія мисливця за помилками v4.0 - Розвідка**](https://www.youtube.com/watch?v=p4JgIu1mceI)

{{#include ../../banners/hacktricks-training.md}}
