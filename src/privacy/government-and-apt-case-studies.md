# Studije slučaja vlada i APT grupa

{{#include ../banners/hacktricks-training.md}}

Ovi javno poznati slučajevi pokazuju kako se različite privacy tehnike kombinuju u stvarnim operacijama. Oznake atribucije su one koje su koristili navedeni istražitelji ili vlade; sama IP adresa, preklapanje alata ili geopolitička podudarnost nisu konačan dokaz atribucije.

## APT28: Wi-Fi pristup sa udaljenog najbližeg suseda

**Javni nalaz.** Volexity je upad iz 2022. pripisao grupi GruesomeLarch/APT28. Nakon što je pristup Internetu pomoću validiranog credential-a zaustavljen MFA mehanizmom, akter je kompromitovao organizacije u blizini mete i sa obližnjeg dual-homed hosta pristupio enterprise Wi-Fi mreži mete. Wi-Fi putanja je prihvatila credential bez MFA mehanizma koji je bio obavezan spolja.<sup>[[1]](#references)</sup>

**Efekat na privatnost.** Konačni pristup je poticao iz fizičkog dometa radio-signala, a posredne organizacije bile su žrtve. Operacija je izbegla putovanje i učinila da konvencionalna IP geolokacija pokaže na suseda.

**Šta je otkrilo operaciju.** Upozorenje mete, istraga hostova/mreže, aktivnost credential-a, topologija interfejsa i fizička blizina morali su da se analiziraju kao jedna celina. Anomalija nije bila samo nova IP adresa; radilo se o legitimnom identitetu koji je pristupao kroz neuobičajen Wi-Fi/device kontekst dok su obližnji sistemi bili kompromitovani.

**Odbrambena lekcija.** Primeni pristup Wi-Fi mreži zasnovan na certificate/device autentikaciji, koreliši RADIUS sa NAC/MDM i fizičkim kontekstom i istražuj susednu infrastrukturu umesto pretpostavke da je poslednji hop operator.

## APT28: kriminalna Moobot infrastruktura koju je GRU prenamenio

**Javni nalaz.** U februaru 2024. godine, US Department of Justice opisao je botnet od nekoliko stotina Ubiquiti EdgeOS rutera. Kriminalni akteri su instalirali Moobot na rutere koji su zadržali poznate podrazumevane administratorske credential-e; GRU Unit 26165 je zatim dodao skripte i fajlove, pretvarajući postojeći kriminalni botnet u espionage platformu korišćenu za spearphishing i krađu credential-a.<sup>[[2]](#references)</sup>

**Efekat na privatnost.** GRU nije sam izgradio svu infrastrukturu. Pozajmljivanje već kompromitovane flote postavilo je adrese nepovezanih domaćinstava i malih kancelarija između aktera i meta, pomešalo državnu aktivnost sa kriminalnom aktivnošću i smanjilo artefakte specifične za registraciju aktera.

**Šta je otkrilo operaciju.** Fajlovi rutera, ponašanje malware-a i routing informacije koje nisu sadržale sadržaj podržali su istragu. Disruption je privremeno promenio firewall pravila i uklonio maliciozne fajlove, dok je DOJ upozorio da nepromenjeni podrazumevani credential-i mogu omogućiti ponovnu infekciju.

**Odbrambena lekcija.** Zamenite rutere kojima je prestala podrška, uklonite administraciju izloženu Internetu, promenite podrazumevane vrednosti, instalirajte zakrpe, prikupljajte konfiguracione/flow podatke edge uređaja i tražite ponašanje karakteristično za flotu. „Residential US IP“ nije dokaz da je operator iz SAD.

## Volt Typhoon: KV Botnet uz living off the land

**Javni nalaz.** DOJ i zajednički CISA advisory opisali su PRC-sponsored Volt Typhoon koji koristi KV Botnet, prvenstveno kompromitovane Cisco i NETGEAR SOHO rutere kojima je istekao životni vek, kako bi prikrio PRC poreklo aktivnosti usmerenih na kritičnu infrastrukturu. Unutar žrtava, akter je preferirao validne naloge i ugrađene administration alate; agencije su prijavile da je pristup u nekim okruženjima trajao najmanje pet godina.<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>
```text
PRC operator -> encrypted KV path -> compromised SOHO exit -> edge service
|
valid accounts + native tools
```
**Efekat na privatnost.** Putanja nalik ORB-u sakrila je poreklo, dok je living-off-the-land smanjio broj novih binarnih datoteka i mogućnosti za detekciju potpisima nakon pristupa. Mrežno i endpoint prikrivanje međusobno su se pojačavali.

**Šta ga je razotkrilo.** Struktura rutera/kontrolera, sudski odobreno tehničko prikupljanje, ponavljajuća aktivnost i analiza među žrtvama bili su važniji od jednog IOC-a. Ponovno pokretanje rutera uklonilo je volatilni KV malware u opisanim slučajevima, ali nije otklonilo osnovnu izloženost uređaja zbog isteka životnog veka.

**Odbrambena lekcija.** Zamenite edge uređaje kojima je istekao životni vek, centralizujte authentication i network-device logove, napravite baseline ponašanja administratora, ograničite outbound connectivity i tražite sekvence ponašanja kroz identity, endpoint i network slojeve.

## China-nexus ORB mreže: infrastruktura kao usluga

**Javni nalaz.** Mandiant je opisao ekosistem ORB mreža koje koristi više China-nexus espionage aktera. Provisioned mreže koristile su iznajmljene VPS čvorove; non-provisioned mreže koristile su kompromitovane IoT uređaje i rutere; hybrid mreže kombinovale su ih. ORB3/SPACEHOP podržavao je aktivnost povezanu sa APT5/APT15. ORB2/FLORAHOX kombinovao je administration server, iznajmljene servere, prilagođeni Tor layer i kompromitovane Cisco, ASUS i DrayTek uređaje. Mandiant je procenio da su neke mreže bile nezavisno administrirane i iznajmljivane većem broju APT aktera.<sup>[[5]](#references)</sup>

**Efekat na privatnost.** Infrastruktura je postala servisna granica. Jedan operator mogao je da dobije geografske/rezidencijalne izlaze bez održavanja flote žrtava, dok je veliki broj korisnika koji je deli otežavao jednostavno mapiranje aktera na IP. Brza promena flote ubrzala je „izumiranje IOC-a“.

**Šta ga je razotkrilo.** Topologija mreže, klonirane server images, portovi/servisi, odnosi sa kontrolerima, router implants i obrasci životnog ciklusa ostali su pogodni za klasterizaciju. Mandiant je izvestio da su neki node IP-jevi ostajali u ORB-u svega 31 dan.

**Odbrambena lekcija.** Pratite ORB kao entitet koji se menja: uloge čvorova, service fingerprints, upstream odnose, scan ponašanje i ritam rotacije. Isticanje IP indikatora treba da ažurira klaster, a ne da izbriše slučaj.

## PRC globalni espionage sistem: ruteri, trusted linkovi i traffic mirroring

**Javni nalaz.** Multinacionalni advisory iz 2025. opisao je aktivnost koja se preklapa sa komercijalnim nazivima za reporting, uključujući Salt Typhoon, OPERATOR PANDA, RedMike, UNC5807 i GhostEmperor. Agencije su izvestile o iznajmljenim VPS-ovima i kompromitovanim intermediate ruterima korišćenim za pristup telecommunications i network providerima. Akteri su se kretali kroz trusted provider/customer linkove, menjali rute, pravili GRE/IPsec tunele, koristili device containers i omogućavali SPAN/RSPAN/ERSPAN ili native packet capture za prikupljanje authentication i customer saobraćaja.<sup>[[13]](#references)</sup>

**Efekat na privatnost.** Kompromitovani ruter istovremeno je relay, observation point i trusted network participant. Privatne interkonekcije mogu zaobići kontrole projektovane oko javnog Interneta, dok traffic mirroring prikuplja credentials bez postavljanja endpoint agenta.

**Šta ga razotkriva.** Configuration diffovi, neočekivana SNMP/SSH/web administracija, nove static routes/tunnels, mirror sessions, Guest Shell containers, PCAP fajlovi, promene TACACS+/RADIUS odredišta i onemogućeno logging. Advisory naglašava da neki intermediate ruteri nisu bili deo prethodno imenovanog javnog botneta, pa odsustvo poznatih ORB indikatora nije oslobađalo od sumnje.

**Odbrambena lekcija.** Koristite out-of-band administraciju, centralizovane configuration/authentication logove, provere integriteta signed image i runtime-a, ograničenja egress-a management interfejsa i alerts za promene route/mirror/tunnel/AAA konfiguracije. Obuhvatite sumnjivi kompromis kroz trusted peers pre eviction-a.

## UNC3886 RedPenguin: pasivni backdoors na ISP ruterima

**Javni nalaz.** Mandiant je pripisao UNC3886 prilagođene backdoors izvedene iz TINYSHELL-a na Juniper MX ruterima kojima je istekao životni vek. Skup je uključivao active i passive implants, nazive koji oponašaju legitimne daemons, ponašanje za onemogućavanje logova, process injection u trusted process, SOCKS proxy mogućnost i infrastrukturu procenjenu kao ORB staging nodes. Pasivne varijante pregledale su pakete preko `libpcap` i aktivirale se tek nakon magic pattern-a; jedna je mogla da pređe na active callback naveden u trigger-u.<sup>[[14]](#references)</sup>

**Efekat na privatnost.** Pasivni implant nema periodični beacon koji bi ga otkrio. Deli portove/saobraćaj sa stvarnim network appliance-om, kratko se aktivira i može da relay-uje kroz ORB umesto da se direktno poveže sa krajnjim kontrolerom.

**Šta ga razotkriva.** Memory analysis, razlike između koda na disku i koda koji se izvršava, neočekivani packet-capture filteri/socket ponašanje, imena procesa/fajlova koja samo približno oponašaju legitimne daemons, administracija preko terminal servera, nedostajući logovi i dvostepeni odnos između staging nodes i backend kontrolera.

**Odbrambena lekcija.** Pribavite memory i filesystem/configuration dokaze, uporedite procese/module sa poznatom ispravnom image datotekom, nadzirite packet-capture/socket-filter upotrebu, zaštitite management terminal servers i zamenite network hardware kojem je istekao životni vek. Čist outbound-beacon hunt nije potvrda da je sistem bezbedan.

## APT29: Tor domain fronting

**Javni nalaz.** MITRE beleži da je APT29 koristio `meek` Tor pluggable transport za domain-front C2 saobraćaja. Spoljašnje TLS ime izgledalo je kao dozvoljeni domain hostovan na CDN-u, dok je unutrašnji HTTP host birao stvarnu rutu.<sup>[[6]](#references)</sup>

**Efekat na privatnost.** Observer koji filtrira saobraćaj mogao je da vidi uobičajeni front/CDN umesto unutrašnjeg odredišta, a njegovo blokiranje nosilo je rizik od collateral damage-a.

**Šta ga razotkriva.** CDN može da uoči neusaglašenost rutiranja, a defender sa endpoint ili lawful TLS visibility može da koreliše proces, authority, trajanje konekcije, obrazac bajtova i kasniju aktivnost. Promene policy-ja provajdera mogu onemogućiti tehniku.

**Odbrambena lekcija.** Ne oslanjajte se samo na SNI allowlisting. Primenite application-aware egress, uporedite TLS i HTTP identitete tamo gde su vidljivi i povežite network događaj sa procesom koji ga je pokrenuo.

## APT41 i drugi dead-drop resolvers

**Javni nalaz.** MITRE dokumentuje da je APT41 koristio legitimne sajtove, uključujući GitHub, Pastebin, Microsoft TechNet, Cloudflare i community forums, za objavljivanje ili preuzimanje C2 informacija. Drugi state-linked alati koristili su posts, documents i social media na sličan način.<sup>[[7]](#references)</sup>

**Efekat na privatnost.** Binarna datoteka sadrži legitimni service/object umesto stabilne C2 adrese. Objekat može da se menja radi rotacije infrastrukture, a početni zahtev se stapa sa uobičajenim TLS saobraćajem.

**Šta ga razotkriva.** Objekat ili account identifier je stabilan; retki procesi ga iznova preuzimaju; sadržaj se dekodira; nakon toga sledi druga outbound konekcija. Provider account i API zapisi mogu povezati objavljivanje sa operatorom.

**Odbrambena lekcija.** Sačuvajte pune proxy paths/object IDs i endpoint process lineage. Događaj na nivou domena, kao što je „povezano sa GitHub-om“, previše je grub.

## Turla: satellite-address C2

**Javni nalaz.** Kaspersky je izvestio da je Turla zloupotrebljavao nešifrovane downstream broadcasts starijih one-way DVB-S Internet servisa. Operator unutar satelitske zone mogao je da izabere adresu legitimnog pretplatnika i prima odgovore koji se emituju toj adresi, zbog čega je izgledalo da je C2 hostovan iza satellite provajdera u drugom regionu.<sup>[[8]](#references)</sup>

**Efekat na privatnost.** Prividna server adresa nije identifikovala primaoca, a uobičajeni postupci zaplene hostinga/WHOIS-a bili su manje korisni.

**Šta ga razotkriva.** Akteru je i dalje bio potreban outbound request path, rutiranje je bilo asimetrično, legitimni pretplatnik nije inicirao C2 razmenu, a RF/provider istraga mogla je da suzi receiving footprint.

**Odbrambena lekcija.** Geolokaciju tretirajte kao jednu hipotezu. Proverite path symmetry, RTT, vlasništvo nad rutiranjem i da li je navodni endpoint zaista mogao da proizvede uočeni service.

## Cyclops Blink i VPNFilter: edge uređaji kao trajni cover

**Javni nalaz.** Advisory NCSC/CISA/FBI/NSA iz 2022. opisao je Sandwormov modularni Cyclops Blink malware na WatchGuard uređajima, trajno postavljen kao firmware update i sposoban za dodavanje modula. DOJ je odvojeno opisao raniji APT28 VPNFilter botnet rutera i NAS uređaja kao sposoban za intelligence collection, destructive activity i misattribution.<sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>

**Efekat na privatnost.** Edge appliance uređaji su stalno online, smatraju se pouzdanom infrastrukturom i imaju slabu EDR pokrivenost. Firmware persistence može preživeti obično ponovno pokretanje i pretvoriti victim uređaj u relay ili control point.

**Šta ga razotkriva.** Integritet firmware-a, vendor-specific implant protocol, neočekivana management exposure, promene konfiguracije i outbound beaconing. Edge uređaji moraju biti forenzički subjekti, a ne transparentna infrastruktura.

## DPRK: identity, network i financial layering

**Javni nalaz.** DOJ slučajevi opisuju DPRK radnike koji su dobijali remote poslove koristeći lažni ili ukradeni identity material i VPN-ove, primali cryptocurrency, delili transfere, menjali assets/chains, koristili NFT-jeve i mešali prihode. Drugi slučajevi opisuju OTC traders i front companies koji su pretvarali ukradeni crypto u kupovine. Treasury i FBI su javno povezali Lazarus/TraderTraitor prihode sa mixers i identifikovali adrese iz velikih krađa.<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup>

**Efekat na privatnost.** Ovo nije „private coin“. To je multi-domain chain: persona i remote access skrivaju lokaciju radnika; crypto premešta vrednost; layering prekida jednostavne transakcione narative; OTC traders/front companies povezuju robu i fiat.

**Šta ga razotkriva.** Anomalije poslodavca/uređaja, ponovo korišćeni facilitatori, blockchain vremenski obrasci/kontinuitet vrednosti, exchange/bridge zapisi, sanctioned addresses, account identity i shipment/company records ponovo povezuju lanac.

**Odbrambena lekcija.** Timovi za hiring, IAM, endpoint, payroll, blockchain i sanctions moraju koristiti zajednički model slučaja. Više detalja nalazi se u [Financial Obfuscation Tradecraft](financial-obfuscation-tradecraft.md).

## Obrasci kroz slučajeve

| Obrazac | APT primeri | Prilagođavanje odbrane |
|---|---|---|
| Izlaz je druga žrtva | APT28/Moobot, Volt Typhoon/KV, ORBs | istražite i sanirajte izlaz; nemojte ga poistovećivati sa lokacijom aktera |
| Kontrole se razlikuju po granici | APT28 nearest neighbor | omogućite internom/wireless pristupu isti nivo identity assurance-a kao za Internet pristup |
| Legitimni service je routing layer | APT29, APT41 | zadržite kontekst objekta/putanje/procesa, a ne samo destination domain |
| Edge uređajima nedostaje telemetry | KV, Moobot, Cyclops Blink, ORBs | centralizujte config/auth/flow logove i proverite firmware/inventory |
| Infrastruktura je deljena i kratkog veka | China-nexus ORBs | klasterizujte ponašanje/topologiju i pratite promene uloga tokom vremena |
| Više slabih razdvajanja se kombinuje | DPRK personas + VPN + crypto + OTC | povežite identity, device, network, payment i fizičke dokaze |

## References

- [1] [Volexity — The Nearest Neighbor Attack](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [2] [US DOJ — Disruption of the GRU-controlled Moobot router botnet](https://www.justice.gov/archives/opa/pr/justice-department-conducts-court-authorized-disruption-botnet-controlled-russian)
- [3] [US DOJ — Disruption of the PRC KV Botnet](https://www.justice.gov/archives/opa/pr/us-government-disrupts-botnet-peoples-republic-china-used-conceal-hacking-critical)
- [4] [CISA AA24-038A — PRC actors compromise and maintain persistent access to US critical infrastructure](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf)
- [5] [Google Cloud/Mandiant — China-nexus espionage actors use ORB networks](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [6] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [7] [MITRE ATT&CK — Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [Kaspersky Securelist — Satellite Turla](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [9] [CISA/NCSC/FBI/NSA — Cyclops Blink advisory AA22-054A](https://www.cisa.gov/sites/default/files/publications/AA22-054A%20New%20Sandworm%20Malware%20Cyclops%20Blink%20Replaces%20VPN%20Filter.pdf)
- [10] [US DOJ — APT28 VPNFilter disruption](https://www.justice.gov/archives/opa/pr/justice-department-announces-actions-disrupt-advanced-persistent-threat-28-botnet-infected)
- [11] [US DOJ — DPRK Foreign Trade Bank representative charged in crypto-laundering conspiracies](https://www.justice.gov/archives/opa/pr/north-korean-foreign-trade-bank-representative-charged-crypto-laundering-conspiracies)
- [12] [US Treasury — Blender.io sanctions and Lazarus funds](https://home.treasury.gov/news/press-releases/jy0768)
- [13] [CISA AA25-239A — Countering Chinese state-sponsored actors' compromise of networks worldwide](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-239a)
- [14] [Google Cloud/Mandiant — Ghost in the Router: UNC3886 targets Juniper routers](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-targets-juniper-routers)
{{#include ../banners/hacktricks-training.md}}
