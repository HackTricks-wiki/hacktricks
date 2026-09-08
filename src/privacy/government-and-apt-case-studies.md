# Studije slučaja vlada i APT grupa

Ovi javno dostupni slučajevi pokazuju kako se odvojene privacy tehnike kombinuju u stvarnim operacijama. Oznake atribucije su one koje su koristili navedeni istražitelji ili vlade; sama IP adresa, preklapanje alata ili geopolitička podudarnost nisu konačan dokaz atribucije.

## APT28: Wi-Fi pristup udaljenom najbližem susedu

**Javni nalaz.** Volexity je upad iz 2022. godine pripisao grupi GruesomeLarch/APT28. Nakon što je MFA zaustavio pristup Internetu pomoću validovanih kredencijala, napadač je kompromitovao organizacije u blizini mete i sa obližnjeg dual-homed hosta pristupio enterprise Wi-Fi mreži mete. Wi-Fi putanja je prihvatala kredencijal bez MFA zahteva koji je važio spolja.<sup>[[1]](#references)</sup>

**Uticaj na privacy.** Konačan pristup potekao je iz fizičkog dometa radio-signala, a posredne organizacije bile su žrtve. Operacija je izbegla putovanje i učinila da konvencionalna IP geolokacija pokaže na suseda.

**Šta je razotkrilo operaciju.** Upozorenje mete, istraga hosta/mreže, aktivnost kredencijala, topologija interfejsa i fizička blizina morali su biti analizirani kao jedna celina. Anomalija nije bila samo nova IP adresa; legitimni identitet se pojavio kroz neuobičajen Wi-Fi/device kontekst, dok su obližnji sistemi bili kompromitovani.

**Defenzivna lekcija.** Primenite pristup Wi-Fi mreži zasnovan na sertifikatima i uređajima, korelišite RADIUS sa NAC/MDM i fizičkim kontekstom i istražujte infrastrukturu u okolini umesto da pretpostavite da je poslednji hop operator.

## APT28: criminal Moobot infrastruktura koju je GRU ponovo upotrebio

**Javni nalaz.** U februaru 2024. godine, US Department of Justice opisao je botnet sa stotinama Ubiquiti EdgeOS rutera. Criminal actors su instalirali Moobot na rutere koji su zadržali poznate podrazumevane administratorske kredencijale; GRU Unit 26165 je zatim dodao skripte i fajlove, pretvarajući postojeći criminal botnet u espionage platformu korišćenu za spearphishing i krađu kredencijala.<sup>[[2]](#references)</sup>

**Uticaj na privacy.** GRU nije sam izgradio celokupnu infrastrukturu. Pozajmljivanje već kompromitovane flote postavilo je adrese nepovezanih domaćinstava i malih kancelarija između operatora i meta, pomešalo državnu aktivnost sa criminal aktivnošću i smanjilo artifacts specifične za operatora.

**Šta je razotkrilo operaciju.** Fajlovi rutera, ponašanje malware-a pri kontroli i routing informacije koje nisu sadržale sadržaj podržali su istragu. Tokom disruption-a privremeno su promenjena firewall pravila i uklonjeni malicious fajlovi, dok je DOJ upozorio da nepromenjeni podrazumevani kredencijali mogu omogućiti reinfection.

**Defenzivna lekcija.** Zamenite rutere kojima je istekla podrška, uklonite administraciju izloženu Internetu, promenite podrazumevane vrednosti, instalirajte zakrpe, prikupljajte configuration/flow podatke edge uređaja i tražite ponašanje karakteristično za flotu. „Residential US IP“ nije dokaz da je operator iz US.

## Volt Typhoon: KV Botnet plus living off the land

**Javni nalaz.** DOJ i zajednički CISA advisory opisali su PRC state-sponsored Volt Typhoon koji koristi KV Botnet, pre svega kompromitovane Cisco i NETGEAR SOHO rutere kojima je istekao životni vek, kako bi prikrio PRC poreklo aktivnosti usmerenih na critical infrastructure. Unutar žrtava, operator je davao prednost validnim nalozima i ugrađenim administration alatima; agencije su prijavile pristup u nekim okruženjima koji je trajao najmanje pet godina.<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>
```text
PRC operator -> encrypted KV path -> compromised SOHO exit -> edge service
|
valid accounts + native tools
```
**Efekat po privatnost.** Putanja nalik ORB-u skrivala je poreklo, dok je living-off-the-land nakon pristupa smanjio broj novih binarnih fajlova i mogućnosti za detekciju potpisima. Mrežno i endpoint prikrivanje međusobno su se pojačavali.

**Šta ga je razotkrilo.** Struktura rutera/kontrolera, tehničko prikupljanje podataka odobreno sudskim nalogom, ponavljajuća aktivnost i analiza među žrtvama bili su važniji od jednog IOC-a. Restartovanje rutera uklonilo je volatilni KV malware u opisanim slučajevima, ali nije otklonilo osnovnu izloženost uređaja koji je bio na kraju životnog veka.

**Defenzivna pouka.** Zamenite edge uređaje na kraju životnog veka, centralizujte authentication i network-device logove, napravite baseline ponašanja administratora, ograničite outbound connectivity i tražite sekvence ponašanja kroz identity, endpoint i network slojeve.

## China-nexus ORB mreže: infrastructure as a service

**Javni nalaz.** Mandiant je opisao ekosistem ORB mreža koje koristi više China-nexus espionage aktera. Provisioned mreže koristile su iznajmljene VPS čvorove; non-provisioned mreže koristile su kompromitovane IoT uređaje i rutere; hybrid mreže kombinovale su ih. ORB3/SPACEHOP podržavao je aktivnosti povezane sa APT5/APT15. ORB2/FLORAHOX kombinovao je administration server, iznajmljene servere, prilagođeni Tor layer i kompromitovane Cisco, ASUS i DrayTek uređaje. Mandiant je procenio da se nekim mrežama nezavisno upravljalo i da su iznajmljivane većem broju APT aktera.<sup>[[5]](#references)</sup>

**Efekat po privatnost.** Infrastructure je postala servisna granica. Jedan operator mogao je da dobije geografske/rezidencijalne izlaze bez održavanja flote žrtava, dok je veliki broj korisnika koji su je delili otežavao jednostavno povezivanje aktera sa IP adresom. Brza smena flote ubrzavala je „izumiranje IOC-a“.

**Šta ga je razotkrilo.** Network topography, klonirane server images, portovi/servisi, odnosi sa kontrolerima, router implants i lifecycle obrasci ostali su pogodni za klasterovanje. Mandiant je naveo da su neke node IP adrese ostajale u ORB-u svega 31 dan.

**Defenzivna pouka.** Pratite ORB kao entitet koji se menja: uloge čvorova, service fingerprints, upstream odnose, scan ponašanje i ritam rotacije. Isticanje IP indikatora treba da ažurira klaster, a ne da izbriše slučaj.

## PRC globalni espionage system: ruteri, trusted links i traffic mirroring

**Javni nalaz.** Multinacionalni advisory iz 2025. godine opisao je aktivnosti koje se preklapaju sa komercijalnim nazivima za reporting, uključujući Salt Typhoon, OPERATOR PANDA, RedMike, UNC5807 i GhostEmperor. Agencije su izvestile o iznajmljenim VPS-ovima i kompromitovanim intermediate ruterima korišćenim za pristup telekomunikacionim i network provajderima. Akteri su se kretali kroz trusted provider/customer linkove, menjali rute, uspostavljali GRE/IPsec tunnels, koristili device containers i uključivali SPAN/RSPAN/ERSPAN ili native packet capture radi prikupljanja authentication i customer traffic podataka.<sup>[[13]](#references)</sup>

**Efekat po privatnost.** Kompromitovani ruter je istovremeno relay, observation point i trusted network participant. Privatne interkonekcije mogu zaobići kontrole projektovane oko javnog Interneta, dok traffic mirroring prikuplja credentials bez postavljanja endpoint agenta.

**Šta ga razotkriva.** Configuration diffovi, neočekivani SNMP/SSH/web administration, nove static routes/tunnels, mirror sessions, Guest Shell containers, PCAP fajlovi, izmene TACACS+/RADIUS odredišta i onemogućeno logging. Advisory naglašava da neki intermediate ruteri nisu bili deo prethodno imenovanog javnog botneta, pa odsustvo poznatih ORB indikatora nije bilo dokaz nevinosti.

**Defenzivna pouka.** Koristite out-of-band administration, centralizovane configuration/authentication logove, provere integriteta signed-image i runtime okruženja, ograničenja egress sa management interfejsa i upozorenja za izmene route/mirror/tunnel/AAA konfiguracije. Obuhvatite sumnjivu kompromitaciju među trusted peerovima pre eviction-a.

## UNC3886 RedPenguin: pasivni backdoor-i na ISP ruterima

**Javni nalaz.** Mandiant je pripisao UNC3886 prilagođene backdoor-e izvedene iz TINYSHELL-a na Juniper MX ruterima na kraju životnog veka. Skup je obuhvatao aktivne i pasivne implants, nazive koji oponašaju legitimne daemons, ponašanje za onemogućavanje logova, process injection u trusted process, SOCKS proxy mogućnost i infrastructure procenjenu kao ORB staging nodes. Pasivne varijante analizirale su pakete preko `libpcap` i aktivirale se tek nakon magic pattern-a; jedna je mogla da pređe na active callback naveden u trigger-u.<sup>[[14]](#references)</sup>

**Efekat po privatnost.** Pasivni implant nema periodični beacon koji bi omogućio njegovo otkrivanje. Deli portove/saobraćaj sa pravim network appliance-om, kratkotrajno se aktivira i može da prosleđuje saobraćaj kroz ORB umesto da se direktno poveže sa krajnjim kontrolerom.

**Šta ga razotkriva.** Memory analysis, razlike između koda na disku i koda koji se izvršava, neočekivani packet-capture filteri/socket ponašanje, imena procesa/fajlova koja samo približno oponašaju legitimne daemons, administration preko terminal servera, nedostajući logovi i dvostepeni odnos između staging nodes i backend kontrolera.

**Defenzivna pouka.** Pribavite memory i filesystem/configuration dokaze, uporedite procese/module sa poznatim dobrim image-om, nadgledajte upotrebu packet-capture/socket filtera, zaštitite management terminal servers i zamenite network hardware na kraju životnog veka. Čist outbound-beacon hunt nije potvrda da je sistem bezbedan.

## APT29: Tor domain fronting

**Javni nalaz.** MITRE beleži da APT29 koristi `meek` Tor pluggable transport za domain-front C2 saobraćaj. Spoljašnje TLS ime izgledalo je kao dozvoljeni domen hostovan na CDN-u, dok je unutrašnji HTTP host birao stvarnu rutu.<sup>[[6]](#references)</sup>

**Efekat po privatnost.** Observer koji vrši filtering mogao je da vidi uobičajeni front/CDN umesto unutrašnjeg odredišta, a njegovo blokiranje nosilo je rizik od kolateralne štete.

**Šta ga razotkriva.** CDN može da uoči nepodudaranje rutiranja, a defender sa endpoint ili lawful TLS visibility može da poveže proces, authority, trajanje konekcije, obrazac bajtova i kasniju aktivnost. Promene politike provajdera mogu onemogućiti tehniku.

**Defenzivna pouka.** Nemojte se oslanjati samo na SNI allowlisting. Primenite application-aware egress, upoređujte TLS i HTTP identitete gde su vidljivi i povežite network događaj sa procesom koji ga je pokrenuo.

## APT41 i drugi dead-drop resolvers

**Javni nalaz.** MITRE dokumentuje da APT41 koristi legitimne sajtove, uključujući GitHub, Pastebin, Microsoft TechNet, Cloudflare i community forums, za objavljivanje ili preuzimanje C2 informacija. Drugi state-linked alati na sličan način koriste posts, documents i social media.<sup>[[7]](#references)</sup>

**Efekat po privatnost.** Binarni fajl sadrži legitimni servis/objekat umesto stabilne C2 adrese. Objekat može da se menja radi rotacije infrastructure, dok se početni zahtev utapa u uobičajeni TLS saobraćaj.

**Šta ga razotkriva.** Objekat ili account identifier je stabilan; retki procesi ga ponavljano preuzimaju; sadržaj se dekodira; zatim sledi druga outbound konekcija. Provider account i API zapisi mogu povezati objavljivanje sa operatorom.

**Defenzivna pouka.** Sačuvajte kompletne proxy paths/object IDs i endpoint process lineage. Događaj na nivou domena, kao što je „connected to GitHub“, previše je grub.

## Turla: satellite-address C2

**Javni nalaz.** Kaspersky je izvestio da Turla zloupotrebljava nešifrovane downstream broadcasts starijih jednosmernih DVB-S Internet servisa. Operator u oblasti pokrivenoj satelitom mogao je da izabere legitimnu adresu subscriber-a i prima odgovore emitovane toj adresi, zbog čega je izgledalo da je C2 hostovan iza satellite provajdera u drugom regionu.<sup>[[8]](#references)</sup>

**Efekat po privatnost.** Prividna server adresa nije otkrivala primaoca, a uobičajeni postupci zaplene hostinga/WHOIS-a bili su manje korisni.

**Šta ga razotkriva.** Akteru je i dalje bila potrebna outbound request putanja, rutiranje je bilo asimetrično, legitimni subscriber nije pokretao C2 razmenu, a RF/provider istraga mogla je da suzi oblast prijema.

**Defenzivna pouka.** Geolokaciju tretirajte kao jednu hipotezu. Proverite path symmetry, RTT, routing ownership i da li je navodni endpoint zaista mogao da proizvede uočeni servis.

## Cyclops Blink i VPNFilter: edge uređaji kao trajni cover

**Javni nalaz.** Advisory NCSC/CISA/FBI/NSA iz 2022. godine opisao je Sandworm-ov modularni Cyclops Blink malware na WatchGuard uređajima, trajno postavljen kao firmware update i sposoban da dodaje module. DOJ je zasebno opisao raniji APT28 VPNFilter botnet rutera i NAS uređaja kao sposoban za intelligence collection, destructive activity i misattribution.<sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>

**Efekat po privatnost.** Edge appliances su stalno online, smatraju se pouzdanim delom infrastructure i slabo su pokriveni EDR-om. Firmware persistence može preživeti uobičajeni restart i pretvoriti uređaj žrtve u relay ili control point.

**Šta ga razotkriva.** Firmware integrity, vendor-specific implant protocol, neočekivana management exposure, promene konfiguracije i outbound beaconing. Edge uređaji moraju biti forenzički subjekti, a ne transparent plumbing.

## DPRK: identity, network i financial layering

**Javni nalaz.** DOJ slučajevi opisuju radnike iz DPRK-a koji dobijaju remote jobs koristeći lažni ili ukradeni identity material i VPN-ove, primaju cryptocurrency, dele transfere, menjaju assets/chains, koriste NFTs i mešaju prihode. Drugi slučajevi opisuju OTC traders i front companies koji ukradeni crypto pretvaraju u kupovine. Treasury i FBI su javno povezali prihode Lazarus/TraderTraitor sa mixers i identifikovali adrese iz velikih krađa.<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup>

**Efekat po privatnost.** Ovo nije „private coin“. To je lanac kroz više domena: persona i remote access skrivaju lokaciju radnika; crypto prenosi vrednost; layering prekida jednostavne narative transakcija; OTC traders/front companies povezuju ga sa robom i fiat novcem.

**Šta ga razotkriva.** Employer/device anomalije, ponovo korišćeni facilitators, blockchain kontinuitet vremena/vrednosti, exchange/bridge zapisi, sanctioned addresses, account identity i shipment/company records ponovo povezuju lanac.

**Defenzivna pouka.** Timovi za hiring, IAM, endpoint, payroll, blockchain i sanctions treba da koriste zajednički case model. Više detalja nalazi se u [Financial Obfuscation Tradecraft](financial-obfuscation-tradecraft.md).

## Obrasci kroz slučajeve

| Obrazac | APT primeri | Prilagođavanje odbrane |
|---|---|---|
| Exit je druga žrtva | APT28/Moobot, Volt Typhoon/KV, ORBs | istražite i sanirajte exit; nemojte ga izjednačavati sa lokacijom aktera |
| Kontrole se razlikuju po granici | APT28 nearest neighbor | obezbedite da interni/wireless access ima isto identity assurance kao Internet access |
| Legitimni servis je routing layer | APT29, APT41 | zadržite object/path/process context, a ne samo destination domain |
| Edge uređaji nemaju telemetriju | KV, Moobot, Cyclops Blink, ORBs | centralizujte config/auth/flow logove i proverite firmware/inventory |
| Infrastructure je deljena i kratkog veka | China-nexus ORBs | klasterujte ponašanje/topologiju i pratite promene uloga kroz vreme |
| Više slabih razdvajanja se kombinuje | DPRK personas + VPN + crypto + OTC | povežite identity, device, network, payment i physical dokaze |

## References

- [1] [Volexity — Napad najbližeg suseda](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [2] [US DOJ — Prekid rada Moobot router botneta pod kontrolom GRU-a](https://www.justice.gov/archives/opa/pr/justice-department-conducts-court-authorized-disruption-botnet-controlled-russian)
- [3] [US DOJ — Prekid rada PRC KV botneta](https://www.justice.gov/archives/opa/pr/us-government-disrupts-botnet-peoples-republic-china-used-conceal-hacking-critical)
- [4] [CISA AA24-038A — Akteri iz PRC-a kompromituju i održavaju trajni pristup kritičnoj infrastrukturi SAD](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf)
- [5] [Google Cloud/Mandiant — China-nexus espionage akteri koriste ORB mreže](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [6] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [7] [MITRE ATT&CK — Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [Kaspersky Securelist — Satelitska Turla](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [9] [CISA/NCSC/FBI/NSA — Cyclops Blink advisory AA22-054A](https://www.cisa.gov/sites/default/files/publications/AA22-054A%20New%20Sandworm%20Malware%20Cyclops%20Blink%20Replaces%20VPN%20Filter.pdf)
- [10] [US DOJ — Prekid rada APT28 VPNFilter-a](https://www.justice.gov/archives/opa/pr/justice-department-announces-actions-disrupt-advanced-persistent-threat-28-botnet-infected)
- [11] [US DOJ — Predstavnik Foreign Trade Bank-a DPRK-a optužen za zavere pranja crypto sredstava](https://www.justice.gov/archives/opa/pr/north-korean-foreign-trade-bank-representative-charged-crypto-laundering-conspiracies)
- [12] [US Treasury — Sankcije protiv Blender.io i sredstva Lazarus-a](https://home.treasury.gov/news/press-releases/jy0768)
- [13] [CISA AA25-239A — Suprotstavljanje kompromitaciji mreža širom sveta od strane aktera koje podržava Kina](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-239a)
- [14] [Google Cloud/Mandiant — Ghost in the Router: UNC3886 cilja Juniper rutere](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-targets-juniper-routers)
