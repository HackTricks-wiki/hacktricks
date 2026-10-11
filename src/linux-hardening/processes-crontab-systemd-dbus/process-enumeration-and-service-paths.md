# Enumeracija procesa i putanje servisa

{{#include ../../banners/hacktricks-training.md}}

Korisno pitanje je koji privilegovani proces koristi podatke ili kod na koje korisnik sa nižim privilegijama može da utiče. Pregledajte stablo procesa, aktivno okruženje, otvorene datoteke i unit ili skriptu koji su pokrenuli svaki kandidat.

## Mapiranje procesa i vlasništva

```bash
ps -eo user,pid,ppid,tty,comm,args --sort=ppid
pstree -alp 2>/dev/null
systemctl list-units --type=service --state=running 2>/dev/null
ss -lntup
```

Unakrsni odnos roditelj–dete između različitih korisnika može biti uobičajen, ali neočekivani prelaz zahteva proveru roditeljske komande, argumenata, izvršne datoteke, radnog direktorijuma i referenciranih datoteka. Koristite [korisnike i sesije](../user-information/user-and-session-triage.md) da biste protumačili vlasnika i kontekst prijave.

### Konzole lokalnih virtuelnih mašina

Pregledajte QEMU opcije `-spice` zajedno sa adresom na kojoj osluškuje. [QEMU dokumentacija](https://www.qemu.org/docs/master/system/qemu-manpage.html) navodi da `disable-ticketing` omogućava SPICE klijentima povezivanje bez autentifikacije. Slušač vezan za loopback i dalje može biti dostupan drugim lokalnim korisnicima hosta. Pre nego što komandu tretirate kao izloženu konzolu, proverite aktivni slušač, opcije autentifikacije i lokalni pristup. Upravljanje konzolom utiče na **gosta**; dobijanje gostujućeg naloga ili promena njegovog stanja pokretanja zahtevaju zasebne uslove unutar gosta i ne daju root privilegije na hostu za virtualizaciju. Tokom pasivne enumeracije pročitajte argumente procesa i metapodatke soketa, bez povezivanja sa gostom ili njegovog ponovnog pokretanja.

Lokalno dostupno veb sučelje može da izvršava kod pod servisnim nalogom čak i kada početna ljuska nema pristup datotekama tog naloga. Na primer, CVE-2023-0297 je uticao na obradu `/flash/addcrypted2` u pyLoad-u kada je nepouzdani JavaScript dospeo do Js2Py-ja uz omogućene Python importe; [ispravka u izvornom kodu](https://github.com/pyload/pyload/commit/7d73ba7919e594d783b3411d7ddb87885aea782d) onemogućila je `pyimport`. Pre nego što proces pyLoad-a tretirate kao putanju za eskalaciju, uporedite vlasnika pokrenutog procesa, adresu na kojoj osluškuje, izloženost krajnje tačke i instaliranu ispravku ili zakrpu dobavljača. Sam naziv procesa, otvoren port ili verzija paketa ne dokazuju izloženost; pasivna enumeracija ne bi trebalo da šalje payload za izvršavanje.

### Privilegovane login ljuske koje dele terminal

Privilegovana interaktivna ljuska koja pokreće `su --login <user>` bez nezavisnog pseudo-terminala može ostaviti terminal zajednički sa login ljuskom korisnika sa nižim privilegijama. Ako taj korisnik može da kontroliše svoju startup datoteku i kod u njoj može da koristi `TIOCSTI` za ubacivanje ulaza sa tastature u terminal, taj ulaz može dospeti do privilegovane ljuske kada ona nastavi sa radom. [Priručnik za `su` iz util-linux-a](https://man7.org/linux/man-pages/man1/su.1.html#SECURITY_NOTES) opisuje rizik zajedničkog terminala i preporučuje `su --pty`/`-P` za interaktivnu upotrebu; `su -c` pokreće zasebnu sesiju bez kontrolnog terminala. Rizik zavisi od stvarne roditeljske ljuske, odnosa terminala, ciljne startup datoteke i politike kernela. Sam naziv procesa ili argument `su -l` samo je povod za proveru.

Pregledajte uočeno stablo procesa i kolone TTY, a zatim proverite launcher koji može da se pročita i vlasništvo/dozvole startup datoteke. U Linuxu, `/proc/sys/dev/tty/legacy_tiocsti` može pomoći u tumačenju politike kada postoji; njegovo odsustvo ne dokazuje da je sistem bezbedan. [Linux priručnik za `TIOCSTI`](https://man7.org/linux/man-pages/man2/TIOCSTI.2const.html) navodi da od Linuxa 6.2 za ovu operaciju može biti potreban `CAP_SYS_ADMIN` kada je ovaj sysctl postavljen na false. Nemojte pozivati ioctl samo radi enumeracije hosta.

Nalog baze podataka ponekad može da izmeni startup datoteku ciljnog korisnika bez direktnog pristupa za pisanje u datotečni sistem. PostgreSQL server-side `COPY ... TO 'filename'` zapisuje datотеку под OS налогом сервера базе података, али [ограничења PostgreSQL-а](https://www.postgresql.org/docs/current/sql-copy.html) дозвољавају овај облик само superuser налозима базе података или улогама као што је `pg_write_server_files`. Проверите и улогу у бази података и OS дозволе за датотеку на серверу; connection string апликације сам по себи не даје право уписа у датотеку. При процени ланца, могућности привилегованог launchera и налога базе података посматрајте одвојено.

## Преглед артефаката током извршавања

```bash
readlink /proc/<PID>/exe
tr '\0' ' ' </proc/<PID>/cmdline; echo
ls -l /proc/<PID>/fd 2>/dev/null
lsof -p <PID> 2>/dev/null
lsof +L1 2>/dev/null
```

Obrisani izvršni fajlovi i obrisani, ali otvoreni fajlovi ostaju referencirani dok se ne zatvori njihov poslednji deskriptor. Mogu da sačuvaju dokaze ili dostupne tajne. Okruženja procesa i memorija mogu sadržati akreditive, ali čitanje drugog procesa ograničavaju vlasništvo, opcije montiranja sistema datoteka `/proc`, Yama ptrace politika i druge bezbednosne kontrole. Za povezane tehnike pogledajte [deskriptore fajlova](../main-system-information/filesystem-links-and-file-descriptors.md) i [traženje akreditiva nakon eksploatacije](../post-exploitation/README.md).

Sačuvani syscall tragovi predstavljaju još jednu granicu dozvola za fajlove. [`strace` beleži argumente syscall poziva u izlazni fajl](https://man7.org/linux/man-pages/man1/strace.1.html), pa čitljiv trag [`execve` argumenata](https://man7.org/linux/man-pages/man2/execve.2.html) može otkriti lozinku koju je privilegovani zadatak prosledio u komandnoj liniji. Najpre utvrdite da li trenutni korisnik može da pročita konkretan trag i da li argument zaista sadrži akreditiv; za kasniji prelazak na Unix nalog potrebna je zasebna potvrda da je akreditiv tamo prihvaćen. Metapodaci fajla mogu poslužiti kao koristan pasivni trag, bez skeniranja svakog traga ili ispisivanja njegovog sadržaja tokom rutinskog prikupljanja podataka.

## Privilegovani soketi za kancelarijsku automatizaciju

LibreOffice i OpenOffice mogu da izlože svoj UNO API pomoću argumenta `--accept=socket,host=<host>,port=<port>;urp;`. Kancelarijski proces u vlasništvu root-a sa dostupnom krajnjom tačkom može niže privilegovanom lokalnom korisniku omogućiti da poziva API servise u bezbednosnom kontekstu tog procesa. Servis `SystemShellExecute` obuhvata operaciju za pokretanje sistemske komande. Vezivanje za loopback ograničava udaljenu dostupnost, ali soket i dalje ostaje dostupan lokalnim korisnicima, osim ako neka druga kontrola to ne sprečava.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
ps -eo user,args | grep -E '[s]office|[l]ibreoffice|[o]penoffice'
ss -ltn 2>/dev/null
```

Povežite vlasnika procesa, tačan argument `--accept` i trenutnu adresu i port na kojima sluša. Konfigurisani prihvatnik koji nije uspeo da se poveže samo je trag; tokom pasivnog enumerisanja nemojte se povezivati na API niti ga pozivati. Izbegavajte pokretanje privilegovane instance kancelarijskog paketa samo da biste testirali ovaj uslov.

## System V deljena memorija koju koriste privilegovani procesi

Pomoćni program u vlasništvu root-a može da kreira segment System V deljene memorije u koji drugi korisnik može da upisuje. Ako pomoćni program kasnije veruje podacima iz tog segmenta u shell komandi ili nekoj drugoj osetljivoj operaciji, segment prelazi granicu privilegija čak i kada su izvršna datoteka i njene datoteke zaštićene. `shmget()` preuzima dozvole pristupa iz nižih devet bitova svojih zastavica; režim `0666` dozvoljava drugim korisnicima upisivanje, dok zastavica `IPC_CREAT` ne ograničava te dozvole. Pasivno pregledajte aktivne segmente pomoću `ipcs -m` i povežite njihovog vlasnika, režim i trajanje postojanja sa privilegovanim procesom i načinom obrade njegovog ulaza. Sam segment u koji svi mogu da upisuju ne dokazuje izvršavanje komandi.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
ipcs -m
```

System V segmenti se razlikuju od POSIX datoteka deljene memorije u `/dev/shm`. Segment napravljen samo na trenutak možda neće biti prisutan u jednom `ipcs` snimku, pa prazan izlaz ne isključuje pomoćni program koji koristi deljenu memoriju. Pregledajte njegov izvorni kod ili ponašanje binarne datoteke i sva `sudo` pravila koja ga pokreću; nemojte pozivati privilegovani pomoćni program samo da bi se segment pojavio tokom enumeracije. [Vodič za IPC namespace](../containers-namespaces/container-security/protections/namespaces/ipc-namespace.md) objašnjava kako namespace-i utiču na vidljivost.<sup>[[2]](#references)[[3]](#references)</sup>

## Provere skripti Consul agenta

Consul može da pokreće provere ispravnosti pomoću skripti sa identitetom operativnog sistema svog agenta. Ako agent radi kao root, omogućena je opcija `enable_script_checks`, a korisniku sa nižim privilegijama je dozvoljeno da registruje servis sa proverom pomoću skripte preko lokalnog HTTP API-ja, taj korisnik može da izazove pokretanje komandi kao root. Vezivanje API-ja samo za `127.0.0.1` i dalje omogućava lokalnim korisnicima da mu pristupe. Podešavanje `enable_local_script_checks` je uže: ono isključuje provere pomoću skripti poslate kroz registracije preko HTTP API-ja. Kada su Consul ACL-ovi omogućeni, za registraciju servisa je potreban `service:write`; sama linija `acl.default_policy=allow` ne dokazuje da anonimni pozivalac može da registruje servis. Zajedno pregledajte stvarni identitet agenta, učitana podešavanja, vezivanje API-ja i autorizaciju.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

```bash
ps -eo user,args | grep '[c]onsul agent'
ls -l /etc/consul.d 2>/dev/null
```

Pratite argumente `-config-dir` i `-config-file` pokrenutog agenta do odgovarajuće konfiguracije i pregledajte samo nazive i podešavanja polja za script-check i ACL. Konfiguracione datoteke mogu sadržati i gossip ključeve ili tokene; nemojte ih lepiti u deljene logove. Nemojte registrovati servis niti pokretati health check samo da biste utvrdili da li ovo stanje postoji.

Zasebna putanja preko lokalne datoteke postoji kada korisnik sa nižim privilegijama može da **piše i pretražuje** direktorijum naveden argumentom `-config-dir` agenta pokrenutog kao root: iz tog direktorijuma može da se učita nova definicija servisa `.hcl` ili `.json`. Dozvole za pretraživanje i pisanje direktorijuma mogu omogućiti dodavanje datoteke čak i kada je onemogućeno listanje direktorijuma. Za izvršavanje komandi kao root potvrdite da agent zaista učitava taj direktorijum, da njegova **efektivna** postavka za script-check dozvoljava lokalne definicije, da je definicija učitana i da agent zadržava root privilegije. [Consul dokumentuje](https://developer.hashicorp.com/consul/docs/fundamentals/agent#reloadable-configurations) koja podešavanja i definicije health check-ova mogu ponovo da se učitaju; za samo omogućavanje script check-ova možda je potrebno ponovno pokretanje, zato proverite ponašanje instalirane verzije. Kada ACL-ovi štite agenta, za [`consul reload` je potreban `agent:write`](https://developer.hashicorp.com/consul/api-docs/agent#reload-agent); dozvola za pisanje u KV sama po sebi to ne omogućava. Tretirajte mogućnost pisanja u metapodatke direktorijuma kao povod za proveru, a ne kao dokaz da je dozvoljeno ponovno učitavanje, ponovno pokretanje ili izvršavanje komandi. Pregledajte putanje, dozvole i pravila bez upisivanja konfiguracije ili pozivanja API-ja.

## Pratite lanac izvršavanja servisa

```bash
systemctl cat <unit>.service
systemctl show <unit>.service -p User -p Group -p ExecStart -p EnvironmentFiles -p WorkingDirectory
namei -l /path/from/ExecStart
```

Proverite unit, drop-in fajlove, `EnvironmentFile=`, pomoćne skripte, relativne komande, direktorijume u koje može da se upisuje i aktivaciju preko soketa. Unit u vlasništvu root-a i dalje može biti nebezbedan ako čita konfiguraciju ili skriptu u koju korisnik može da upisuje. Stranica o [arbitrary file write](../interesting-files-permissions/write-to-root.md) pokriva uobičajene načine zloupotrebe servisa i unit fajlova. Pratite kratkotrajne poslove pomoću alata [pspy](https://github.com/DominicBreuker/pspy) ili revizijske/procesne telemetrije, ako ih jednokratni spisak iz `ps` ne obuhvati.

Za prilagođeni **xinetd** servis, uporedite `server`, `user` i kontrole pristupa iz omogućene konfiguracione sekcije sa aktivnim listener-om i tačnom izvršnom datotekom. Postavka [`user`](https://manpages.debian.org/testing/xinetd/xinetd.conf.5.en.html) bira identitet procesa koji se pokreće, dok set-user-ID bit na izvršnoj datoteci može zasebno da promeni njen efektivni identitet, ako [`execve` dozvoljava taj prelaz](https://man7.org/linux/man-pages/man2/execve.2.html). Dostupan privilegovani binarni fajl koji prihvata nepouzdan ulaz opravdava offline pregled izvornog koda ili disasembliranog koda zbog grešaka u bezbednosti memorije, kao što je neograničena [`scanf` konverzija niza](https://www.gnu.org/software/libc/manual/html_node/String-Input-Conversions.html) u bafer fiksne veličine. Mapiranje servisa i set-user-ID metapodaci samo su tragovi, a ne dokaz takve greške; tokom pasivne enumeracije nemojte slati ulaze koji izazivaju pad niti otklanjati greške u aktivnom privilegovanom servisu.

Za prilagođeni privilegovani listener čiji je izvorni kod čitljiv, pregledajte svaku dužinu koju kontroliše pozivalac, a koja se koristi u operaciji kopiranja kao što je [`memcpy`](https://man7.org/linux/man-pages/man3/memcpy.3.html). Provera da li je trenutni indeks upisa unutar bafera fiksne veličine ne dokazuje da se **dužina kopiranja** uklapa u preostali prostor; proverite `copy_length <= capacity - index` nakon što utvrdite da je indeks u dozvoljenom opsegu, kao i predznak i prekoračenje u aritmetici. Ovo je samo trag za pregled kada ulaz zaista stiže do te operacije, listener je dostupan korisniku sa nižim privilegijama, a proces zadržava viši efektivni identitet. Izvorni kod i metapodatke procesa pregledajte offline; tokom enumeracije nemojte slati ulaze koji izazivaju pad aktivnom servisu.

Na sistemima koji koriste **Upstart**, definicije sistemskih poslova mogu se nalaziti u `/etc/init/*.conf`. Fajl posla u koji trenutni korisnik može da upisuje važan je kada aktivni init daemon učitava baš taj posao, njegova `script` ili `exec` sekcija se izvršava sa višim privilegijama, a korisnik može da ga pokrene dozvoljenom komandom `initctl` ili drugim stvarnim okidačem. Dozvola za `initctl` kroz sudo sama po sebi ne dokazuje da je neki fajl posla upisiv niti da će se izmenjeni posao izvršiti. Proverite dozvole tačnog fajla posla, efektivnu postavku korisnika pod kojim se izvršava, aktivni daemon i okidač, bez menjanja ili pokretanja posla tokom enumeracije. Pogledajte priručnike za [konfiguraciju Upstart poslova](https://manpages.ubuntu.com/manpages/trusty/man5/init.5.html) i [`initctl`](https://manpages.ubuntu.com/manpages/xenial/man8/initctl.8.html).

Čitljiv fajl sa lozinkom za automatsku prijavu, kao što je `/etc/autologin/passwd` na sistemima čiji [boot posao čita baš tu putanju](https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/master/chromeos-base/autologin/files/init/autologin.conf), ukazuje na moguću izloženost akreditiva. Potvrdite da je boot posao instaliran i da koristi taj fajl, a zatim zasebno proverite da li je lozinka važeća za neki drugi lokalni nalog ili servis. Sam naziv fajla ne dokazuje ponovnu upotrebu lozinke; zabeležite putanju i metapodatke pristupa, ali nemojte unositi lozinku u zajedničke izlaze enumeracije.

`ExecStart=` u unit fajlu ili zakazana komanda mogu da otkriju tačnu putanju do skripte unutar direktorijuma čiji se sadržaj ne može izlistati. [Dozvola za pretragu direktorijuma](https://man7.org/linux/man-pages/man7/path_resolution.7.html) i dalje može omogućiti trenutnom identitetu da prođe poznatom putanjom; potvrdite dozvolu za pretragu u svakom nadređenom direktorijumu i dozvolu za čitanje fajla, umesto da pretpostavite da neuspešno izlistavanje direktorijuma štiti njegov sadržaj. Čitljiva skripta može sadržati akreditiv za prenos, ali prelazak na drugi nalog zahteva da taj akreditiv i dalje važi i da bude nezavisno prihvaćen na tom nalogu. Zabeležite putanju i dokaze o dozvolama bez ispisivanja tajnih vrednosti u zajedničke logove.

Kod zakazane CommonJS Node.js skripte pregledajte gole importe kao što je `require('package')`, čak i kada je sama skripta samo za čitanje. [Node pretražuje `node_modules` pored fajla koji vrši import, a zatim u njegovim nadređenim direktorijumima](https://nodejs.org/api/modules.html#loading-from-node_modules-folders), pre nego što pređe na konfigurisane globalne putanje. Korisnik sa nižim privilegijama koji može da **upisuje u jedan od tih nadređenih direktorijuma i da ga pretražuje** možda može da napravi paket koji će se ranije podudariti. Potvrdite da se tačan import izvršava, da izabrani paket nije ugrađeni modul, da se relevantna putanja može kreirati ili izmeniti, da se modul razrešava na toj putanji u instaliranom runtime-u i da će ga posao sa višim privilegijama učitati pri narednom pokretanju. Metapodaci o upisivom nadređenom direktorijumu samo su povod za pregled; pregledajte skriptu i planer pasivno, bez postavljanja modula ili pokretanja posla.

Privatni Python indeks paketa predstavlja još jednu granicu poverenja kada automatizovani posao instalira pakete pod drugim OS identitetom. Uporedite tačan posao i nalog pod kojim se izvršava sa konfigurisanim indeksom, izabranim nazivima paketa i mogućnošću korisnika sa nižim privilegijama da objavi ili zameni paket koji će posao zaista instalirati. Izrada source distribucije može da pokrene njen build backend ili nasleđeni `setup.py` pod identitetom instalera; importovanje instaliranog paketa predstavlja zaseban putev izvršavanja. Listener indeksa, читљив хеш лозинке за отпремање или само име пакета не доказују цео тај ланац. Прегледајте посао, овлашћења за индекс и порекло пакета, без отпремања или инсталирања било чега током enumeracije. Погледајте [pip-ов интерфејс build система](https://pip.pypa.io/en/stable/reference/build-system/) и [смернице за безбедну инсталацију](https://pip.pypa.io/en/stable/topics/secure-installs/).

Привилеговани агент може да проверава ред задатака којим управља засебан веб сервис или контејнер. Ако идентитет са нижим степеном поверења може да уписује у базу података задатака тог сервиса, утврдите да ли се ти редови заиста прослеђују агенту и да ли се командни задатак извршава под OS идентитетом агента. Засебно потврдите приступ за упис у базу података, циљну сесију или кључ за рутирање, активно проверавање реда, овлашћење за задатак и ефективног корисника агента. Root унутар контејнера сам по себи не значи да постоји приступ као host-root; граница се прелази само ако потрошач са привилегијама на host-у изврши податке задатка које контролише нападач. Прегледајте метаподатке процеса, фајла базе података и сервиса, без мењања реда или слања задатка током enumeracije.

Понављајући посао може уместо тога да чита команду из конфигурационог реда у бази података апликације. Потврдите да улога базе података са нижим привилегијама може да измени баш тај ред, да га активни посао чита након измене и да вредност стиже до shell-а или еквивалентног покретача команди под вишим OS идентитетом. Приступ за упис у базу података или вредност која личи на команду сами по себи не доказују извршавање; прегледајте посао и дозволе, без мењања реда током пасивне enumeracije.

Порука у реду може да садржи URL уместо кода. Ако привилеговани потрошач преузима тај URL и учитава одговор као Lua или неки други извршни plugin, проверите дозволу објављивача за тачну размену и routing key, повезивање са редом који се обрађује, путању преузимања и учитавања plugin-а и ефективни идентитет worker-а. [RabbitMQ рутира објављене поруке преко размена](https://www.rabbitmq.com/docs/exchanges); listener брокера или важећа пријава сами по себи не доказују да ће порука бити испоручена овом worker-у. Ухваћени акредитиви брокера у чистом тексту засебан су траг који захтева стварни приступ хватању пакета и читљив саобраћај; они не доказују овлашћење за објављивање. Lua plugin може да покреће shell команде преко [`os.execute`](https://www.lua.org/manual/5.4/manual.html#pdf-os.execute) само ако је тај API доступан у његовом runtime-у. Прегледајте конфигурацију и код без хватања саобраћаја, објављивања порука или преузимања plugin-а током пасивне enumeracije.

Када привилеговани Python сервис излаже локалну HTTP или socket крајњу тачку, читљива скрипта може да открије путању од улаза до кода, чак и ако њене дозволе спречавају измену. Упоредите активни процес и идентитет unit-а са тачном скриптом, listener-ом, ауторизацијом рута и пољима која контролише позивалац. Затим пратите та поља кроз парсирање и валидацију до динамичког `eval()` или `exec()` одредишта. Конкретно, састављање новог f-string-а од текста захтева, а затим његова евалуација, може да протумачи поља за замену која је унео нападач као Python изразе ([Python упозорење о `eval`](https://docs.python.org/3/library/functions.html#eval); [семантика f-string-а](https://docs.python.org/3/reference/lexical_analysis.html#f-strings)). Само појављивање `eval` или везивање на loopback адресу не доказује да непоуздан позивалац стиже до тог одредишта; прегледајте стварни ток података и контроле приступа, без слања пробног payload-а током enumeracije.

Провера потписа на тој рути захтева засебан преглед. Ако читљив изворни код показује да се кључ за потпис изводи из доказиво малог или предвидљивог скупа вредности, а сервис излаже важећи пример потписа, потпис можда више не штити привилеговано `eval()` одредиште. Проверите тачно извођење кључа и верификатор, идентитет активног сервиса и локални приступ позиваоца, као и то да ли потписано поље стиже до одредишта; import Python-овог модула [`random`](https://docs.python.org/3/library/random.html) или само пример потписа не доказују ниједан од тих услова. Python такође упозорава да ограничавање `__builtins__` [није безбедносна граница за непоуздан улаз у `eval()`](https://docs.python.org/3/library/functions.html#eval). Анализу кључа обављајте offline и немојте слати фалсификоване захтеве током пасивне enumeracije.

Празан, али уписив директоријум `/etc/systemd/system/<unit>.service.d` важан је чак и када су unit фајл и сви постојећи drop-in фајлови заштићени: корисник може да направи нови `.conf` override. Проверите да ли тренутни идентитет може да уписује у директоријум и да га претражује, да ли је unit учитан и да ли се извршава као root, као и да ли ће уследити reload daemon-а па restart. Дозвола за reload или restart, timer или касније покретање система могу да активирају измену; сам приступ за упис у директоријум не извршава је одмах.

Код покренутих сервиса пратите дословне путање `EnvironmentFile=` из одељка `[Service]` unit-а, укључујући фајлове чији називи не почињу са `.env`. Ако корисник са ниским привилегијама може да прочита неки од њих, наведите имена кључева који личе на акредитиве, као што су `API_TOKEN` или `APP_SECRET_KEY`, али немојте исписивати њихове вредности у заједничке логове. При процени ефективног unit-а проверите drop-in override-е и опционе префиксе `-`. Читљивост указује на могућу изложеност акредитива; вредност и даље мора бити важећа за привилеговану радњу да би омогућила ескалацију.

### Привилегована обрада непоузданих отпремања

File watcher покренут као root може да прослеђује фајлове из уписивог upload директоријума корисника краткотрајном parser-у или extractor-у. Пратите надређену скрипту или сервис активног watcher-а и потврдите тачан директоријум, ко у њега може да поставља фајлове, команду детета и њене аргументе, као и идентитет под којим се дете извршава. Снимак процеса може да прикаже watcher, а да не ухвати extractor који ради између отпремања. Током пасивне enumeracije немојте постављати пробни payload нити покретати watcher.

Један конкретан пример је Binwalk-ов режим издвајања (`-e`) при обради PFS података које контролише нападач. [CVE-2022-4510](https://github.com/ReFirmLabs/binwalk/pull/617) је омогућавао PFS extractor-у да уписује ван предвиђеног директоријума, укључујући путању plugin-а који је Binwalk касније могао да учита. Узводно решење је обухваћено у [2.3.4](https://github.com/ReFirmLabs/binwalk/releases/tag/v2.3.4), али backport-ови дистрибуција могу да задрже старију приказану верзију; пре процене применљивости проверите безбедносни статус инсталираног пакета, на пример у [Debian пратиоцу](https://security-tracker.debian.org/tracker/CVE-2022-4510). Сама инсталирана верзија Binwalk-а не доказује путању за ескалацију привилегија: екстракцију мора заиста да покреће процес са вишим привилегијама над улазом који може да контролише корисник са нижим привилегијама.

### Заказане изградње са локалним зависностима

Заказани `cargo run` поново компајлира изворни код као корисник под чијим се идентитетом извршава посао. Прегледајте локалне зависности `{ path = "..." }` из manifest-а, као и дозволе изворног кода и надређених директоријума сваке зависности, а не само главног crate-а. Ако корисник са нижим привилегијама може да измени зависност коју Cargo компајлира, а заказани посао покреће резултат, компајлирани код може да се изврши као тај корисник. Потврдите ефективну команду планера, радни директоријум, разрешење зависности и да ли ће се обавити поновна изградња; Rust изворни фајл у који може да се уписује негде другде само је траг. За пасивну почетну процену довољно је прочитати manifest и метаподатке путања. Погледајте [Cargo документацију о зависностима по путањи](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#specifying-path-dependencies).

## Framebuffer fajlovi Xvfb

`Xvfb -fbdir <directory>` користи memory-mapped fajlove под називом `Xvfb_screen<n>` за своје виртуелне екране. Ако активни Xvfb процес другог корисника наведе директоријум чије screen фајлове тренутни корисник може да чита, framebuffer може да открије садржај радне површине тог корисника. Заједно потврдите процес, власништво над фајловима и дозволе; чињеница да је фајл читљив сама по себи не доказује да се на екрану налази користан садржај. Најпре прегледајте путање и метаподатке, без копирања сликовних података у заједнички излаз enumeracije. [Xvfb приручник](https://xorg.freedesktop.org/archive/X11R7.5/doc/man/man1/Xvfb.1.html) описује понашање опције `-fbdir`.

```bash
pgrep -a -x Xvfb
ls -l /path/from/-fbdir/Xvfb_screen*
```

## References

1. [Linux `shmget(2)` priručnik](https://man7.org/linux/man-pages/man2/shmget.2.html)
2. [Linux `ipcs(1)` priručnik](https://man7.org/linux/man-pages/man1/ipcs.1.html)
3. [OpenBSD `ipcs(1)` priručnik](https://man.openbsd.org/ipcs.1)
4. [Konfiguracija Consul agenta: provere skriptama](https://developer.hashicorp.com/consul/docs/reference/agent/configuration-file/general)
5. [API za registraciju servisa Consul agenta](https://developer.hashicorp.com/consul/api-docs/agent/service)
6. [Konfiguracija Consul ACL-a](https://developer.hashicorp.com/consul/docs/reference/agent/configuration-file/acl)
7. [Pomoć za LibreOffice: otvaranje socketa za klijente eksternog API-ja](https://help.libreoffice.org/latest/en-US/text/sbasic/shared/03/sf_intro.html)
8. [LibreOffice SDK: `XSystemShellExecute`](https://api.libreoffice.org/docs/idl/ref/interfacecom_1_1sun_1_1star_1_1system_1_1XSystemShellExecute.html)

{{#include ../../banners/hacktricks-training.md}}
