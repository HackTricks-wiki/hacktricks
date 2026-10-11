# Nabrajanje procesa i putanje servisa

{{#include ../../banners/hacktricks-training.md}}

Korisno pitanje je koji privilegovani proces koristi podatke ili kod na koje korisnik sa nižim privilegijama može da utiče. Pregledajte stablo procesa, aktivno okruženje, otvorene datoteke i jedinicu ili skriptu koja je pokrenula svakog kandidata.

## Mapiranje procesa i vlasništva

```bash
ps -eo user,pid,ppid,tty,comm,args --sort=ppid
pstree -alp 2>/dev/null
systemctl list-units --type=service --state=running 2>/dev/null
ss -lntup
```

Odnos roditeljskog i podređenog procesa između različitih korisnika može biti uobičajen, ali neočekivana promena zahteva proveru roditeljske komande, argumenata, izvršne datoteke, radnog direktorijuma i referenciranih datoteka. Koristite [users and sessions](../user-information/user-and-session-triage.md) da biste protumačili vlasnika i kontekst prijave.

### Konzole lokalnih virtuelnih mašina

Proverite QEMU opcije `-spice` zajedno sa adresom na kojoj osluškuje. [QEMU dokumentacija](https://www.qemu.org/docs/master/system/qemu-manpage.html) navodi da `disable-ticketing` omogućava SPICE klijentima da se povežu bez autentifikacije. Listener vezan za loopback i dalje može biti dostupan drugim lokalnim korisnicima sistema. Pre nego što komandu smatrate izloženom konzolom, proverite aktivni listener, opcije autentifikacije i lokalni pristup. Kontrola konzole utiče na **guest**; pribavljanje guest naloga ili promena njegovog stanja pri pokretanju zahteva zasebne uslove na guest strani i ne daje root pristup hostu za virtuelizaciju. Tokom pasivne enumeracije, pročitajte argumente procesa i metapodatke socketa bez povezivanja sa guest-om ili njegovog ponovnog pokretanja.

Lokalno dostupan web interfejs može da izvršava kod sa nalogom svoje usluge čak i kada prva shell sesija ne može da pristupi datotekama tog naloga. Na primer, CVE-2023-0297 je uticao na obradu `/flash/addcrypted2` u pyLoad-u kada bi nepouzdani JavaScript dospeo do Js2Py-ja sa omogućenim Python importima; [ispravka upstream-a](https://github.com/pyload/pyload/commit/7d73ba7919e594d783b3411d7ddb87885aea782d) onemogućila je `pyimport`. Pre nego što proces pyLoad-a smatrate putem za eskalaciju privilegija, uporedite vlasnika pokrenutog procesa, adresu na kojoj osluškuje, izloženost krajnje tačke i instaliranu ispravku ili vendor backport. Sam naziv procesa, otvoren port ili verzija paketa ne dokazuju izloženost; pasivna enumeracija ne treba da šalje payload za izvršavanje.

### Privilegovane login shell sesije koje dele terminal

Privilegovana interaktivna shell sesija koja pokreće `su --login <user>` bez zasebnog pseudo-terminala može da ostavi terminal deljen sa login shell sesijom korisnika sa nižim privilegijama. Ako taj korisnik može da kontroliše svoju startup datoteku i kod u njoj može da koristi `TIOCSTI` za ubacivanje terminalskog unosa, taj unos može da stigne do privilegovane shell sesije kada ona nastavi rad. [Uputstvo za util-linux `su`](https://man7.org/linux/man-pages/man1/su.1.html#SECURITY_NOTES) opisuje rizik deljenog terminala i preporučuje `su --pty`/`-P` za interaktivnu upotrebu; `su -c` pokreće zasebnu sesiju bez kontrolnog terminala. Rizik zavisi od stvarne roditeljske shell sesije, odnosa terminala, ciljne startup datoteke i politike kernela. Sam naziv procesa ili argument `su -l` samo ukazuje na potrebu za proverom.

Pregledajte uočeno stablo procesa i TTY kolone, a zatim proverite čitljivi launcher i vlasništvo/dozvole startup datoteke. U Linux-u, `/proc/sys/dev/tty/legacy_tiocsti` može pomoći u tumačenju politike kada postoji; njegovo odsustvo ne dokazuje da je sistem bezbedan. [Uputstvo za Linux `TIOCSTI`](https://man7.org/linux/man-pages/man2/TIOCSTI.2const.html) navodi da od Linux-a 6.2 ova operacija može zahtevati `CAP_SYS_ADMIN` kada je ovaj sysctl postavljen na false. Nemojte pozivati ioctl samo radi enumeracije hosta.

Nalog baze podataka ponekad može da izmeni startup datoteku ciljnog korisnika bez direktnog pristupa za pisanje u datotečni sistem. PostgreSQL server-side `COPY ... TO 'filename'` upisuje kao OS nalog servera baze podataka, ali [PostgreSQL ograničava](https://www.postgresql.org/docs/current/sql-copy.html) ovaj oblik rada sa datotekom na superkorisnike baze podataka ili uloge poput `pg_write_server_files`. Proverite i ulogu baze podataka i dozvole OS naloga servera nad datotekom; connection string aplikacije sam po sebi ne daje ovlašćenje za upis u datoteku. Pri proceni lanca, mogućnosti privilegovanog launchera i naloga baze podataka držite odvojeno.

## Pregled runtime artefakata

```bash
readlink /proc/<PID>/exe
tr '\0' ' ' </proc/<PID>/cmdline; echo
ls -l /proc/<PID>/fd 2>/dev/null
lsof -p <PID> 2>/dev/null
lsof +L1 2>/dev/null
```

Obrisani izvršni fajlovi i obrisani, ali još uvek otvoreni fajlovi ostaju referencirani dok se ne zatvori njihov poslednji deskriptor. Mogu da sačuvaju dokaze ili dostupne tajne. Okruženja procesa i memorija mogu sadržati akreditive, ali čitanje drugog procesa ograničeno je vlasništvom, opcijama montiranja `/proc`, Yama ptrace pravilima i drugim bezbednosnim kontrolama. Pogledajte [file descriptors](../main-system-information/filesystem-links-and-file-descriptors.md) i [post-exploitation credential hunting](../post-exploitation/README.md) za povezane tehnike.

Sačuvani syscall tragovi predstavljaju još jednu granicu dozvola za fajlove. [`strace` beleži argumente syscall-ova u izlazni fajl](https://man7.org/linux/man-pages/man1/strace.1.html), pa čitljiv trag argumenata [`execve`](https://man7.org/linux/man-pages/man2/execve.2.html) može otkriti lozinku koju je privilegovani posao prosledio u komandnoj liniji. Najpre utvrdite da li trenutni korisnik može da pročita konkretan trag i da li argument zaista sadrži akreditiv; za kasniji prelazak na Unix nalog potrebno je zasebno dokazati da se akreditiv tamo prihvata. Metapodaci fajla predstavljaju koristan pasivni trag, bez potrebe da se skeniraju svi tragovi ili ispisuje njihov sadržaj tokom rutinske enumeracije.

## Privilegovani soketi za kancelarijsku automatizaciju

LibreOffice i OpenOffice mogu da izlože svoj UNO API putem argumenta `--accept=socket,host=<host>,port=<port>;urp;`. Kancelarijski proces u vlasništvu root-a sa dostupnom krajnjom tačkom može omogućiti lokalnom korisniku sa nižim privilegijama da poziva API servise u bezbednosnom kontekstu tog procesa. Servis `SystemShellExecute` obuhvata operaciju za pokretanje sistemske komande. Vezivanje za loopback ograničava udaljenu dostupnost, ali soket i dalje ostaje dostupan lokalnim korisnicima, osim ako neka druga kontrola ne sprečava pristup.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
ps -eo user,args | grep -E '[s]office|[l]ibreoffice|[o]penoffice'
ss -ltn 2>/dev/null
```

Povežite vlasnika procesa, tačan argument `--accept` i trenutnu adresu i port na kojima proces sluša. Podešeni acceptor koji nije uspeo da se veže samo je naznaka; tokom pasivnog enumerisanja nemojte se povezivati na API niti ga pozivati. Izbegavajte pokretanje privilegovane instance kancelarijskog programa samo da biste testirali ovaj uslov.

## System V shared memory koju koriste privilegovani procesi

Pomoćni program u vlasništvu root korisnika može da kreira segment System V shared memory koji drugi korisnik može da menja. Ako se pomoćni program kasnije osloni na podatke iz tog segmenta u shell komandi ili drugoj osetljivoj operaciji, segment prelazi granicu privilegija čak i kada su izvršna datoteka i njene datoteke zaštićene. `shmget()` preuzima dozvole pristupa iz nižih devet bitova svojih zastavica; režim `0666` dozvoljava drugim korisnicima upis, dok zastavica `IPC_CREAT` ne ograničava te dozvole. Pasivno proverite aktivne segmente pomoću `ipcs -m` i uporedite njihovog vlasnika, režim i trajanje postojanja sa privilegovanim procesom i načinom obrade njegovih ulaznih podataka. Sam segment sa dozvolom za upis svim korisnicima ne dokazuje izvršavanje komandi.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
ipcs -m
```

System V segmenti se razlikuju od POSIX datoteka za deljenu memoriju u `/dev/shm`. Segment kreiran samo na trenutak možda neće biti prisutan u pojedinačnom `ipcs` snimku, zato prazan izlaz ne isključuje mogućnost da pomoćni program koristi deljenu memoriju. Pregledajte njegov izvorni kod ili ponašanje binarne datoteke, kao i sva `sudo` pravila koja ga pokreću; nemojte pozivati privilegovani pomoćni program samo da bi se segment pojavio tokom enumeracije. [Vodič za IPC namespace](../containers-namespaces/container-security/protections/namespaces/ipc-namespace.md) objašnjava kako namespace-ovi utiču na vidljivost.<sup>[[2]](#references)[[3]](#references)</sup>

## Consul agent provere skriptama

Consul može da pokreće skriptne provere ispravnosti sa identitetom operativnog sistema svog agenta. Ako agent radi kao root, ima omogućeno `enable_script_checks` i korisniku sa nižim privilegijama dozvoljava da preko lokalnog HTTP API-ja registruje servis sa skriptnom proverom, taj korisnik može da izazove pokretanje komandi kao root. Čak i kada je API vezan samo za `127.0.0.1`, lokalni korisnici i dalje mogu da mu pristupe. Postavka `enable_local_script_checks` je užeg opsega: isključuje skriptne provere poslate putem registracije kroz HTTP API. Kada su Consul ACL-ovi omogućeni, za registraciju servisa potreban je `service:write`; sama linija `acl.default_policy=allow` ne dokazuje da anonimni pozivalac može da registruje servis. Zajedno proverite stvarni identitet agenta, učitane postavke, vezivanje API-ja i autorizaciju.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

```bash
ps -eo user,args | grep '[c]onsul agent'
ls -l /etc/consul.d 2>/dev/null
```

Pratite argumente `-config-dir` i `-config-file` prosleđene pokrenutom agentu do odgovarajuće konfiguracije i pregledajte samo nazive polja i podešavanja za script-check i ACL. Konfiguracione datoteke mogu sadržati i gossip ključeve ili tokene; izbegavajte da ih objavljujete u zajedničkim zapisnicima. Nemojte registrovati servis niti pokretati proveru ispravnosti samo da biste utvrdili da li ovaj uslov postoji.

Postoji zaseban put preko lokalne datoteke kada korisnik sa nižim privilegijama može da **piše u direktorijum** koji je naveden argumentom `-config-dir` agenta pokrenutog kao root i da ga **pretražuje**: iz tog direktorijuma može da se učita nova definicija servisa `.hcl` ili `.json`. Dozvole za pretraživanje i pisanje u direktorijumu mogu omogućiti dodavanje datoteke čak i kada je pregled sadržaja direktorijuma zabranjen. Da biste potvrdili izvršavanje komandi kao root, proverite da agent действительно учитава тај директоријум, да његово **efektivno** podešavanje za script-check dozvoljava lokalne definicije, da je definicija učitana i da agent zadržava privilegije root-a. [Consul dokumentuje](https://developer.hashicorp.com/consul/docs/fundamentals/agent#reloadable-configurations) koja podešavanja i definicije provera ispravnosti mogu ponovo da se učitaju; omogućavanje provera skriptom može zahtevati ponovno pokretanje, zato proverite ponašanje instalirane verzije. Kada ACL-ovi štite agenta, [`consul reload` zahteva `agent:write`](https://developer.hashicorp.com/consul/api-docs/agent#reload-agent); dozvola za pisanje u KV sama po sebi ne obezbeđuje tu dozvolu. Tretirajte metapodatke o dozvolama direktorijuma kao povod za proveru, a ne kao dokaz da je ponovno učitavanje, ponovno pokretanje ili izvršavanje komandi odobreno. Pregledajte putanje, dozvole i politiku bez upisivanja konfiguracije ili pozivanja API-ja.

## Pratite lanac izvršavanja servisa

```bash
systemctl cat <unit>.service
systemctl show <unit>.service -p User -p Group -p ExecStart -p EnvironmentFiles -p WorkingDirectory
namei -l /path/from/ExecStart
```

Proverite unit, drop-ins, `EnvironmentFile=`, pomoćne skripte, relativne komande, direktorijume u koje može da se upisuje i aktivaciju preko socket-a. Unit u vlasništvu root-a i dalje može biti nebezbedan ako čita konfiguraciju ili skriptu u koju korisnik može da upisuje. Stranica o [arbitrary file write](../interesting-files-permissions/write-to-root.md) pokriva uobičajene načine zloupotrebe servisa i unit-a. Kratkotrajne poslove pratite pomoću [pspy](https://github.com/DominicBreuker/pspy) ili audit/procesne telemetrije ako ih jednokratni listing komande `ps` ne prikaže.

Za prilagođeni **xinetd** servis povežite aktivnu stavku `server`, `user` i kontrole pristupa sa aktivnim listener-om i tačnom izvršnom datotekom. Postavka [`user`](https://manpages.debian.org/testing/xinetd/xinetd.conf.5.en.html) određuje identitet procesa koji se pokreće, dok set-user-ID bit na izvršnoj datoteci može zasebno da promeni njen efektivni identitet ako [`execve` dozvoljava taj prelaz](https://man7.org/linux/man-pages/man2/execve.2.html). Privilegovana dostupna binarna datoteka koja prihvata nepouzdan ulaz zaslužuje offline pregled izvornog koda ili disasembliranog koda radi otkrivanja grešaka u bezbednosti memorije, kao što je neograničena [`scanf` konverzija stringa](https://www.gnu.org/software/libc/manual/html_node/String-Input-Conversions.html) u bafer fiksne veličine. Mapiranje servisa i set-user-ID metapodaci samo su naznake, a ne dokaz postojanja takve greške; tokom pasivne enumeracije nemojte slati ulaze koji izazivaju pad niti debagovati aktivni privilegovani servis.

Ako je izvorni kod prilagođenog privilegovanog listener-a čitljiv, pregledajte svaku dužinu koju kontroliše pozivalac i koja se koristi u operaciji kopiranja, kao što je [`memcpy`](https://man7.org/linux/man-pages/man3/memcpy.3.html). Provera da li je trenutni indeks upisa unutar fiksnog bafera ne dokazuje da se **dužina kopiranja** uklapa u preostali prostor; nakon provere da li je indeks u opsegu, proverite `copy_length <= capacity - index`, kao i predznak i prekoračenje pri računanju. Ovo je samo smernica za pregled ako ulaz dospeva do te operacije, listener je dostupan korisniku sa nižim privilegijama, a proces zadržava viši efektivni identitet. Izvorni kod i metapodatke procesa pregledajte offline; tokom enumeracije nemojte slati ulaze koji izazivaju pad aktivnom servisu.

Na sistemima koji koriste **Upstart**, definicije sistemskih poslova mogu se nalaziti pod `/etc/init/*.conf`. Datoteka posla u koju trenutni korisnik može da upisuje važna je ako aktivni init daemon učitava baš taj posao, njegova stavka `script` ili `exec` se izvršava pod identitetom sa višim privilegijama, a korisnik može da ga pokrene dozvoljenom komandom `initctl` ili drugim stvarnim okidačem. Sama sudo dozvola za `initctl` ne dokazuje da je neka datoteka posla upisiva niti da će izmenjeni posao biti pokrenut. Proverite dozvole tačne datoteke posla, efektivno podešavanje naloga za izvršavanje, aktivni daemon i okidač, bez izmene ili pokretanja posla tokom enumeracije. Pogledajte priručnike za [konfiguraciju Upstart posla](https://manpages.ubuntu.com/manpages/trusty/man5/init.5.html) i [`initctl`](https://manpages.ubuntu.com/manpages/xenial/man8/initctl.8.html).

Čitljiva datoteka sa lozinkom za automatsku prijavu, kao što je `/etc/autologin/passwd` na sistemima čiji [boot posao čita baš tu putanju](https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/master/chromeos-base/autologin/files/init/autologin.conf), ukazuje na moguće izlaganje akreditiva. Potvrdite da je boot posao instaliran i da koristi tu datoteku, a zatim odvojeno proverite da li je lozinka važeća za neki drugi lokalni nalog ili servis. Sam naziv datoteke ne dokazuje ponovnu upotrebu lozinke; zabeležite putanju i metapodatke o pristupu, ali nemojte unositi lozinku u zajednički izlaz enumeracije.

`ExecStart=` u unit-u ili zakazana komanda mogu otkriti tačnu putanju skripte unutar direktorijuma čiji sadržaj ne može da se izlista. [Dozvola za pretragu direktorijuma](https://man7.org/linux/man-pages/man7/path_resolution.7.html) i dalje može da omogući trenutnom identitetu prolaz kroz poznatu putanju; proverite dozvolu za pretragu na svakom nadređenom direktorijumu i dozvolu za čitanje datoteke, umesto da pretpostavite da je listing neuspeo pa je datoteka zaštićena. Čitljiva skripta može da sadrži akreditive za pristup drugom sistemu, ali prelazak na drugi nalog zahteva da ti akreditivi i dalje važe i da budu nezavisno prihvaćeni na tom nalogu. Zabeležite putanju i dokaze o dozvolama, ali nemojte ispisivati tajne vrednosti u zajedničke logove.

Kod zakazane CommonJS Node.js skripte pregledajte gole importe kao što je `require('package')` čak i kada je sama skripta samo za čitanje. [Node traži `node_modules` pored datoteke koja obavlja import, a zatim u njenim nadređenim direktorijumima](https://nodejs.org/api/modules.html#loading-from-node_modules-folders), pre nego što pređe na konfigurisane globalne putanje. Korisnik sa nižim privilegijama koji može da **upisuje u jedan od tih nadređenih direktorijuma i da ga pretražuje** možda može da napravi paket koji će biti pronađen ranije. Potvrdite da se dotični import zaista izvršava, da izabrani paket nije ugrađeni modul, da se relevantna putanja može kreirati ili menjati, da se modul razrešava na toj putanji u instaliranom runtime-u i da će ga posao sa višim privilegijama učitati pri nekom budućem pokretanju. Metapodaci o upisivom nadređenom direktorijumu samo su povod za pregled; skriptu i raspoređivač pregledajte pasivno, bez postavljanja modula ili pokretanja posla.

Privatni Python indeks paketa predstavlja još jednu granicu poverenja kada automatizovani posao instalira pakete pod drugim OS identitetom. Povežite tačan posao i nalog pod kojim se izvršava sa konfigurisanim indeksom, izabranim nazivima paketa i proverom da li korisnik sa nižim privilegijama može da objavi ili zameni paket koji će posao zaista instalirati. Izgradnja source distribution-a može da pokrene njegov backend za izgradnju ili zastарели `setup.py` под идентитетом инсталационог процеса; увоз инсталираног пакета је засебан пут извршавања. Listener индекса, читљив hash лозинке за отпремање или сам назив датотеке пакета не доказују тај ланац. Прегледајте посао, овлашћења на индексу и порекло пакета, без отпремања или инсталирања било чега током енумерације. Погледајте [интерфејс за изградњу у pip-у](https://pip.pypa.io/en/stable/reference/build-system/) и [смернице за безбедну инсталацију](https://pip.pypa.io/en/stable/topics/secure-installs/).

Привилеговани агент може да проверава ред задатака којим управља засебан веб-сервис или container. Ако идентитет са нижим нивоом поверења може да уписује у базу података са задацима тог сервиса, утврдите да ли се ти редови заиста испоручују агенту и да ли се командни задатак покреће под OS идентитетом агента. Одвојено потврдите приступ за упис у базу података, циљну сесију или кључ за рутирање, активно преузимање задатака, овлашћења за задатке и ефективног корисника агента. Root унутар container-а сам по себи не подразумева приступ host-у као root; граница се прелази само ако потрошач са привилегијама на host-у изврши податке задатка под контролом нападача. Прегледајте метаподатке процеса, датотеке базе података и сервиса, без измене реда или слања задатка током енумерације.

Уместо тога, периодични посао може да чита команду из реда конфигурације у бази података апликације. Потврдите да улога базе података са нижим привилегијама може да измени баш тај ред, да активни посао чита вредност после измене и да се вредност прослеђује shell-у или еквивалентном покретачу команди под OS идентитетом са вишим привилегијама. Приступ за упис у базу података или вредност која личи на команду сами по себи не доказују извршавање; прегледајте посао и дозволе без измене реда током пасивне енумерације.

Порука у реду може да садржи и URL, а не код. Ако привилеговани потрошач преузима тај URL и учитава одговор као Lua или други извршни plugin, проверите дозволе пошиљаоца за тачан exchange и routing key, везу са редом који се чита, пут преузимања и учитавања plugin-а и ефективни идентитет worker-а. [RabbitMQ усмерава објављене поруке кроз exchange-ове](https://www.rabbitmq.com/docs/exchanges); listener брокера или важећа пријава сами по себи не доказују да ће порука бити испоручена овом worker-у. Пресретнути акредитиви брокера у чистом тексту представљају засебан траг који захтева стварни приступ packet capture-у и читљив саобраћај; они не доказују овлашћење за објављивање. Lua plugin може да покреће shell команде преко [`os.execute`](https://www.lua.org/manual/5.4/manual.html#pdf-os.execute) само ако је тај API доступан у његовом runtime-у. Прегледајте конфигурацију и код без пресретања саобраћаја, објављивања порука или преузимања plugin-а током пасивне енумерације.

Када привилеговани Python сервис излаже локални HTTP или socket крајњи део, читљива скрипта може да открије пут од улаза до кода чак и ако дозволе датотеке онемогућавају њену измену. Повежите активни процес и идентитет unit-а са тачном скриптом, listener-ом, овлашћењима за руту и пољима под контролом позиваоца. Затим пратите та поља кроз парсирање и валидацију до динамичког sink-а `eval()` или `exec()`. Конкретно, креирање новог f-string-а од текста захтева и његова евалуација могу да протумаче поља за замену, које је унео нападач, као Python изразе ([Python упозорење о `eval`](https://docs.python.org/3/library/functions.html#eval); [семантика f-string-а](https://docs.python.org/3/reference/lexical_analysis.html#f-strings)). Само појављивање `eval` или везивање за loopback не доказују да непоуздан позивалац може да досегне sink; прегледајте стварни ток података и контроле приступа, без слања пробног payload-а током енумерације.

Gate за потписани захтев на тој рути захтева посебан преглед. Ако читљив изворни код изводи кључ за потписивање из доказиво малог или предвидивог скупа могућих вредности, а сервис излаже важећи потписани пример, потпис можда више не штити привилеговани sink `eval()`. Проверите тачан начин извођења кључа и verifier, идентитет активног сервиса и приступ локалног позиваоца, као и то да ли потписано поље досеже sink; import Python [`random` модула](https://docs.python.org/3/library/random.html) или сам пример потписа ништа од тога не доказују. Python такође упозорава да ограничавање `__builtins__` [није безбедносна граница за непоуздан улаз у `eval()`](https://docs.python.org/3/library/functions.html#eval). Анализу кључа обављајте offline и немојте слати фалсификоване захтеве током пасивне енумерације.

Празан, али уписив директоријум `/etc/systemd/system/<unit>.service.d` је важан чак и када су unit датотека и сви постојећи drop-in-ови заштићени: корисник може да направи нови `.conf` override. Проверите да ли тренутни идентитет може да уписује у директоријум и да га претражује, да ли је unit учитан и да ли се покреће као root, као и да ли ће уследити поновно учитавање daemon-а, а затим рестарт. Дозвола за поновно учитавање или рестарт, timer или касније покретање система могу да активирају измену; сам приступ за упис у директоријум не покреће је одмах.

Код активних сервиса пратите дословне путање `EnvironmentFile=` из одељка `[Service]` unit-а, укључујући датотеке чија имена не почињу са `.env`. Ако корисник са ниским привилегијама може да прочита неку од њих, наведите називе кључева који личе на акредитиве, као што су `API_TOKEN` или `APP_SECRET_KEY`, али немојте исписивати вредности у заједничке логове. При процени ефективног unit-а проверите override-е у drop-in-овима и опционе префиксе `-`. Читљивост указује на могуће излагање акредитива; вредност и даље мора да буде важећа за привилеговану радњу да би довела до ескалације.

### Привилегована обрада непоузданих отпремљених датотека

File watcher који ради као root може да прослеђује датотеке из upload директоријума у који корисник може да уписује краткотрајном parser-у или extractor-у. Пратите родитељску скрипту или сервис активног watcher-а и потврдите тачан директоријум, ко може да поставља датотеке, child команду и њене аргументе, као и идентитет под којим се child покреће. Снимак процеса може да прикаже watcher, а да не ухвати extractor између отпремања. Током пасивне енумерације немојте постављати пробни payload нити покретати watcher.

Један конкретан пример је Binwalk-ов режим издвајања (`-e`) који обрађује PFS податке под контролом нападача. [CVE-2022-4510](https://github.com/ReFirmLabs/binwalk/pull/617) је омогућавао PFS extractor-у да уписује ван предвиђеног директоријума, укључујући путању plugin-а који је Binwalk касније могао да учита. Узводни пројекат је укључио исправку у верзију [2.3.4](https://github.com/ReFirmLabs/binwalk/releases/tag/v2.3.4), али backport-ови дистрибуција могу да задрже приказ старе верзије; пре процене применљивости проверите безбедносни статус инсталираног пакета, на пример у [Debian tracker-у](https://security-tracker.debian.org/tracker/CVE-2022-4510). Сама инсталирана верзија Binwalk-а не доказује постојање пута за ескалацију привилегија: процес са вишим привилегијама мора заиста да покрене издвајање над улазом који корисник са нижим привилегијама може да контролише.

### Zakazane izgradnje sa lokalnim zavisnostima

Zakazani `cargo run` ponovo kompajlira izvorni kod pod nalogom pod kojim se posao izvršava. Pregledajte lokalne zavisnosti iz manifesta u obliku `{ path = "..." }` i dozvole nad izvornim kodom i nadređenim direktorijumima svake zavisnosti, a ne samo nad glavnim crate-om. Ako korisnik sa nižim privilegijama može da izmeni zavisnost koju Cargo kompajlira, a zakazani posao pokreće rezultat, kompajlirani kod može da se izvršava kao taj nalog. Potvrdite efektivnu komandu raspoređivača, radni direktorijum, razrešavanje zavisnosti i da li će doći do ponovne izgradnje; Rust izvorni fajl koji može da se menja na nekom drugom mestu samo je naznaka. Za pasivnu trijažu dovoljno je pročitati manifest i metapodatke putanje. Pogledajte [dokumentaciju za Cargo zavisnosti navedene putanjom](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#specifying-path-dependencies).

## Xvfb framebuffer datoteke

`Xvfb -fbdir <directory>` koristi memory-mapped datoteke nazvane `Xvfb_screen<n>` za svoje virtuelne ekrane. Ako aktivni Xvfb proces drugog korisnika navodi direktorijum čije su datoteke ekrana čitljive trenutnom korisniku, framebuffer može da otkrije sadržaj radne površine tog korisnika. Zajedno potvrdite proces, vlasništvo nad datotekama i dozvole; sama čitljivost datoteke ne dokazuje da se na ekranu nalazi koristan sadržaj. Najpre pregledajte putanje i metapodatke, bez kopiranja slikovnih podataka u zajednički izlaz enumeracije. [Xvfb priručnik](https://xorg.freedesktop.org/archive/X11R7.5/doc/man/man1/Xvfb.1.html) opisuje ponašanje opcije `-fbdir`.

```bash
pgrep -a -x Xvfb
ls -l /path/from/-fbdir/Xvfb_screen*
```

## References

1. [Linux `shmget(2)` priručnik](https://man7.org/linux/man-pages/man2/shmget.2.html)
2. [Linux `ipcs(1)` priručnik](https://man7.org/linux/man-pages/man1/ipcs.1.html)
3. [OpenBSD `ipcs(1)` priručnik](https://man.openbsd.org/ipcs.1)
4. [Consul agent konfiguracija: provere skripti](https://developer.hashicorp.com/consul/docs/reference/agent/configuration-file/general)
5. [Consul agent API za registraciju servisa](https://developer.hashicorp.com/consul/api-docs/agent/service)
6. [Consul ACL konfiguracija](https://developer.hashicorp.com/consul/docs/reference/agent/configuration-file/acl)
7. [LibreOffice pomoć: otvaranje soketa za klijente spoljnog API-ja](https://help.libreoffice.org/latest/en-US/text/sbasic/shared/03/sf_intro.html)
8. [LibreOffice SDK: `XSystemShellExecute`](https://api.libreoffice.org/docs/idl/ref/interfacecom_1_1sun_1_1star_1_1system_1_1XSystemShellExecute.html)

{{#include ../../banners/hacktricks-training.md}}
