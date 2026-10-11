# Enumeracija procesa i putanje servisa

{{#include ../../banners/hacktricks-training.md}}

Važno je utvrditi koji privilegovani proces koristi podatke ili kod na koje korisnik sa nižim privilegijama može da utiče. Pregledajte stablo procesa, aktivno okruženje, otvorene datoteke i jedinicu ili skriptu koja je pokrenula svaki od kandidata.

## Mapiranje procesa i vlasništva

```bash
ps -eo user,pid,ppid,tty,comm,args --sort=ppid
pstree -alp 2>/dev/null
systemctl list-units --type=service --state=running 2>/dev/null
ss -lntup
```

Odnos roditeljskog i podređenog procesa između različitih korisnika može biti normalan, ali neočekivan prelaz zahteva proveru roditeljske komande, argumenata, izvršne datoteke, radnog direktorijuma i referenciranih datoteka. Koristite [users and sessions](../user-information/user-and-session-triage.md) da biste protumačili vlasnika i kontekst prijave.

### Konzole lokalnih virtuelnih mašina

Proverite `-spice` opcije QEMU procesa zajedno sa adresom na kojoj sluša. [QEMU dokumentacija](https://www.qemu.org/docs/master/system/qemu-manpage.html) navodi da `disable-ticketing` omogućava SPICE klijentima da se povežu bez autentifikacije. Listener vezan za loopback i dalje mogu potencijalno da dohvate drugi lokalni korisnici hosta. Pre nego što komandu tretirate kao izloženu konzolu, proverite aktivni listener, opcije autentifikacije i lokalni pristup. Kontrola konzole utiče na **guest**; dobijanje guest naloga ili promena njegovog stanja pri pokretanju zahteva zasebne uslove na guest strani i ne daje root pristup hostu za virtuelizaciju. Tokom pasivne enumeracije čitajte argumente procesa i metapodatke soketa, ali se nemojte povezivati sa guest sistemom niti ga ponovo pokretati.

Lokalno dostupan veb-interfejs može da izvršava kod sa nalogom servisnog procesa čak i kada prva shell sesija ne može da pristupi datotekama tog naloga. Na primer, CVE-2023-0297 uticao je na obradu putanje `/flash/addcrypted2` u pyLoad-u kada bi nepouzdani JavaScript dospeo do Js2Py-a sa omogućenim Python importima; [ispravka iz upstream-a](https://github.com/pyload/pyload/commit/7d73ba7919e594d783b3411d7ddb87885aea782d) onemogućila je `pyimport`. Pre nego što pyLoad proces tretirate kao putanju za eskalaciju, uporedite vlasnika pokrenutog procesa, adresu na kojoj sluša, izloženost krajnje tačke i instaliranu zakrpu ili ispravku koju je preneo dobavljač. Sam naziv procesa, otvoren port ili verzija paketa ne dokazuju izloženost; pasivna enumeracija ne bi trebalo da šalje payload za izvršavanje.

### Privilegovane login shell sesije koje dele terminal

Privilegovana interaktivna shell sesija koja pokrene `su --login <user>` bez nezavisnog pseudo-terminala može da ostavi terminal deljen sa login shell sesijom korisnika sa nižim privilegijama. Ako korisnik može da kontroliše njegovu startup datoteku i kod u njoj može da koristi `TIOCSTI` za ubacivanje ulaza u terminal, taj ulaz može da stigne do privilegovane shell sesije kada nastavi rad. [Priručnik za util-linux `su`](https://man7.org/linux/man-pages/man1/su.1.html#SECURITY_NOTES) opisuje rizik deljenog terminala i preporučuje `su --pty`/`-P` za interaktivnu upotrebu; `su -c` pokreće zasebnu sesiju bez kontrolnog terminala. Rizik zavisi od stvarne roditeljske shell sesije, odnosa sa terminalom, ciljne startup datoteke i politike kernela. Sam naziv procesa ili argument `su -l` samo je razlog za dodatnu proveru.

Pregledajte uočeno stablo procesa i TTY kolone, a zatim i dozvole čitljivog pokretača i vlasništvo/dozvole startup datoteke. Na Linuxu, `/proc/sys/dev/tty/legacy_tiocsti` može pomoći u tumačenju politike ako postoji; njegovo odsustvo ne dokazuje da je sistem bezbedan. [Priručnik za Linux `TIOCSTI`](https://man7.org/linux/man-pages/man2/TIOCSTI.2const.html) navodi da od Linuxa 6.2 ova operacija može zahtevati `CAP_SYS_ADMIN` kada je ovaj sysctl postavljen na false. Nemojte pozivati ioctl samo radi enumeracije hosta.

Nalog baze podataka ponekad može da izmeni startup datoteku ciljnog korisnika bez direktnog pristupa za upis u sistem datoteka. PostgreSQL server-side `COPY ... TO 'filename'` upisuje kao OS nalog servera baze podataka, ali [PostgreSQL ograničava](https://www.postgresql.org/docs/current/sql-copy.html) ovaj oblik datoteke na superkorisnike baze podataka ili uloge kao što je `pg_write_server_files`. Proverite i ulogu baze podataka i dozvole OS naloga servera nad datotekom; connection string aplikacije sam po sebi ne daje ovlašćenje za upis u datoteku. Pri proceni lanca, mogućnosti privilegovanog pokretača i naloga baze podataka posmatrajte odvojeno.

## Pregled artefakata tokom izvršavanja

```bash
readlink /proc/<PID>/exe
tr '\0' ' ' </proc/<PID>/cmdline; echo
ls -l /proc/<PID>/fd 2>/dev/null
lsof -p <PID> 2>/dev/null
lsof +L1 2>/dev/null
```

Obrisani izvršni fajlovi i obrisani, ali i dalje otvoreni fajlovi ostaju referencirani dok se ne zatvori njihov poslednji deskriptor. Mogu da sačuvaju dokaze ili dostupne tajne. Okruženje procesa i memorija mogu sadržati akreditive, ali čitanje drugog procesa ograničavaju vlasništvo, opcije montiranja `/proc`, Yama ptrace politika i druge bezbednosne kontrole. Pogledajte [file descriptors](../main-system-information/filesystem-links-and-file-descriptors.md) i [post-exploitation credential hunting](../post-exploitation/README.md) za povezane tehnike.

Sačuvani syscall trace-ovi predstavljaju još jednu granicu dozvola za fajlove. [`strace` beleži argumente syscall-ova u izlazni fajl](https://man7.org/linux/man-pages/man1/strace.1.html), pa čitljiv trace argumenata za [`execve`](https://man7.org/linux/man-pages/man2/execve.2.html) može otkriti lozinku koju je privilegovani job prosledio u komandnoj liniji. Najpre utvrdite da li trenutni korisnik može da pročita konkretan trace i da li argument zaista sadrži akreditive; za kasniji prelazak na drugi Unix nalog potrebno je zasebno dokazati da se akreditivi tamo prihvataju. Metapodaci fajla predstavljaju koristan pasivan trag, bez skeniranja svih trace-ova ili prikazivanja njihovog sadržaja tokom rutinskog enumerisanja.

## Privilegovani socket-i za office automatizaciju

LibreOffice i OpenOffice mogu da izlože svoj UNO API putem argumenta `--accept=socket,host=<host>,port=<port>;urp;`. Office proces čiji je vlasnik root i koji ima dostupan endpoint može korisniku sa nižim privilegijama na lokalnom sistemu omogućiti da poziva API servise u bezbednosnom kontekstu tog procesa. Servis `SystemShellExecute` uključuje operaciju za pokretanje sistemske komande. Vezivanje za loopback ograničava udaljenu dostupnost, ali socket i dalje ostaje dostupan lokalnim korisnicima, osim ako neka druga kontrola ne sprečava pristup.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
ps -eo user,args | grep -E '[s]office|[l]ibreoffice|[o]penoffice'
ss -ltn 2>/dev/null
```

Povežite vlasnika procesa, tačan argument `--accept` i trenutnu adresu i port na kojima se osluškuje. Konfigurisani prihvatnik koji nije uspeo da se veže za adresu predstavlja samo trag; tokom pasivnog enumerisanja nemojte se povezivati sa API-jem niti ga pozivati. Nemojte pokretati privilegovanu instancu office aplikacije samo da biste testirali ovo stanje.

## System V deljena memorija koju koriste privilegovani procesi

Pomoćni program u vlasništvu root-a može da kreira segment System V deljene memorije u koji drugi korisnik može da upisuje. Ako pomoćni program kasnije veruje podacima iz tog segmenta u shell komandi ili drugoj osetljivoj operaciji, segment prelazi granicu privilegija čak i kada su izvršna datoteka i njeni fajlovi zaštićeni. `shmget()` preuzima dozvole pristupa iz nižih devet bitova svojih zastavica; režim `0666` dozvoljava drugim korisnicima upisivanje, dok zastavica `IPC_CREAT` ne ograničava te dozvole. Pasivno pregledajte aktivne segmente pomoću `ipcs -m` i povežite njihovog vlasnika, režim i životni vek sa privilegovanim procesom i načinom obrade njegovih ulaznih podataka. Sam po sebi, segment sa dozvolom upisivanja za sve ne dokazuje izvršavanje komandi.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
ipcs -m
```

System V segmenti se razlikuju od POSIX datoteka za deljenu memoriju u direktorijumu `/dev/shm`. Segment kreiran samo na trenutak možda neće biti prisutan u pojedinačnom `ipcs` snimku, pa prazan izlaz ne isključuje mogućnost da pomoćni program koristi deljenu memoriju. Pregledajte njegov izvorni kôd ili ponašanje binarne datoteke, kao i svako `sudo` pravilo koje je pokreće; nemojte pozivati pomoćni program sa privilegijama samo da bi se segment pojavio tokom enumeracije. [Vodič za IPC imenske prostore](../containers-namespaces/container-security/protections/namespaces/ipc-namespace.md) objašnjava kako imenski prostori utiču na vidljivost.<sup>[[2]](#references)[[3]](#references)</sup>

## Provere skripti Consul agenta

Consul može da pokreće skriptne provere ispravnosti sa identitetom operativnog sistema koji koristi njegov agent. Ako se agent pokreće kao root, omogućen je `enable_script_checks`, a korisniku sa nižim privilegijama je dozvoljeno da registruje uslugu sa skriptnom proverom preko lokalnog HTTP API-ja, taj korisnik može da pokrene komande koje se izvršavaju kao root. Čak i ako je API vezan samo za `127.0.0.1`, lokalni korisnici i dalje mogu da mu pristupe. Podešavanje `enable_local_script_checks` je uže: ono isključuje skriptne provere poslate putem registracija kroz HTTP API. Kada su Consul ACL-ovi omogućeni, za registraciju usluge je potreban `service:write`; sama linija `acl.default_policy=allow` ne dokazuje da anonimni pozivalac može da registruje uslugu. Zajedno proverite stvarni identitet agenta, učitana podešavanja, vezivanje API-ja i autorizaciju.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

```bash
ps -eo user,args | grep '[c]onsul agent'
ls -l /etc/consul.d 2>/dev/null
```

Pratite argumente `-config-dir` i `-config-file` pokrenutog agenta da biste pronašli odgovarajuću konfiguraciju, a zatim pregledajte samo nazive i postavke polja za script-check i ACL. Konfiguracione datoteke mogu sadržati i gossip ključeve ili tokene; nemojte ih lepiti u deljene logove. Nemojte registrovati servis niti pokretati health check samo da biste utvrdili da li ovo stanje postoji.

Postoji i zaseban put preko lokalnih datoteka kada korisnik sa nižim privilegijama može **da upisuje u direktorijum koji je naveden u argumentu `-config-dir` agenta pokrenutog kao root i da ga pretražuje**: iz tog direktorijuma može da se učita nova definicija servisa `.hcl` ili `.json`. Dozvole za pretraživanje i upisivanje u direktorijum mogu omogućiti dodavanje datoteke čak i kada je pregled sadržaja direktorijuma zabranjen. Za izvršavanje komandi kao root, potvrdite da agent zaista učitava taj direktorijum, da njegova **efektivna** postavka za script-check dozvoljava lokalne definicije, da je definicija učitana i da agent zadržava root privilegije. [Consul dokumentuje](https://developer.hashicorp.com/consul/docs/fundamentals/agent#reloadable-configurations) koje postavke i definicije health check-a mogu ponovo da se učitaju; za samo omogućavanje script check-ova može biti potrebno ponovno pokretanje, zato proverite ponašanje instalirane verzije. Kada ACL-ovi štite agenta, [`consul reload` zahteva `agent:write`](https://developer.hashicorp.com/consul/api-docs/agent#reload-agent); sama dozvola za upis u KV ne obezbeđuje je. Tretirajte mogućnost upisa u metapodatke direktorijuma kao povod za proveru, a ne kao dokaz da je dozvoljeno ponovno učitavanje, ponovno pokretanje ili izvršavanje komandi. Pregledajte putanje, dozvole i pravila bez upisivanja konfiguracije i bez pozivanja API-ja.

## Pratite lanac izvršavanja servisa

```bash
systemctl cat <unit>.service
systemctl show <unit>.service -p User -p Group -p ExecStart -p EnvironmentFiles -p WorkingDirectory
namei -l /path/from/ExecStart
```

Proverite unit, drop-ins, `EnvironmentFile=`, pomoćne skripte, relativne komande, direktorijume u koje može da se upisuje i aktivaciju soketa. Unit u vlasništvu root-a i dalje može biti nebezbedan ako čita konfiguraciju ili skriptu u koju korisnik može da upisuje. Stranica o [arbitrary file write](../interesting-files-permissions/write-to-root.md) pokriva uobičajene načine zloupotrebe servisa i unit-a. Kratkotrajne poslove pratite pomoću [pspy](https://github.com/DominicBreuker/pspy) ili audit/procesne telemetrije ako ih jednokratni `ps` listing ne obuhvati.

Kod prilagođenog **xinetd** servisa uporedite omogućenu stavku `server`, `user` i kontrole pristupa sa aktivnim listener-om i tačnim izvršnim fajlom. Postavka [`user`](https://manpages.debian.org/testing/xinetd/xinetd.conf.5.en.html) određuje identitet procesa koji se pokreće, dok set-user-ID bit na izvršnom fajlu može zasebno da promeni njegov efektivni identitet ako [`execve` dozvoljava tu promenu](https://man7.org/linux/man-pages/man2/execve.2.html). Dostupan privilegovani binarni fajl koji prihvata nepouzdan unos treba offline pregledati kroz izvorni kod ili disasembliranje, tražeći greške u memorijskoj bezbednosti, kao što je neograničena [`scanf` konverzija stringa](https://www.gnu.org/software/libc/manual/html_node/String-Input-Conversions.html) u bafer fiksne veličine. Mapiranje servisa i set-user-ID metapodaci predstavljaju tragove, a ne dokaz takve greške; nemojte slati ulaze koji izazivaju pad niti debagovati aktivni privilegovani servis tokom pasivnog enumerisanja.

Kod prilagođenog privilegovanog listener-a sa čitljivim izvornim kodom pregledajte svaku dužinu koju kontroliše pozivalac, a koja se koristi u operaciji kopiranja kao što je [`memcpy`](https://man7.org/linux/man-pages/man3/memcpy.3.html). Provera da li je trenutni indeks upisa unutar bafera fiksne veličine ne dokazuje da **dužina kopiranja** staje u preostali prostor; proverite `copy_length <= capacity - index` nakon što potvrdite da je indeks u opsegu, kao i predznak i prekoračenje pri aritmetičkim operacijama. Ovo je samo trag za pregled i relevantno je jedino ako unos stiže do te operacije, listener je dostupan korisniku sa nižim privilegijama, a proces zadržava viši efektivni identitet. Pregledajte izvorni kod i metapodatke procesa offline; nemojte slati ulaze koji izazivaju pad aktivnom servisu tokom enumerisanja.

Na sistemima koji koriste **Upstart**, definicije sistemskih poslova mogu se nalaziti u direktorijumu `/etc/init/*.conf`. Fajl posla u koji trenutni korisnik može da upisuje važan je ako aktivni init daemon učitava baš taj posao, njegova `script` ili `exec` stavka se izvršava pod identitetom sa višim privilegijama, a korisnik može da ga pokrene dozvoljenom `initctl` komandom ili nekim drugim stvarnim okidačem. Sama sudo dozvola za `initctl` ne dokazuje da je ijedan fajl posla upisiv niti da će izmenjeni posao biti pokrenut. Proverite dozvole tačnog fajla posla, efektivnu postavku identiteta za pokretanje, aktivni daemon i okidač, bez menjanja ili pokretanja posla tokom enumerisanja. Pogledajte priručnike za [konfiguraciju Upstart posla](https://manpages.ubuntu.com/manpages/trusty/man5/init.5.html) i [`initctl`](https://manpages.ubuntu.com/manpages/xenial/man8/initctl.8.html).

Čitljiv fajl sa lozinkom za autologin, kao što je `/etc/autologin/passwd` na sistemima čiji [boot job čita upravo tu putanju](https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/master/chromeos-base/autologin/files/init/autologin.conf), predstavlja trag o izlaganju akreditiva. Potvrdite da je boot job instaliran i da koristi taj fajl, a zatim zasebno proverite da li lozinka važi za neki drugi lokalni nalog ili servis. Sam naziv fajla ne dokazuje ponovnu upotrebu lozinke; zabeležite putanju i metapodatke o pristupu, ali nemojte unositi lozinku u zajednički enumeracioni izlaz.

`ExecStart=` u unit-u ili zakazana komanda mogu otkriti tačnu putanju skripte unutar direktorijuma čiji sadržaj ne može da se izlista. [Dozvola za pretragu direktorijuma](https://man7.org/linux/man-pages/man7/path_resolution.7.html) i dalje može omogućiti trenutnom identitetu prolaz kroz tu poznatu putanju; proverite dozvolu za pretragu na svakom nadređenom direktorijumu i dozvolu za čitanje fajla, umesto da pretpostavite da neuspešan listing direktorijuma štiti fajl. Čitljiva skripta može sadržati akreditive za prijenos, ali za prelazak na drugi nalog ti akreditivi moraju i dalje da važe i da budu nezavisno prihvaćeni na tom nalogu. Zabeležite putanju i dokaze o dozvolama, ali nemojte ispisivati tajne vrednosti u zajedničke logove.

Kod zakazane CommonJS Node.js skripte pregledajte gole importe kao što je `require('package')`, čak i kada je sama skripta samo za čitanje. [Node traži `node_modules` pored fajla koji uvozi modul, a zatim u njegovim nadređenim direktorijumima](https://nodejs.org/api/modules.html#loading-from-node_modules-folders), pre nego što pređe na konfigurisane globalne putanje. Korisnik sa nižim privilegijama koji može da **upisuje u jedan od tih nadređenih direktorijuma i pretražuje ga** možda može da napravi paket koji će biti pronađen ranije. Potvrdite da se do tačnog importa zaista dolazi, da izabrani paket nije ugrađeni modul, da se relevantna putanja može kreirati ili menjati, da se modul u instaliranom runtime-u razrešava do te putanje i da će ga posao sa višim privilegijama učitati pri budućem pokretanju. Metapodaci o upisivom nadređenom direktorijumu samo su povod za pregled; pasivno pregledajte skriptu i scheduler, bez postavljanja modula ili pokretanja posla.

Privatni Python indeks paketa predstavlja još jednu granicu poverenja kada automatizovani posao instalira pakete pod drugim OS identitetom. Povežite tačan posao i nalog pod kojim se pokreće sa konfigurisanim indeksom i izabranim nazivima paketa, pa proverite da li korisnik sa nižim privilegijama može da objavi ili zameni paket koji će posao zaista instalirati. Izgradnja source distribucije može pokrenuti build backend ili zastareli `setup.py` pod identitetom instalatera; uvoz instaliranog paketa predstavlja zaseban put izvršavanja. Listener indeksa, čitljiv hash lozinke za otpremanje ili sam naziv fajla paketa ne dokazuju taj lanac. Pregledajte posao, autorizaciju indeksa i poreklo paketa, bez otpremanja ili instaliranja bilo čega tokom enumerisanja. Pogledajte [pip-ov interfejs build sistema](https://pip.pypa.io/en/stable/reference/build-system/) i [uputstva za bezbednu instalaciju](https://pip.pypa.io/en/stable/topics/secure-installs/).

Privilegovani agent može da proverava red zadataka kojim upravlja zaseban web servis ili kontejner. Ako identitet sa nižim nivoom poverenja može da upisuje u bazu podataka zadataka tog servisa, utvrdite da li se ti redovi zaista dostavljaju tom agentu i da li se komandni zadatak izvršava pod OS identitetom agenta. Zasebno potvrdite pristup za upis u bazu, ciljnu sesiju ili routing key, aktivno proveravanje reda, autorizaciju zadataka i efektivnog korisnika agenta. Root unutar kontejnera sam po sebi ne podrazumeva pristup kao host-root; granica se prelazi samo ako potrošač sa privilegijama na hostu izvršava podatke zadatka koje kontroliše napadač. Pregledajte metapodatke procesa, fajla baze podataka i servisa, bez menjanja reda ili slanja zadatka tokom enumerisanja.

Zakazani posao može umesto toga da čita komandu iz reda konfiguracije u bazi podataka aplikacije. Potvrdite da uloga baze podataka sa nižim privilegijama može da izmeni baš taj red, da ga aktivni posao čita nakon izmene i da se vrednost prosleđuje shell-u ili ekvivalentnom izvršiocu komandi pod višim OS identitetom. Pristup za upis u bazu ili vrednost koja liči na komandu sami po sebi ne dokazuju izvršavanje; pregledajte posao i dozvole, bez menjanja reda tokom pasivnog enumerisanja.

Poruka u redu može da sadrži i URL umesto koda. Ako privilegovani potrošač preuzima taj URL i učitava odgovor kao Lua ili drugi izvršni plugin, proverite dozvolu izdavača za tačan exchange i routing key, binding ka redu iz kog se poruke preuzimaju, putanju za preuzimanje i učitavanje plugina i efektivni identitet workera. [RabbitMQ rutira objavljene poruke kroz exchanges](https://www.rabbitmq.com/docs/exchanges); listener brokera ili važeća prijava sami po sebi ne dokazuju isporuku ovom worker-u. Uhvaćeni broker akreditivi u čistom tekstu zaseban su trag koji zahteva stvarni pristup snimanju paketa i čitljiv saobraćaj; ne dokazuju ovlašćenje za objavljivanje. Lua plugin može da poziva shell komande preko [`os.execute`](https://www.lua.org/manual/5.4/manual.html#pdf-os.execute) samo ako je taj API dostupan u njegovom runtime-u. Pregledajte konfiguraciju i kod bez snimanja saobraćaja, objavljivanja poruka ili preuzimanja plugina tokom pasivnog enumerisanja.

Kada privilegovani Python servis izlaže lokalni HTTP ili socket endpoint, čitljiva skripta može otkriti putanju od ulaza do koda čak i ako njene dozvole sprečavaju izmene. Povežite aktivni proces i identitet unit-a sa tačnom skriptom, listener-om, autorizacijom rute i poljima koja kontroliše pozivalac. Zatim pratite ta polja kroz parsiranje i validaciju do dinamičkog `eval()` ili `exec()` odredišta. Konkretno, pravljenje novog f-string-a od teksta zahteva i njegovo evaluiranje može protumačiti polja za zamenu koja je dostavio napadač kao Python izraze ([Python upozorenje za `eval`](https://docs.python.org/3/library/functions.html#eval); [semantika f-string-a](https://docs.python.org/3/reference/lexical_analysis.html#f-strings)). Sam nalaz `eval` ili vezivanje na loopback ne dokazuju da nepouzdan pozivalac može da dođe do odredišta; pregledajte stvarni tok podataka i kontrole pristupa, bez slanja probnog payload-a tokom enumerisanja.

Provera potpisanog zahteva na toj ruti zahteva zaseban pregled. Ako čitljiv izvorni kod izvodi ključ za potpisivanje iz dokazivo malog ili predvidivog skupa vrednosti, a servis izlaže važeći potpisani primer, potpis možda više ne štiti privilegovano `eval()` odredište. Proverite tačan način izvođenja ključa i verifier, identitet aktivnog servisa i lokalni pristup pozivalaca, kao i da li potpisano polje stiže do odredišta; uvoz Python-ovog [`random` modula](https://docs.python.org/3/library/random.html) ili sam potpisani primer ništa od toga ne dokazuju. Python takođe upozorava da ograničavanje `__builtins__` [nije bezbednosna granica za nepouzdan `eval()` unos](https://docs.python.org/3/library/functions.html#eval). Analizu ključa obavljajte offline i nemojte slati falsifikovane zahteve tokom pasivnog enumerisanja.

Prazan, ali upisiv direktorijum `/etc/systemd/system/<unit>.service.d` važan je čak i kada su fajl unit-a i svi postojeći drop-in fajlovi zaštićeni: korisnik može da kreira novu `.conf` zamenu. Proverite da li trenutni identitet može da upisuje u direktorijum i pretražuje ga, da li je unit učitan i pokreće se kao root, kao i da li će uslediti ponovno učitavanje daemon-a pa restart. Dozvola za ponovno učitavanje ili restart, timer ili kasnije podizanje sistema mogu aktivirati izmenu; sam pristup za upis u direktorijum ne izvršava je odmah.

Kod pokrenutih servisa pratite doslovne putanje `EnvironmentFile=` iz odeljka `[Service]` u unit-u, uključujući fajlove čija imena ne počinju sa `.env`. Ako korisnik sa nižim privilegijama može da pročita neki od njih, navedite nazive ključeva koji liče na akreditive, kao što su `API_TOKEN` ili `APP_SECRET_KEY`, ali nemojte ispisivati vrednosti u zajedničke logove. Prilikom procene efektivnog unit-a proverite drop-in zamene i opcione prefikse `-`. Čitljivost ukazuje na moguće izlaganje akreditiva; vrednost i dalje mora da bude važeća za privilegovanu radnju da bi dovela do eskalacije.

### Privilegovana obrada nepouzdanih otpremanja

File watcher koji se pokreće kao root može da prosledi fajlove iz direktorijuma za otpremanje u koji korisnici mogu da upisuju kratkotrajnom parser-u ili extractor-u. Pratite nadređenu skriptu ili servis pokrenutog watcher-a i potvrdite tačan direktorijum, ko može da postavlja fajlove u njega, komandu podređenog procesa i njene argumente, kao i identitet pod kojim se podređeni proces pokreće. Snimak procesa može prikazati watcher, a da ne obuhvati extractor koji se pokreće između otpremanja. Nemojte postavljati probni payload niti aktivirati watcher tokom pasivnog enumerisanja.

Jedan konkretan primer je Binwalk-ov režim izdvajanja (`-e`) koji obrađuje PFS podatke pod kontrolom napadača. [CVE-2022-4510](https://github.com/ReFirmLabs/binwalk/pull/617) omogućavao je PFS extractor-u da upisuje izvan predviđenog direktorijuma, uključujući putanju plugina koju je Binwalk kasnije mogao da učita. Projekat je uključio ispravku u verziju [2.3.4](https://github.com/ReFirmLabs/binwalk/releases/tag/v2.3.4), ali backport-ovi distribucija mogu zadržati stariju prikazanu verziju; pre procene primenljivosti proverite bezbednosni status instaliranog paketa, na primer u [Debian tracker-u](https://security-tracker.debian.org/tracker/CVE-2022-4510). Sama instalirana verzija Binwalk-a ne dokazuje putanju za eskalaciju privilegija: izdvajanje mora zaista da pokreće proces sa višim privilegijama nad ulazom koji korisnik sa nižim privilegijama može da kontroliše.

### Zakazane izgradnje sa lokalnim zavisnostima

Zakazani `cargo run` ponovo kompajlira izvorni kod pod identitetom naloga za pokretanje posla. Pregledajte lokalne zavisnosti `{ path = "..." }` u manifestu, kao i dozvole za izvorni kod i nadređene direktorijume svake zavisnosti, a ne samo glavnog crate-a. Ako korisnik sa nižim privilegijama može da izmeni zavisnost koju Cargo kompajlira, a zakazani posao pokreće njen rezultat, kompajlirani kod može da se izvrši pod tim identitetom. Potvrdite efektivnu komandu scheduler-a, radni direktorijum, razrešavanje zavisnosti i da li će doći do ponovne izgradnje; Rust izvorni fajl u koji može da se upisuje, a nalazi se negde drugde, samo je trag. Čitanje manifesta i metapodataka putanja dovoljno je za pasivnu trijažu. Pogledajte [Cargo dokumentaciju o path zavisnostima](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#specifying-path-dependencies).

## Fajlovi framebuffer-a u Xvfb-u

`Xvfb -fbdir <directory>` koristi memory-mapped fajlove nazvane `Xvfb_screen<n>` za svoje virtuelne ekrane. Ako aktivni Xvfb proces drugog korisnika navodi direktorijum čiji su fajlovi ekrana čitljivi trenutnom korisniku, framebuffer može da otkrije sadržaj desktopa tog korisnika. Zajedno potvrdite proces, vlasništvo nad fajlovima i dozvole; sam čitljiv fajl ne dokazuje da se na ekranu nalazi koristan sadržaj. Najpre pregledajte putanje i metapodatke, bez kopiranja podataka slike u zajednički enumeracioni izlaz. [Xvfb priručnik](https://xorg.freedesktop.org/archive/X11R7.5/doc/man/man1/Xvfb.1.html) opisuje ponašanje opcije `-fbdir`.

```bash
pgrep -a -x Xvfb
ls -l /path/from/-fbdir/Xvfb_screen*
```

## References

1. [Linux `shmget(2)` priručnik](https://man7.org/linux/man-pages/man2/shmget.2.html)
2. [Linux `ipcs(1)` priručnik](https://man7.org/linux/man-pages/man1/ipcs.1.html)
3. [OpenBSD `ipcs(1)` priručnik](https://man.openbsd.org/ipcs.1)
4. [Konfiguracija Consul agenta: provere skripti](https://developer.hashicorp.com/consul/docs/reference/agent/configuration-file/general)
5. [Consul agent API za registraciju servisa](https://developer.hashicorp.com/consul/api-docs/agent/service)
6. [Konfiguracija Consul ACL-a](https://developer.hashicorp.com/consul/docs/reference/agent/configuration-file/acl)
7. [LibreOffice pomoć: otvaranje socketa za eksterne API klijente](https://help.libreoffice.org/latest/en-US/text/sbasic/shared/03/sf_intro.html)
8. [LibreOffice SDK: `XSystemShellExecute`](https://api.libreoffice.org/docs/idl/ref/interfacecom_1_1sun_1_1star_1_1system_1_1XSystemShellExecute.html)

{{#include ../../banners/hacktricks-training.md}}
