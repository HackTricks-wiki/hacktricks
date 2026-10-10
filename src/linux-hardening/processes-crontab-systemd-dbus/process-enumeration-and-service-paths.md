# Enumeracija procesa i putanje servisa

{{#include ../../banners/hacktricks-training.md}}

Korisno pitanje je koji privilegovani proces koristi podatke ili kod na koje može da utiče korisnik sa nižim privilegijama. Pregledajte stablo procesa, aktivno okruženje, otvorene datoteke i jedinicu ili skriptu koja je pokrenula svaki kandidat.

## Mapiranje procesa i vlasništva

```bash
ps -eo user,pid,ppid,tty,comm,args --sort=ppid
pstree -alp 2>/dev/null
systemctl list-units --type=service --state=running 2>/dev/null
ss -lntup
```

Unakrsni odnos roditelj–dete između različitih korisnika može biti normalan, ali neočekivan prelaz zahteva proveru roditeljske komande, argumenata, izvršne datoteke, radnog direktorijuma i referenciranih datoteka. Koristite [users and sessions](../user-information/user-and-session-triage.md) da protumačite vlasnika i kontekst prijave.

### Konzole lokalnih virtuelnih mašina

Pregledajte QEMU opcije `-spice` zajedno sa adresom na kojoj proces sluša. [QEMU dokumentacija](https://www.qemu.org/docs/master/system/qemu-manpage.html) navodi da `disable-ticketing` omogućava SPICE klijentima povezivanje bez autentifikacije. Listener vezan za loopback i dalje može biti dostupan drugim lokalnim korisnicima hosta. Pre nego što komandnu liniju smatrate izloženom konzolom, potvrdite aktivni listener, opcije autentifikacije i lokalni pristup. Kontrola konzole utiče na **guest**; dobijanje guest naloga ili promena njegovog stanja pri pokretanju zahteva zasebne uslove na guest strani i ne daje root pristup hostu za virtuelizaciju. Tokom pasivne enumeracije pregledajte argumente procesa i metapodatke socket-a, bez povezivanja na guest ili njegovog ponovnog pokretanja.

Lokalno dostupno web sučelje može da izvršava kod sa nalogom servisnog procesa, čak i kada prva shell sesija ne može da pristupi datotekama tog naloga. Na primer, CVE-2023-0297 je uticao na obradu putanje `/flash/addcrypted2` u pyLoad-u kada bi nepouzdan JavaScript dospeo do Js2Py-ja sa omogućenim Python import-om; [ispravka u upstream-u](https://github.com/pyload/pyload/commit/7d73ba7919e594d783b3411d7ddb87885aea782d) onemogućila je `pyimport`. Pre nego što pyLoad proces smatrate putem za eskalaciju privilegija, uporedite vlasnika aktivnog procesa, adresu na kojoj sluša, izloženost endpoint-a i instaliranu ispravku ili backport dobavljača. Sam naziv procesa, otvoren port ili verzija paketa ne dokazuju izloženost; pasivna enumeracija ne treba da šalje payload za izvršavanje koda.

### Privilegovane login shell sesije koje dele terminal

Privilegovana interaktivna shell sesija koja pokreće `su --login <user>` bez nezavisnog pseudo-terminala može ostaviti terminal deljen sa login shell sesijom korisnika sa nižim privilegijama. Ako taj korisnik može da kontroliše svoju startup datoteku, a kod u njoj može da koristi `TIOCSTI` za ubacivanje unosa u terminal, taj unos može stići do privilegovane shell sesije kada se ona nastavi. [Priručnik za util-linux `su`](https://man7.org/linux/man-pages/man1/su.1.html#SECURITY_NOTES) opisuje rizik deljenog terminala i preporučuje `su --pty`/`-P` za interaktivnu upotrebu; `su -c` pokreće zasebnu sesiju bez kontrolnog terminala. Rizik zavisi od stvarne roditeljske shell sesije, odnosa terminala, ciljne startup datoteke i pravila kernela. Sam naziv procesa ili argument `su -l` samo je povod za proveru.

Pregledajte uočeno stablo procesa i TTY kolone, a zatim launcher koji se može čitati i vlasništvo/dozvole startup datoteke. Na Linuxu, `/proc/sys/dev/tty/legacy_tiocsti` može pomoći u tumačenju pravila kada postoji; njegovo odsustvo ne dokazuje da je sistem bezbedan. [Priručnik za Linux `TIOCSTI`](https://man7.org/linux/man-pages/man2/TIOCSTI.2const.html) navodi da od Linuxa 6.2 ova operacija može zahtevati `CAP_SYS_ADMIN` kada je ovaj sysctl podešen na false. Nemojte pozivati ioctl samo radi enumeracije hosta.

Nalog baze podataka ponekad može da izmeni startup datoteku ciljnog korisnika bez direktnog pristupa za pisanje u datotečni sistem. PostgreSQL serverska komanda `COPY ... TO 'filename'` upisuje kao OS nalog servera baze podataka, ali [ograničenja PostgreSQL-a](https://www.postgresql.org/docs/current/sql-copy.html) dozvoljavaju ovaj oblik datoteke samo superkorisnicima baze podataka ili ulogama kao što je `pg_write_server_files`. Potvrdite i ulogu u bazi podataka i dozvole OS naloga servera za datoteku; sama connection string aplikacije ne daje ovlašćenje za upis u datoteku. Prilikom procene lanca, mogućnosti privilegovanog launchera držite odvojeno od mogućnosti naloga baze podataka.

## Pregledajte runtime artefakte

```bash
readlink /proc/<PID>/exe
tr '\0' ' ' </proc/<PID>/cmdline; echo
ls -l /proc/<PID>/fd 2>/dev/null
lsof -p <PID> 2>/dev/null
lsof +L1 2>/dev/null
```

Izbrisani izvršni fajlovi i izbrisani, ali i dalje otvoreni fajlovi ostaju referencirani dok se ne zatvori poslednji deskriptor. Mogu da sačuvaju dokaze ili tajne kojima je moguće pristupiti. Okruženja procesa i memorija mogu sadržati akreditive, ali čitanje drugog procesa ograničavaju vlasništvo, opcije montiranja `/proc`, Yama ptrace politika i druge bezbednosne kontrole. Pogledajte [file descriptors](../main-system-information/filesystem-links-and-file-descriptors.md) i [post-exploitation credential hunting](../post-exploitation/README.md) za povezane tehnike.

Sačuvani syscall tragovi predstavljaju još jednu granicu dozvola za fajlove. [`strace` records syscall arguments to an output file](https://man7.org/linux/man-pages/man1/strace.1.html), pa čitljiv trag [`execve` arguments](https://man7.org/linux/man-pages/man2/execve.2.html) može da otkrije lozinku koju je privilegovani zadatak prosledio u komandnoj liniji. Najpre utvrdite da li trenutni korisnik može da pročita konkretan trag i da li argument zaista sadrži akreditiv; za kasniji prelazak na Unix nalog potrebno je zasebno dokazati da se taj akreditiv tamo prihvata. Metapodaci fajla korisni su kao pasivan trag, bez skeniranja svakog traga ili ispisivanja njegovog sadržaja tokom rutinskog izviđanja.

## Socket-i za automatizaciju kancelarijskog softvera sa privilegijama

LibreOffice i OpenOffice mogu da izlože svoj UNO API putem argumenta `--accept=socket,host=<host>,port=<port>;urp;`. Kancelarijski proces u vlasništvu root korisnika sa dostupnom krajnjom tačkom može lokalnom korisniku sa nižim privilegijama omogućiti pozivanje API servisa u bezbednosnom kontekstu tog procesa. Servis `SystemShellExecute` obuhvata operaciju za pokretanje sistemske komande. Vezivanje za loopback ograničava udaljenu dostupnost, ali socket i dalje ostaje dostupan lokalnim korisnicima, osim ako neka druga kontrola to ne sprečava.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
ps -eo user,args | grep -E '[s]office|[l]ibreoffice|[o]penoffice'
ss -ltn 2>/dev/null
```

Povežite vlasnika procesa, tačan argument `--accept` i trenutnu adresu i port na kojima sluša. Konfigurisani acceptor koji nije uspeo da se veže predstavlja samo trag; tokom pasivnog nabrajanja nemojte se povezivati na API niti ga pozivati. Izbegavajte pokretanje privilegovane instance office aplikacije samo da biste testirali ovo stanje.

## System V deljena memorija koju koriste privilegovani procesi

Pomoćni program u vlasništvu root korisnika može da kreira segment System V deljene memorije u koji drugi korisnik može da upisuje. Ako se pomoćni program kasnije osloni na podatke iz tog segmenta u shell komandi ili drugoj osetljivoj operaciji, segment prelazi granicu privilegija čak i kada su izvršna datoteka i njene datoteke zaštićene. `shmget()` preuzima dozvole pristupa iz nižih devet bitova svojih zastavica; režim `0666` dozvoljava drugim korisnicima da upisuju, dok zastavica `IPC_CREAT` ne sužava te dozvole. Pasivno pregledajte aktivne segmente pomoću `ipcs -m` i uporedite njihovog vlasnika, režim i životni vek sa privilegovanim procesom i načinom obrade njegovih ulaznih podataka. Sam segment sa dozvolom pisanja za sve ne dokazuje izvršavanje komandi.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
ipcs -m
```

System V segmenti se razlikuju od POSIX datoteka za deljenu memoriju u `/dev/shm`. Segment kreiran samo na trenutak možda neće biti prisutan u jednom `ipcs` snimku, pa prazan izlaz ne isključuje mogućnost da pomoćni program koristi deljenu memoriju. Pregledajte njegov izvorni kod ili ponašanje binarne datoteke, kao i sva `sudo` pravila koja ga pokreću; nemojte pokretati privilegovani pomoćni program samo da biste izazvali pojavu segmenta tokom enumeracije. [Vodič za IPC namespace](../containers-namespaces/container-security/protections/namespaces/ipc-namespace.md) objašnjava kako namespace-i utiču na vidljivost.<sup>[[2]](#references)[[3]](#references)</sup>

## Provere skriptama Consul agenta

Consul može da pokreće skriptne provere ispravnosti koristeći identitet operativnog sistema svog agenta. Ako agent radi kao root, omogući `enable_script_checks` i dozvoli korisniku sa nižim privilegijama da registruje servis sa skriptnom proverom preko lokalnog HTTP API-ja, taj korisnik može da izazove pokretanje komandi kao root. Vezivanje API-ja samo za `127.0.0.1` i dalje omogućava lokalnim korisnicima da mu pristupe. Podešavanje `enable_local_script_checks` je uže: ono isključuje skriptne provere poslate putem registracija preko HTTP API-ja. Kada su Consul ACL-ovi omogućeni, za registraciju servisa je potreban `service:write`; sama linija `acl.default_policy=allow` ne dokazuje da anonimni pozivalac može da registruje servis. Zajedno proverite stvarni identitet agenta, učitana podešavanja, vezivanje API-ja i autorizaciju.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

```bash
ps -eo user,args | grep '[c]onsul agent'
ls -l /etc/consul.d 2>/dev/null
```

Pratite argumente `-config-dir` i `-config-file` pokrenutog agenta do odgovarajuće konfiguracije i pregledajte samo nazive i vrednosti polja za proveru skripti i ACL. Konfiguracione datoteke mogu sadržati i gossip ključeve ili tokene; izbegavajte da ih kopirate u zajedničke logove. Nemojte registrovati servis niti pokretati proveru ispravnosti samo da biste utvrdili da li ovaj uslov postoji.

Postoji i zaseban put preko lokalnih datoteka ako korisnik sa nižim privilegijama može **da upisuje u direktorijum i da ga pretražuje**, a taj direktorijum je naveden argumentom `-config-dir` agenta koji se pokreće kao root: iz tog direktorijuma može da se učita nova servisna definicija `.hcl` ili `.json`. Mogućnost pretraživanja i upisivanja u direktorijum može dozvoliti dodavanje datoteke čak i kada je izlistavanje direktorijuma zabranjeno. Za izvršavanje komandi kao root, potvrdite da agent zaista učitava taj direktorijum, da njegova **efektivna** postavka za proveru skripti dozvoljava lokalne definicije, da je definicija učitana i da agent zadržava root privilegije. [Consul dokumentuje](https://developer.hashicorp.com/consul/docs/fundamentals/agent#reloadable-configurations) koje postavke i definicije provere ispravnosti mogu ponovo da se učitaju; za samo omogućavanje provera skripti možda je potrebno ponovno pokretanje, zato proverite ponašanje instalirane verzije. Kada ACL štiti agenta, za [`consul reload` je potrebna dozvola `agent:write`](https://developer.hashicorp.com/consul/api-docs/agent#reload-agent); sama dozvola za upis u KV to ne omogućava. Tretirajte mogućnost izmene metapodataka direktorijuma kao povod za proveru, a ne kao dokaz da je ponovno učitavanje, ponovno pokretanje ili izvršavanje komandi odobreno. Pregledajte putanje, dozvole i pravila bez upisivanja konfiguracije i pozivanja API-ja.

## Pratite lanac izvršavanja servisa

```bash
systemctl cat <unit>.service
systemctl show <unit>.service -p User -p Group -p ExecStart -p EnvironmentFiles -p WorkingDirectory
namei -l /path/from/ExecStart
```

Proverite jedinicu, drop-in konfiguracije, `EnvironmentFile=`, pomoćne skripte, relativne komande, direktorijume sa dozvolom za upis i aktivaciju preko soketa. Jedinica u vlasništvu root-a i dalje može biti nebezbedna ako čita konfiguraciju ili skriptu u koju korisnik može da upisuje. Stranica o [arbitrary file write](../interesting-files-permissions/write-to-root.md) obrađuje uobičajene načine zloupotrebe servisa i jedinica. Kratkotrajne poslove pratite pomoću [pspy](https://github.com/DominicBreuker/pspy) ili audit/telemetrije procesa kada ih jednokratni `ps` ispis ne prikaže.

Za prilagođeni **xinetd** servis povežite omogućenu stavku `server`, `user` i kontrole pristupa sa aktivnim listener-om i tačnom izvršnom datotekom. Postavka [`user`](https://manpages.debian.org/testing/xinetd/xinetd.conf.5.en.html) bira identitet pokrenutog procesa, dok set-user-ID bit na izvršnoj datoteci može zasebno da promeni njen efektivni identitet ako [`execve` dozvoljava tu promenu](https://man7.org/linux/man-pages/man2/execve.2.html). Dostupan privilegovani binarni fajl koji prihvata nepouzdan unos zaslužuje pregled izvornog koda ili disasembliranog koda van mreže radi grešaka u memorijskoj bezbednosti, kao što je neograničena [`scanf` konverzija stringa](https://www.gnu.org/software/libc/manual/html_node/String-Input-Conversions.html) u bafer fiksne veličine. Mapiranje servisa i set-user-ID metapodaci su smernice za istragu, a ne dokaz da takva greška postoji; tokom pasivne enumeracije nemojte slati ulaze koji izazivaju pad niti debagovati aktivni privilegovani servis.

Za prilagođeni privilegovani listener sa čitljivim izvornim kodom pregledajte svaku dužinu pod kontrolom pozivaoca koja se koristi u operaciji kopiranja kao što je [`memcpy`](https://man7.org/linux/man-pages/man3/memcpy.3.html). Provera da je trenutni indeks upisa unutar bafera fiksne veličine ne potvrđuje da **dužina kopiranja** staje u preostali prostor; proverite `copy_length <= capacity - index` nakon potvrde da je indeks u opsegu, kao i predznak vrednosti i prekoračenje pri aritmetičkim operacijama. Ovo je smernica za pregled samo ako unos stiže do te operacije, listener je dostupan korisniku sa nižim privilegijama, a proces zadržava viši efektivni identitet. Pregledajte izvorni kod i metapodatke procesa van mreže; tokom enumeracije nemojte slati ulaze koji izazivaju pad aktivnom servisu.

Na sistemima koji koriste **Upstart**, definicije sistemskih poslova mogu se nalaziti u direktorijumu `/etc/init/*.conf`. Datoteka posla u koju trenutni korisnik može da upisuje predstavlja rizik kada aktivni init demon učitava baš tu datoteku, njena `script` ili `exec` stavka radi pod identitetom sa višim privilegijama, a korisnik može da je pokrene dozvoljenom `initctl` komandom ili drugim stvarnim okidačem. Sama sudo dozvola za `initctl` ne dokazuje da je ijedna datoteka posla upisiva niti da će izmenjeni posao biti pokrenut. Proverite dozvole tačne datoteke posla, efektivnu postavku identiteta za pokretanje, aktivni demon i okidač, bez izmene ili pokretanja posla tokom enumeracije. Pogledajte priručnike za [konfiguraciju Upstart posla](https://manpages.ubuntu.com/manpages/trusty/man5/init.5.html) i [`initctl`](https://manpages.ubuntu.com/manpages/xenial/man8/initctl.8.html).

Čitljiva datoteka sa lozinkom za automatsku prijavu, kao što je `/etc/autologin/passwd` na sistemima čiji [boot posao čita baš tu putanju](https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/master/chromeos-base/autologin/files/init/autologin.conf), ukazuje na moguće izlaganje akreditiva. Potvrdite da je boot posao instaliran i da koristi tu datoteku, a zatim zasebno proverite da li lozinka važi za neki drugi lokalni nalog ili servis. Sam naziv datoteke ne dokazuje ponovnu upotrebu lozinke; zabeležite putanju i metapodatke o pristupu, ali nemojte unositi lozinku u zajednički izlaz enumeracije.

`ExecStart=` u jedinici ili zakazana komanda mogu otkriti tačnu putanju skripte u direktorijumu čiji se sadržaj ne može izlistati. [Dozvola za pretragu direktorijuma](https://man7.org/linux/man-pages/man7/path_resolution.7.html) i dalje može dozvoliti trenutnom identitetu da pristupi toj poznatoj putanji; proverite dozvolu za pretragu svakog nadređenog direktorijuma i dozvolu za čitanje same datoteke, umesto da pretpostavite da je neuspešno izlistavanje direktorijuma štiti. Čitljiva skripta može sadržati akreditiv za prenos, ali pristup drugom nalogu zahteva da taj akreditiv i dalje važi i da je zasebno prihvaćen tamo. Zabeležite putanju i dokaze o dozvolama, ali nemojte ispisivati tajne vrednosti u zajedničke logove.

Kod zakazane CommonJS Node.js skripte pregledajte gole importe kao što je `require('package')`, čak i kada je sama skripta samo za čitanje. [Node pretražuje `node_modules` pored datoteke koja vrši import, a zatim u njenim nadređenim direktorijumima](https://nodejs.org/api/modules.html#loading-from-node_modules-folders), pre nego što pređe na konfigurisane globalne putanje. Korisnik sa nižim privilegijama koji može da **upisuje u jedan od tih nadređenih direktorijuma i da ga pretražuje** možda može da napravi paket koji će biti pronađen ranije. Potvrdite da se tačan import zaista izvršava, da izabrani paket nije ugrađeni modul, da se relevantna putanja može kreirati ili menjati, da se modul razrešava na toj putanji u instaliranom runtime okruženju i da će ga posao sa višim privilegijama učitati pri budućem pokretanju. Metapodaci o upisivom nadređenom direktorijumu samo su povod za pregled; pasivno pregledajte skriptu i raspoređivač, bez postavljanja modula ili pokretanja posla.

Privatni Python indeks paketa predstavlja još jednu granicu poverenja kada automatizovani posao instalira pakete pod drugim OS identitetom. Povežite tačan posao i nalog pod kojim se pokreće sa konfigurisanim indeksom, izabranim imenima paketa i mogućnošću da korisnik sa nižim privilegijama objavi ili zameni paket koji će posao zaista instalirati. Izgradnja izvorne distribucije može pokrenuti njen build backend ili zastareli `setup.py` pod identitetom instalētora; uvoz instaliranog paketa je zasebna putanja izvršavanja. Listener indeksa, čitljiv hash lozinke za otpremanje ili samo ime datoteke paketa ne dokazuju tu putanju. Pregledajte posao, ovlašćenja za indeks i poreklo paketa, ne otpremajući niti instalirajući bilo šta tokom enumeracije. Pogledajte [pip interfejs za build sistem](https://pip.pypa.io/en/stable/reference/build-system/) i [smernice za bezbednu instalaciju](https://pip.pypa.io/en/stable/topics/secure-installs/).

Privilegovani agent može periodično da proverava red poslova kojim upravlja zaseban veb-servis ili kontejner. Ako identitet sa nižim stepenom poverenja može da upisuje u bazu podataka sa poslovima tog servisa, utvrdite da li se ti zapisi zaista prosleđuju agentu i da li se komandni posao izvršava pod OS identitetom agenta. Zasebno potvrdite dozvolu za upis u bazu, ciljnu sesiju ili routing key, aktivno periodično proveravanje, ovlašćenje za posao i efektivnog korisnika agenta. Root unutar kontejnera sam po sebi ne znači pristup hostu kao root; granica se prelazi samo ako potrošač sa privilegijama na hostu izvršava podatke posla koje kontroliše napadač. Pregledajte metapodatke procesa, datoteke baze i servisa bez menjanja reda ili slanja posla tokom enumeracije.

Umesto toga, ponavljajući posao može da čita komandu iz reda konfiguracije u bazi aplikacije. Potvrdite da uloga baze podataka sa nižim privilegijama može da izmeni baš taj red, da ga aktivni posao čita nakon izmene i da se vrednost prosleđuje shell-u ili ekvivalentnom izvršiocu komandi pod višim OS identitetom. Dozvola za upis u bazu ili vrednost koja liči na komandu sama po sebi ne dokazuje izvršavanje; pasivno pregledajte posao i dozvole, bez menjanja reda.

Red poruka može da sadrži URL umesto koda. Ako privilegovani potrošač preuzima taj URL i učitava odgovor kao Lua ili drugi izvršni dodatak, proverite dozvolu izdavaoca za tačan exchange i routing key, vezu sa redom koji se konzumira, putanju preuzimanja i učitavanja dodatka i efektivni identitet radnog procesa. [RabbitMQ usmerava objavljene poruke kroz exchanges](https://www.rabbitmq.com/docs/exchanges); listener brokera ili ispravni podaci za prijavu sami po sebi ne dokazuju da će poruka biti dostavljena ovom radnom procesu. Uhvaćeni kredencijali brokera u čistom tekstu zaseban su trag koji zahteva stvarni pristup hvatanju paketa i čitljiv saobraćaj; oni ne dokazuju ovlašćenje za objavljivanje. Lua dodatak može da poziva shell komande preko [`os.execute`](https://www.lua.org/manual/5.4/manual.html#pdf-os.execute) samo ako je taj API dostupan u njegovom runtime okruženju. Pregledajte konfiguraciju i kod bez hvatanja saobraćaja, objavljivanja poruka ili preuzimanja dodatka tokom pasivne enumeracije.

Kada privilegovani Python servis izlaže lokalnu HTTP ili socket krajnju tačku, čitljiva skripta može da otkrije putanju od ulaza do koda čak i ako njene dozvole sprečavaju izmene. Povežite aktivni proces i identitet jedinice sa tačnom skriptom, listener-om, autorizacijom rute i poljima pod kontrolom pozivaoca. Zatim pratite ta polja kroz parsiranje i validaciju do dinamičkog `eval()` ili `exec()` odredišta. Konkretno, kreiranje novog f-stringa od teksta zahteva i njegovo evaluiranje može da protumači polja za zamenu koja je uneo napadač kao Python izraze ([Python upozorenje za `eval`](https://docs.python.org/3/library/functions.html#eval); [semantika f-stringova](https://docs.python.org/3/reference/lexical_analysis.html#f-strings)). Samo poklapanje sa `eval` ili vezivanje za loopback ne dokazuje da nepouzdan pozivalac može da dođe do tog odredišta; pregledajte stvarni tok podataka i kontrole pristupa, bez slanja probnog sadržaja tokom enumeracije.

Kapija za potpisane zahteve na toj ruti zahteva zaseban pregled. Ako čitljiv izvorni kod izvodi ključ za potpis iz dokazivo malog ili predvidljivog prostora izlaznih vrednosti, a servis izlaže važeći potpisani primer, potpis možda više ne štiti privilegovano `eval()` odredište. Proverite tačan način izvođenja ključa i verifikator, identitet aktivnog servisa i lokalni pristup pozivaoca, kao i to da li potpisano polje stiže do odredišta; samo import Pythonovog [`random` modula](https://docs.python.org/3/library/random.html) ili primer potpisa ne dokazuje nijedan od tih uslova. Python takođe upozorava da ograničavanje `__builtins__` [nije bezbednosna granica za nepouzdan unos u `eval()`](https://docs.python.org/3/library/functions.html#eval). Analizirajte ključ van mreže i nemojte slati falsifikovane zahteve tokom pasivne enumeracije.

Prazan direktorijum `/etc/systemd/system/<unit>.service.d` u koji može da se upisuje i dalje je važan čak i kada su datoteka jedinice i svi postojeći drop-in fajlovi zaštićeni: korisnik može da napravi novi `.conf` override. Proverite da li trenutni identitet može da upisuje u direktorijum i da ga pretražuje, da li je jedinica učitana i da li se pokreće kao root, kao i da li će uslediti ponovno učitavanje demona nakon kog će servis biti restartovan. Dozvola za ponovno učitavanje ili restartovanje, tajmer ili kasnije podizanje sistema mogu da aktiviraju izmenu; sama dozvola za upis u direktorijum ne izvršava je odmah.

Kod pokrenutih servisa pratite doslovne putanje `EnvironmentFile=` iz odeljka `[Service]` u jedinici, uključujući datoteke čija imena ne počinju sa `.env`. Ako korisnik sa niskim privilegijama može da pročita neku od njih, navedite nazive ključeva koji liče na akreditive, poput `API_TOKEN` ili `APP_SECRET_KEY`, ali nemojte ispisivati njihove vrednosti u zajedničke logove. Proverite drop-in izmene i opciona `-` prefiksiranja pri proceni efektivne jedinice. Čitljivost ukazuje na moguće izlaganje akreditiva; vrednost i dalje mora da bude važeća za privilegovanu radnju da bi dovela do eskalacije privilegija.

### Obrada nepouzdanih otpremanja sa privilegijama

Root pokrenut nadzornik datoteka može da prosledi datoteke iz direktorijuma za otpremanje u koji korisnici mogu da upisuju kratkotrajnom parseru ili alatu za raspakivanje. Pratite roditeljsku skriptu ili servis aktivnog nadzornika i potvrdite tačan direktorijum, ko može da postavlja datoteke u njega, komandu deteta i njene argumente, kao i identitet pod kojim se dete pokreće. Snimak procesa može da prikaže nadzornika, a da propusti alat za raspakivanje koji radi između otpremanja. Tokom pasivne enumeracije nemojte postavljati probni sadržaj niti pokretati nadzornika.

Jedan konkretan primer je Binwalk režim izdvajanja (`-e`) pri obradi PFS podataka koje kontroliše napadač. [CVE-2022-4510](https://github.com/ReFirmLabs/binwalk/pull/617) je omogućavao PFS ekstraktoru da upisuje izvan predviđenog direktorijuma, uključujući putanju dodatka koji je Binwalk kasnije mogao da učita. Ispravka je uključena uzvodno u [2.3.4](https://github.com/ReFirmLabs/binwalk/releases/tag/v2.3.4), ali distribucioni backport-i mogu zadržati stariju prikazanu verziju; proverite bezbednosni status instaliranog paketa, na primer u [Debian tracker-u](https://security-tracker.debian.org/tracker/CVE-2022-4510), pre nego što procenite da li je problem primenljiv. Sama instalirana verzija Binwalk-a ne dokazuje putanju za eskalaciju privilegija: izdvajanje mora zaista da pokrene privilegovaniji proces nad ulazom koji korisnik sa nižim privilegijama može da kontroliše.

### Zakazana izgradnja sa lokalnim zavisnostima

Zakazani `cargo run` ponovo kompajlira izvorni kod kao korisnik pod kojim se posao pokreće. Pregledajte lokalne zavisnosti `{ path = "..." }` u manifestu i dozvole izvornog koda i nadređenih direktorijuma za svaku zavisnost, a ne samo za glavni crate. Ako korisnik sa nižim privilegijama može da izmeni zavisnost koju Cargo kompajlira, a zakazani posao pokreće dobijeni rezultat, kompajlirani kod može da se izvrši kao taj korisnik. Potvrdite efektivnu komandu raspoređivača, radni direktorijum, razrešavanje zavisnosti i da li će se desiti nova izgradnja; Rust izvorna datoteka u koju se može upisivati, a koja se nalazi negde drugde, samo je smernica za istragu. Za pasivnu trijažu dovoljno je pročitati manifest i metapodatke putanja. Pogledajte [dokumentaciju za Cargo zavisnosti po putanji](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#specifying-path-dependencies).

## Xvfb framebuffer datoteke

`Xvfb -fbdir <directory>` koristi memorijski mapirane datoteke pod nazivom `Xvfb_screen<n>` za svoje virtuelne ekrane. Ako aktivni Xvfb proces drugog korisnika navodi direktorijum čije datoteke ekrana trenutni korisnik može da čita, framebuffer može da otkrije sadržaj radne površine tog korisnika. Zajedno potvrdite proces, vlasništvo nad datotekama i dozvole; sama čitljiva datoteka ne dokazuje da se na ekranu nalazi koristan sadržaj. Najpre pregledajte putanje i metapodatke, bez kopiranja slikovnih podataka u zajednički izlaz enumeracije. [Xvfb priručnik](https://xorg.freedesktop.org/archive/X11R7.5/doc/man/man1/Xvfb.1.html) opisuje ponašanje opcije `-fbdir`.

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
7. [LibreOffice pomoć: otvaranje socket-a za spoljne API klijente](https://help.libreoffice.org/latest/en-US/text/sbasic/shared/03/sf_intro.html)
8. [LibreOffice SDK: `XSystemShellExecute`](https://api.libreoffice.org/docs/idl/ref/interfacecom_1_1sun_1_1star_1_1system_1_1XSystemShellExecute.html)

{{#include ../../banners/hacktricks-training.md}}
