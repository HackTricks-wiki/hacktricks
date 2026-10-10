# Prosesopnoeming en dienspaadjies

{{#include ../../banners/hacktricks-training.md}}

Die nuttige vraag is watter bevoorregte proses data of kode verwerk waarop ’n gebruiker met minder voorregte invloed kan uitoefen. Inspekteer die prosesboom, die lewendige omgewing, oop lêers en die eenheid of skrip wat elke kandidaat van stapel gestuur het.

## Karteer prosesse en eienaarskap

```bash
ps -eo user,pid,ppid,tty,comm,args --sort=ppid
pstree -alp 2>/dev/null
systemctl list-units --type=service --state=running 2>/dev/null
ss -lntup
```

’n Ouer-kind-verhouding tussen verskillende gebruikers kan normaal wees, maar ’n onverwagte oorgang regverdig ’n hersiening van die oueropdrag, argumente, uitvoerbare lêer, werkgids en lêers waarna verwys word. Gebruik [users and sessions](../user-information/user-and-session-triage.md) om die eienaar- en aanmeldkonteks te interpreteer.

### Plaaslike virtuelemasjienkonsole

Hersien ’n QEMU-proses se `-spice`-opsies saam met sy luisteradres. [QEMU documentation](https://www.qemu.org/docs/master/system/qemu-manpage.html) meld dat `disable-ticketing` SPICE-kliënte toelaat om sonder verifikasie te koppel. ’n Luisteraar wat aan loopback gebind is, kan steeds vir ander plaaslike gasheergebruikers bereikbaar wees. Bevestig die aktiewe luisteraar, verifikasie-opsies en plaaslike toegang voordat jy die opdragreël as ’n blootgestelde konsole beskou. Konsolebeheer raak die **gasstelsel**; om ’n gasrekening te verkry of sy selflaaitoestand te verander, vereis afsonderlike toestande aan die gasstelselkant en verleen nie root-toegang op die virtualisasiegasheer nie. Lees prosesargumente en sokmetadata sonder om tydens passiewe enumerasie aan die gasstelsel te koppel of dit te herlaai.

’n Plaaslik bereikbare webkoppelvlak kan kode met sy diensrekening uitvoer, selfs wanneer die eerste shell nie toegang tot daardie rekening se lêers het nie. Byvoorbeeld, CVE-2023-0297 het pyLoad se `/flash/addcrypted2`-hantering geraak wanneer onbetroubare JavaScript Js2Py bereik het met Python-imports geaktiveer; die [upstream fix](https://github.com/pyload/pyload/commit/7d73ba7919e594d783b3411d7ddb87885aea782d) het `pyimport` gedeaktiveer. Vergelyk die lopende proses se eienaar, luisteradres, eindpuntblootstelling en geïnstalleerde patch of verskaffer-terugplasing voordat jy ’n pyLoad-proses as ’n eskalasiepad beskou. ’n Prosesnaam, oop poort of pakketweergawe alleen bewys nie blootstelling nie; passiewe enumerasie behoort nie ’n uitvoeringspayload te stuur nie.

### Bevoorregte aanmeldshells wat ’n terminale deel

’n Bevoorregte interaktiewe shell wat `su --login <user>` uitvoer sonder ’n onafhanklike pseudo-terminal, kan sy terminale met die laerbevoorregte aanmeldshell deel. As daardie gebruiker se opstartlêer beheerbaar is en kode daarin `TIOCSTI` kan gebruik om terminale-invoer in te spuit, kan die invoer die bevoorregte shell bereik wanneer dit hervat. [The util-linux `su` manual](https://man7.org/linux/man-pages/man1/su.1.html#SECURITY_NOTES) beskryf die risiko van ’n gedeelde terminale en beveel `su --pty`/`-P` vir interaktiewe gebruik aan; `su -c` begin ’n afsonderlike sessie sonder ’n beherende terminale. Die risiko vereis die werklike ouershell, terminale-verhouding, teiken se opstartlêer en kernbeleid. ’n Prosesnaam of `su -l`-argument alleen is bloot ’n leidraad vir hersiening.

Inspekteer die waargenome prosesboom en TTY-kolomme, en daarna die leesbare lanseerder en eienaarskap/toestemmings van die opstartlêer. Op Linux kan `/proc/sys/dev/tty/legacy_tiocsti`, indien dit bestaan, help om die beleid te interpreteer; die afwesigheid daarvan bewys nie dat dit veilig is nie. [The Linux `TIOCSTI` manual](https://man7.org/linux/man-pages/man2/TIOCSTI.2const.html) meld dat die bewerking sedert Linux 6.2 moontlik `CAP_SYS_ADMIN` vereis wanneer hierdie sysctl false is. Moenie die ioctl aanroep bloot om die gasheer te enumereer nie.

’n Databasisrekening kan soms die teikengebruiker se opstartlêer verander sonder direkte skryftoegang tot die lêerstelsel. PostgreSQL-bedienerkantse `COPY ... TO 'filename'` skryf as die databasisbediener se OS-rekening, maar [PostgreSQL limits](https://www.postgresql.org/docs/current/sql-copy.html) beperk hierdie lêervorm tot databasis-supergebruikers of rolle soos `pg_write_server_files`. Bevestig beide die databasisrol en die bediener se OS-lêertoestemmings; ’n toepassing se verbindingsstring verleen nie op sigself lêerskryftoegang nie. Hou die bevoorregte lanseerder en die databasisrekening se vermoëns apart wanneer jy die ketting beoordeel.

## Inspekteer looptydartefakte

```bash
readlink /proc/<PID>/exe
tr '\0' ' ' </proc/<PID>/cmdline; echo
ls -l /proc/<PID>/fd 2>/dev/null
lsof -p <PID> 2>/dev/null
lsof +L1 2>/dev/null
```

Geskrapte uitvoerbare lêers en geskrapte maar oop lêers bly verwys totdat hul laaste descriptor gesluit word. Hulle kan bewyse of toeganklike geheime bewaar. Prosesomgewings en geheue kan geloofsbriewe bevat, maar toegang tot ’n ander proses word beperk deur eienaarskap, `/proc`-monteeropsies, Yama ptrace-beleid en ander sekuriteitskontroles. Sien [file descriptors](../main-system-information/filesystem-links-and-file-descriptors.md) en [post-exploitation credential hunting](../post-exploitation/README.md) vir verwante tegnieke.

Gestoorde syscall-traces vorm nog ’n lêertoestemmingsgrens. [`strace` teken syscall-argumente in ’n uitvoerlêer aan](https://man7.org/linux/man-pages/man1/strace.1.html), dus kan ’n leesbare trace van [`execve`-argumente](https://man7.org/linux/man-pages/man2/execve.2.html) ’n wagwoord blootlê wat ’n bevoorregte taak op sy opdragreël deurgegee het. Stel eers vas dat die huidige gebruiker die spesifieke trace kan lees en dat die argument werklik ’n geloofsbrief bevat; ’n latere Unix-rekening-oorgang vereis afsonderlike bewys dat die geloofsbrief daar aanvaar word. Lêermetadata is ’n nuttige passiewe leidraad sonder om elke trace te skandeer of die inhoud daarvan tydens roetine-enumerasie te vertoon.

## Bevoorregte kantooroutomatiseringsockets

LibreOffice en OpenOffice kan hul UNO API via ’n `--accept=socket,host=<host>,port=<port>;urp;`-argument blootstel. ’n Kantoorproses wat deur root besit word en ’n bereikbare eindpunt het, kan ’n plaaslike gebruiker met laer voorregte toelaat om API-dienste binne die sekuriteitskonteks van daardie proses aan te roep. Die `SystemShellExecute`-diens sluit ’n bewerking in om ’n stelselopdrag te begin. Binding aan loopback beperk bereikbaarheid van buite, maar laat die socket steeds vir plaaslike gebruikers bereikbaar, tensy ’n ander beheer toegang verhoed.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
ps -eo user,args | grep -E '[s]office|[l]ibreoffice|[o]penoffice'
ss -ltn 2>/dev/null
```

Korrelleer die proseseienaar, die presiese `--accept`-argument en die huidige luisteradres en -poort. ’n Gekonfigureerde acceptor wat nie kon bind nie, is net ’n leidraad; moenie tydens passiewe enumerasie aan die API koppel of dit aanroep nie. Moenie ’n bevoorregte office-instansie begin bloot om hierdie toestand te toets nie.

## System V-gedeelde geheue wat deur bevoorregte prosesse gebruik word

’n Root-besitte helper kan ’n System V-gedeeldegeheuesegment skep waarna ’n ander gebruiker kan skryf. As die helper later data uit daardie segment in ’n shell-opdrag of ’n ander sensitiewe bewerking vertrou, kruis die segment ’n voorreggrens, selfs wanneer die uitvoerbare lêer en sy lêers beskerm is. `shmget()` neem toegangstoestemmings uit die onderste nege bisse van sy vlae; modus `0666` laat ander gebruikers toe om te skryf, terwyl ’n `IPC_CREAT`-vlag nie daardie toestemmings beperk nie. Inspekteer aktiewe segmente passief met `ipcs -m` en korreleer hul eienaar, modus en lewensduur met die bevoorregte proses en die hantering van sy invoer. ’n Wêreldskryfbare segment alleen bewys nie dat kode uitgevoer kan word nie.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
ipcs -m
```

System V-segmente verskil van POSIX shared-memory-lêers onder `/dev/shm`. ’n Segment wat net vir ’n oomblik geskep word, kan afwesig wees in ’n enkele `ipcs`-momentopname; leë uitvoer sluit dus nie ’n helper uit wat shared memory gebruik nie. Gaan die bronkode of binêre gedrag daarvan na, asook enige `sudo`-reël wat dit begin; moenie die bevoorregte helper aanroep net om ’n segment tydens enumerasie te laat verskyn nie. Die [IPC-naamruimtegids](../containers-namespaces/container-security/protections/namespaces/ipc-namespace.md) verduidelik hoe naamruimtes sigbaarheid beïnvloed.<sup>[[2]](#references)[[3]](#references)</sup>

## Consul-agent-skripkontroles

Consul kan skripgesondheidkontroles uitvoer met die bedryfstelselidentiteit van sy agent. As ’n agent as root loop, `enable_script_checks` aktiveer en ’n gebruiker met laer voorregte toelaat om ’n diens met ’n skripkontrole via die plaaslike HTTP API te registreer, kan daardie gebruiker veroorsaak dat opdragte as root uitgevoer word. Deur die API slegs aan `127.0.0.1` te bind, kan plaaslike gebruikers dit steeds bereik. Die `enable_local_script_checks`-instelling is enger: dit sluit skripkontroles uit wat via HTTP API-registrasies ingedien word. Wanneer Consul ACLs geaktiveer is, vereis diensregistrasie `service:write`; ’n `acl.default_policy=allow`-reël alleen bewys nie dat ’n anonieme oproeper kan registreer nie. Gaan die werklike agentidentiteit, gelaaide instellings, API-binding en magtiging saam na.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

```bash
ps -eo user,args | grep '[c]onsul agent'
ls -l /etc/consul.d 2>/dev/null
```

Volg die lopende agent se `-config-dir`- en `-config-file`-argumente na die relevante konfigurasie, en inspekteer slegs die veldname en instellings vir script checks en ACL's. Konfigurasielêers kan ook gossip-sleutels of tokens bevat; moenie dit in gedeelde logs plak nie. Moenie 'n diens registreer of 'n gesondheidstoets uitvoer bloot om hierdie toestand te lys nie.

'n Afsonderlike plaaslike lêerpad bestaan wanneer 'n gebruiker met laer voorregte die gids kan **skryf en deursoek** wat deur 'n agent wat as root loop se `-config-dir` benoem word: 'n nuwe `.hcl`- of `.json`-diensdefinisie kan uit daardie gids gelaai word. Gidsdeursoeking en skryftoegang kan dit moontlik maak om 'n lêer by te voeg selfs wanneer die gids nie gelys kan word nie. Vir uitvoering van opdragte as root, bevestig dat die agent daardie gids werklik laai, dat sy **effektiewe** script-check-instelling plaaslike definisies toelaat, dat die definisie gelaai word en dat die agent root-voorregte behou. [Consul dokumenteer](https://developer.hashicorp.com/consul/docs/fundamentals/agent#reloadable-configurations) watter instellings en gesondheidstoetsdefinisies herlaai kan word; die aktivering van script checks kan self 'n herbegin vereis, dus bevestig die gedrag van die geïnstalleerde weergawe. Wanneer ACL's die agent beskerm, vereis [`consul reload` `agent:write`](https://developer.hashicorp.com/consul/api-docs/agent#reload-agent); KV-skryftoestemming alleen voorsien dit nie. Beskou skryfbare gidsmetadata as 'n aanduiding vir hersiening, nie as bewys van 'n gemagtigde herlaai, herbegin of opdraguitvoering nie. Inspekteer paaie, toestemmings en beleid sonder om konfigurasie te skryf of die API aan te roep.

## Volg die diensuitvoeringsketting

```bash
systemctl cat <unit>.service
systemctl show <unit>.service -p User -p Group -p ExecStart -p EnvironmentFiles -p WorkingDirectory
namei -l /path/from/ExecStart
```

Kontroleer die unit, drop-ins, `EnvironmentFile=`, hulpskrifte, relatiewe opdragte, skryfbare gidse en socket activation. ’n Unit wat deur root besit word, kan steeds onveilig wees as dit ’n konfigurasie- of skriplêer lees wat deur ’n gebruiker geskryf kan word. Die [arbitrary file write](../interesting-files-permissions/write-to-root.md)-bladsy dek algemene misbruikroetes vir services en units. Monitor kortstondige take met [pspy](https://github.com/DominicBreuker/pspy) of oudit-/prosestelemetrie wanneer ’n eenmalige `ps`-lys hulle miskyk.

Vir ’n pasgemaakte **xinetd**-service, korreleer die geaktiveerde stanza se `server`, `user` en toegangsbeheer met die aktiewe listener en presiese uitvoerbare lêer. Die [`user`-instelling](https://manpages.debian.org/testing/xinetd/xinetd.conf.5.en.html) kies die identiteit van die voortgebragte proses, terwyl ’n set-user-ID-bit op die uitvoerbare lêer sy effektiewe identiteit afsonderlik kan verander as [`execve` daardie oorgang toelaat](https://man7.org/linux/man-pages/man2/execve.2.html). ’n Bereikbare bevoorregte binêre lêer wat onbetroubare invoer aanvaar, verdien ’n vanlyn hersiening van die bronkode of disassemblage vir geheueveiligheidsfoute, soos ’n onbeperkte [`scanf`-stringomskakeling](https://www.gnu.org/software/libc/manual/html_node/String-Input-Conversions.html) na ’n vaste buffer. Die service-kartering en set-user-ID-metadata is leidrade, nie bewys van so ’n fout nie; moenie crash-invoer stuur of die aktiewe bevoorregte service ontfout tydens passiewe enumerasie nie.

Vir ’n pasgemaakte bevoorregte listener met leesbare bronkode, hersien elke lengte onder beheer van die oproeper wat vir ’n kopieerbewerking soos [`memcpy`](https://man7.org/linux/man-pages/man3/memcpy.3.html) gebruik word. Om net te kontroleer dat die huidige skryf-indeks binne ’n vaste buffer is, bewys nie dat die **kopielengte** binne die oorblywende spasie pas nie; verifieer `copy_length <= capacity - index` nadat jy bevestig het dat die indeks binne die reeks is, en kontroleer getaltekens en rekenkundige oorloop. Dit is slegs ’n hersieningsleidraad as die invoer daardie bewerking bereik, die listener toeganklik is vir die gebruiker met minder voorregte, en die proses ’n hoër effektiewe identiteit behou. Inspekteer bronkode en prosesmetadata vanlyn; moenie crash-invoer na die aktiewe service stuur tydens enumerasie nie.

Op stelsels wat **Upstart** gebruik, kan stelseltaakdefinisies onder `/etc/init/*.conf` wees. ’n Taaklêer wat deur die huidige gebruiker geskryf kan word, is relevant wanneer die aktiewe init-daemon daardie presiese taak laai, sy `script`- of `exec`-stanza as ’n identiteit met hoër voorregte loop, en die gebruiker dit deur ’n toegelate `initctl`-opdrag of ’n ander werklike sneller kan begin. ’n sudo-toekenning vir `initctl` alleen bewys nie dat enige taaklêer skryfbaar is of dat ’n gewysigde taak sal loop nie. Kontroleer die presiese taaklêertoestemmings, effektiewe run-as-instelling, aktiewe daemon en sneller sonder om die taak te wysig of te begin tydens enumerasie. Sien die handleidings vir [Upstart-taakkonfigurasie](https://manpages.ubuntu.com/manpages/trusty/man5/init.5.html) en [`initctl`](https://manpages.ubuntu.com/manpages/xenial/man8/initctl.8.html).

’n Leesbare outologin-wagwoordlêer, soos `/etc/autologin/passwd` op stelsels waar die [boot-taak daardie presiese pad lees](https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/master/chromeos-base/autologin/files/init/autologin.conf), is ’n leidraad oor blootgestelde geloofsbriewe. Bevestig dat die boot-taak geïnstalleer is en die lêer gebruik, en verifieer dan afsonderlik of die wagwoord vir ’n ander plaaslike rekening of service geldig is. Die lêernaam alleen bewys nie dat die wagwoord hergebruik word nie; teken die pad- en toegangmetadata aan sonder om die wagwoord in gedeelde enumerasie-uitvoer te plaas.

’n Unit se `ExecStart=` of ’n geskeduleerde opdrag kan die presiese padnaam van ’n skriplêer binne ’n lysbare gids openbaar. [Gidessoektoestemming](https://man7.org/linux/man-pages/man7/path_resolution.7.html) kan die huidige identiteit steeds toelaat om daardie bekende pad te deurkruis; bevestig soektoegang op elke ouergids en leestoestemming op die lêer eerder as om aan te neem dat ’n mislukte gidslys dit beskerm. ’n Leesbare skriplêer kan ’n oordraggeloofsbrief bevat, maar om toegang tot ’n ander rekening te verkry, moet daardie geloofsbrief steeds geldig wees en onafhanklik daar aanvaar word. Teken die pad- en toestemmingsbewyse aan sonder om geheime waardes in gedeelde logs te druk.

Vir ’n geskeduleerde CommonJS Node.js-skrip, hersien onverbonde imports soos `require('package')`, selfs wanneer die skrip self leesalleen is. [Node soek `node_modules` langs die lêer wat die import doen en daarna in sy ouergidse](https://nodejs.org/api/modules.html#loading-from-node_modules-folders), voordat dit na opgestelde globale paaie terugval. ’n Gebruiker met minder voorregte wat een van daardie ouergidse kan **skryf en deurkruis**, kan moontlik ’n pakket skep wat vroeër ooreenstem. Bevestig dat die presiese import bereik word, dat die gekose pakket nie ’n ingeboude module is nie, dat die betrokke pad geskep of verander kan word, dat die module daar in die geïnstalleerde runtime oplos, en dat ’n taak met hoër voorregte dit tydens ’n toekomstige aanroep sal laai. Skryfbare ouergidsmetadata is slegs ’n aanduiding om te hersien; inspekteer die skrip en skeduleerder passief sonder om ’n module te plant of die taak te aktiveer.

’n Private Python-pakketindeks is nog ’n trust boundary wanneer ’n outomatiese taak pakkette onder ’n ander OS-identiteit installeer. Korreleer die presiese taak en run-as-rekening met sy opgestelde indeks, gekose pakketname en die vraag of ’n gebruiker met minder voorregte ’n pakket kan publiseer of vervang wat die taak werklik gaan installeer. Die bou van ’n brondistribusie kan sy build-backend of verouderde `setup.py` onder die installeerder se identiteit laat loop; die invoer van die geïnstalleerde pakket is ’n afsonderlike uitvoeringsroete. ’n Indeks-listener, leesbare oplaaiwagwoord-hash of pakketlêernaam alleen bewys nie daardie ketting nie. Hersien die taak, indeksmagtiging en pakketherkoms sonder om enigiets op te laai of te installeer tydens enumerasie. Sien [pip se build-system-koppelvlak](https://pip.pypa.io/en/stable/reference/build-system/) en [riglyne vir veilige installasie](https://pip.pypa.io/en/stable/topics/secure-installs/).

’n Bevoorregte agent kan ’n taakry poll wat deur ’n afsonderlike webservice of container bestuur word. As ’n identiteit met ’n laer vertrouensvlak die service se taakdatabasis kan skryf, bepaal of daardie rye werklik aan die agent gelewer word en of ’n command-taak met die agent se OS-identiteit loop. Bevestig databasis-skryftoegang, die teikensessie of roeteringsleutel, aktiewe polling, taakt magtiging en die agent se effektiewe gebruiker afsonderlik. Root binne ’n container impliseer nie op sigself host-root-toegang nie; die grens word slegs oorgesteek as ’n verbruiker met hostvoorregte aanvallerbeheerde taakdata uitvoer. Inspekteer proses-, databasislêer- en servicemetadata sonder om die ry te wysig of ’n taak te stuur tydens enumerasie.

’n Herhalende taak kan eerder ’n opdrag uit ’n konfigurasie-ry in ’n toepassingsdatabasis lees. Bevestig dat die databasiserol met minder voorregte daardie presiese ry kan verander, dat die aktiewe taak dit ná die verandering lees, en dat die waarde ’n shell of ’n soortgelyke opdraguitvoerder onder ’n hoër OS-identiteit bereik. Databasis-skryftoegang of ’n waarde wat soos ’n opdrag lyk, bewys nie uitvoering nie; inspekteer die taak en toestemmings sonder om die ry tydens passiewe enumerasie te verander.

’n Boodskap in ’n tou kan ook ’n URL in plaas van kode bevat. As ’n bevoorregte verbruiker daardie URL ophaal en die antwoord as ’n Lua- of ander uitvoerbare plugin laai, verifieer die uitgewer se toestemming vir die presiese exchange en routing key, die binding aan die verbruikte tou, die ophaal- en plugin-laaipad, en die werker se effektiewe identiteit. [RabbitMQ roeteer gepubliseerde boodskappe deur exchanges](https://www.rabbitmq.com/docs/exchanges); ’n broker-listener of geldige aanmelding bewys nie op sigself aflewering aan hierdie werker nie. Vasgelegde duideliketeks-broker-geloofsbriewe is ’n afsonderlike leidraad wat werklike toegang tot pakkievaslegging en leesbare verkeer vereis; dit bewys nie publiseringmagtiging nie. ’n Lua-plugin kan shell-opdragte deur [`os.execute`](https://www.lua.org/manual/5.4/manual.html#pdf-os.execute) aanroep slegs as daardie API in sy runtime beskikbaar is. Hersien konfigurasie en kode sonder om verkeer vas te lê, boodskappe te publiseer of ’n plugin op te haal tydens passiewe enumerasie.

Wanneer ’n bevoorregte Python-service ’n plaaslike HTTP- of socket-eindpunt blootstel, kan ’n leesbare skrip ’n invoer-na-kode-roete openbaar, selfs al verhinder sy lêertoestemmings wysiging. Korreleer die aktiewe proses en unit-identiteit met die presiese skrip, listener, roete-magtiging en velde onder beheer van die oproeper. Volg dan daardie velde deur ontleding en validering tot by ’n dinamiese `eval()`- of `exec()`-sink. Spesifiek, die bou van ’n nuwe f-string uit versoekteks en die evaluering daarvan kan invoegingsvelde wat deur ’n aanvaller verskaf word as Python-uitdrukkings interpreteer ([Python se `eval`-waarskuwing](https://docs.python.org/3/library/functions.html#eval); [f-string-semantiek](https://docs.python.org/3/reference/lexical_analysis.html#f-strings)). ’n Blote `eval`-treffer of loopback-binding bewys nie dat ’n onbetroubare oproeper die sink bereik nie; hersien die werklike dataflow en toegangsbeheer sonder om ’n toets-payload te stuur tydens enumerasie.

’n Getekende-versoekhek op daardie roete vereis ’n eie hersiening. As leesbare bronkode die ondertekeningsleutel aflei deur ’n aantoonbaar klein of voorspelbare uitvoerruimte, en die service ’n geldige getekende voorbeeld blootstel, beskerm die handtekening moontlik nie meer ’n bevoorregte `eval()`-sink nie. Verifieer die presiese sleutelafleiding en verifieerder, die aktiewe service se identiteit en plaaslike oproeperstoegang, en of die getekende veld die sink bereik; ’n import van Python se [`random`-module](https://docs.python.org/3/library/random.html) of ’n voorbeeldhandtekening bewys nie enige van daardie voorwaardes nie. Python waarsku ook dat die beperking van `__builtins__` [nie ’n sekuriteitsgrens vir onbetroubare `eval()`-invoer is nie](https://docs.python.org/3/library/functions.html#eval). Ontleed die sleutel vanlyn en moenie vervalste versoeke indien tydens passiewe enumerasie nie.

’n Leë maar skryfbare `/etc/systemd/system/<unit>.service.d`-gids is relevant selfs wanneer die unit-lêer en elke bestaande drop-in beskerm is: die gebruiker kan ’n nuwe `.conf`-override skep. Kontroleer dat die gids deur die huidige identiteit geskryf en deurkruis kan word, dat die unit gelaai is en as root loop, en of ’n daemon-herlaai gevolg deur ’n herbegin sal plaasvind. Toestemming vir herlaai of herbegin, ’n timer of ’n latere selflaai kan die verandering van krag laat word; skryftoegang tot die gids alleen voer dit nie onmiddellik uit nie.

Vir dienste wat loop, volg letterlike `EnvironmentFile=`-paaie vanaf die unit se `[Service]`-afdeling, insluitend lêers waarvan die name nie met `.env` begin nie. As ’n gebruiker met lae voorregte een kan lees, lys geloofsbriefagtige sleutelname soos `API_TOKEN` of `APP_SECRET_KEY` sonder om die waardes in gedeelde logs te druk. Kontroleer drop-in-overrides en opsionele `-`-voorvoegsels wanneer jy die effektiewe unit beoordeel. Leesbaarheid is ’n leidraad oor blootgestelde geloofsbriewe; die waarde moet steeds geldig wees vir ’n bevoorregte handeling om eskalasie te lewer.

### Bevoorregte verwerking van onbetroubare oplaaie

’n Lêerkyker wat as root loop, kan lêers uit ’n oplaai-gids wat deur gebruikers geskryf kan word, aan ’n kortstondige ontleder of uitpakprogram oorhandig. Volg die lopende lêerkyker se ouerskrip of service en bevestig die presiese gids, wie lêers daar kan plaas, die child-opdrag en sy argumente, en die identiteit waaronder die child loop. ’n Prosesopname kan die lêerkyker wys terwyl dit die uitpakprogram tussen oplaaie miskyk. Moenie ’n toets-payload plaas of die lêerkyker aktiveer tydens passiewe enumerasie nie.

Een konkrete voorbeeld is Binwalk se ekstraksiemodus (`-e`) wat aanvallerbeheerde PFS-data verwerk. [CVE-2022-4510](https://github.com/ReFirmLabs/binwalk/pull/617) het die PFS-uitpakprogram toegelaat om buite sy bedoelde gids te skryf, insluitend na ’n plugin-pad wat Binwalk later kon laai. Die stroomop-projek het die regstelling in [2.3.4](https://github.com/ReFirmLabs/binwalk/releases/tag/v2.3.4) ingesluit, maar backports van verspreidings kan ’n ouer weergawe wat vertoon word behou; kontroleer die geïnstalleerde pakket se sekuriteitstatus, soos die [Debian-spoorsnyer](https://security-tracker.debian.org/tracker/CVE-2022-4510), voordat jy bepaal of dit van toepassing is. ’n Geïnstalleerde Binwalk-weergawe alleen bewys nie ’n voorregte-eskalasieroete nie: ’n proses met hoër voorregte moet ekstraksie werklik aanroep op invoer wat die gebruiker met minder voorregte kan beheer.

### Geskeduleerde builds met plaaslike afhanklikhede

’n Geskeduleerde `cargo run` herkompileer bronkode as die gebruiker waaronder die taak loop. Inspekteer die manifest se plaaslike `{ path = "..." }`-afhanklikhede en die bron- en ouergidstoestemmings van elke afhanklikheid, nie net dié van die hoof-crate nie. As ’n gebruiker met minder voorregte ’n afhanklikheid kan wysig wat Cargo kompilereer, en die geskeduleerde taak die resultaat uitvoer, kan die saamgestelde kode as daardie gebruiker loop. Bevestig die skeduleerder se effektiewe opdrag, werkgids, afhanklikheidsresolusie en of ’n nuwe bou gaan plaasvind; ’n skryfbare Rust-bronlêer elders is slegs ’n leidraad. Om die manifest en padmetadata te lees, is genoeg vir passiewe triage. Sien die [Cargo-dokumentasie oor path-dependencies](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#specifying-path-dependencies).

## Xvfb-raambufferlêers

`Xvfb -fbdir <directory>` gebruik geheuegekoppelde lêers met die name `Xvfb_screen<n>` vir sy virtuele skerms. As ’n ander gebruiker se lopende Xvfb-proses ’n gids noem waarvan die skermlêers deur die huidige gebruiker gelees kan word, kan die raambuffer daardie gebruiker se lessenaarinhoud blootstel. Bevestig die proses, lêereienaarskap en toestemmings saam; ’n leesbare lêer op sigself bewys nie dat bruikbare inhoud op die skerm is nie. Inspekteer eers paaie en metadata, sonder om beelddata na gedeelde enumerasie-uitvoer te kopieer. Die [Xvfb-handleiding](https://xorg.freedesktop.org/archive/X11R7.5/doc/man/man1/Xvfb.1.html) dokumenteer die gedrag van `-fbdir`.

```bash
pgrep -a -x Xvfb
ls -l /path/from/-fbdir/Xvfb_screen*
```

## References

1. [Linux `shmget(2)`-handleiding](https://man7.org/linux/man-pages/man2/shmget.2.html)
2. [Linux `ipcs(1)`-handleiding](https://man7.org/linux/man-pages/man1/ipcs.1.html)
3. [OpenBSD `ipcs(1)`-handleiding](https://man.openbsd.org/ipcs.1)
4. [Consul-agentopstelling: scriptkontroles](https://developer.hashicorp.com/consul/docs/reference/agent/configuration-file/general)
5. [Consul-agentdiensregistrasie-API](https://developer.hashicorp.com/consul/api-docs/agent/service)
6. [Consul-ACL-opstelling](https://developer.hashicorp.com/consul/docs/reference/agent/configuration-file/acl)
7. [LibreOffice-hulp: maak ’n socket oop vir eksterne API-kliënte](https://help.libreoffice.org/latest/en-US/text/sbasic/shared/03/sf_intro.html)
8. [LibreOffice SDK: `XSystemShellExecute`](https://api.libreoffice.org/docs/idl/ref/interfacecom_1_1sun_1_1star_1_1system_1_1XSystemShellExecute.html)

{{#include ../../banners/hacktricks-training.md}}
