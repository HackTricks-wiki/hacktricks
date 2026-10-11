# Prosesenumerasie en dienspaaie

{{#include ../../banners/hacktricks-training.md}}

Die nuttige vraag is watter bevoorregte proses data of kode gebruik wat ’n gebruiker met minder voorregte kan beïnvloed. Ondersoek die proseshierargie, die aktiewe omgewing, oop lêers en die eenheid of skrip wat elke kandidaat geloods het.

## Karteer prosesse en eienaarskap

```bash
ps -eo user,pid,ppid,tty,comm,args --sort=ppid
pstree -alp 2>/dev/null
systemctl list-units --type=service --state=running 2>/dev/null
ss -lntup
```

’n Ouer-kind-verhouding tussen verskillende gebruikers kan normaal wees, maar ’n onverwagte oorgang regverdig ’n ondersoek van die oueropdrag, argumente, uitvoerbare lêer, werkgids en lêers waarna verwys word. Gebruik [users and sessions](../user-information/user-and-session-triage.md) om die eienaar- en aanmeldkonteks te interpreteer.

### Plaaslike virtuelemasjienkonsole

Ondersoek ’n QEMU-proses se `-spice`-opsies saam met sy luisteradres. [QEMU documents](https://www.qemu.org/docs/master/system/qemu-manpage.html) dat `disable-ticketing` SPICE-kliënte sonder verifikasie laat koppel. ’n Luisteraar wat aan loopback gebind is, kan steeds potensieel deur ander plaaslike gasheergebruikers bereik word. Bevestig die aktiewe luisteraar, verifikasie-opsies en plaaslike toegang voordat jy die opdragreël as ’n blootgestelde konsole beskou. Konsolebeheer raak die **guest**; om ’n guest-rekening te verkry of sy selflaaitoestand te verander, vereis afsonderlike toestande aan die guest-kant en verleen nie root op die virtualisasiegasheer nie. Lees prosesargumente en sokkiemetadata sonder om tydens passiewe enumerasie aan die guest te koppel of dit te herlaai.

’n Plaaslik bereikbare webkoppelvlak kan kode met sy diensrekening uitvoer, selfs wanneer die eerste shell nie toegang tot daardie rekening se lêers het nie. CVE-2023-0297 het byvoorbeeld pyLoad se `/flash/addcrypted2`-hantering geraak wanneer onbetroubare JavaScript Js2Py bereik het met Python-imports geaktiveer; die [upstream fix](https://github.com/pyload/pyload/commit/7d73ba7919e594d783b3411d7ddb87885aea782d) het `pyimport` gedeaktiveer. Kruiskontroleer die lopende proses se eienaar, luisteradres, endpoint-blootstelling en geïnstalleerde patch of vendor-backport voordat jy ’n pyLoad-proses as ’n eskalasiepad beskou. ’n Prosesnaam, oop poort of pakketweergawe alleen bewys nie blootstelling nie; passiewe enumerasie behoort nie ’n uitvoeringspayload te stuur nie.

### Bevoorregte aanmeldingshells wat ’n terminaal deel

’n Bevoorregte interaktiewe shell wat `su --login <user>` uitvoer sonder ’n onafhanklike pseudo-terminaal, kan sy terminaal met die laerbevoorregte aanmeldingshell deel. As daardie gebruiker se opstartlêer beheerbaar is en kode daarin `TIOCSTI` kan gebruik om terminaalinvoer in te spuit, kan die invoer die bevoorregte shell bereik wanneer dit hervat. [The util-linux `su` manual](https://man7.org/linux/man-pages/man1/su.1.html#SECURITY_NOTES) beskryf die risiko van ’n gedeelde terminaal en beveel `su --pty`/`-P` vir interaktiewe gebruik aan; `su -c` begin ’n afsonderlike sessie sonder ’n beherende terminaal. Die risiko vereis die werklike ouershell, terminaalverhouding, teikenopstartlêer en kernbeleid. ’n Prosesnaam of `su -l`-argument alleen is slegs ’n leidraad vir ondersoek.

Ondersoek die waargenome prosesboom en TTY-kolomme, en daarna die leesbare lanseerder en eienaarskap/toestemmings van die opstartlêer. Op Linux kan `/proc/sys/dev/tty/legacy_tiocsti`, indien dit bestaan, help om die beleid te interpreteer; die afwesigheid daarvan bewys nie dat dit veilig is nie. [The Linux `TIOCSTI` manual](https://man7.org/linux/man-pages/man2/TIOCSTI.2const.html) meld dat die bewerking sedert Linux 6.2 moontlik `CAP_SYS_ADMIN` vereis wanneer hierdie sysctl false is. Moenie die ioctl uitvoer bloot om die gasheer te enumereer nie.

’n Databasisrekening kan soms die teikengebruiker se opstartlêer wysig sonder direkte skryftoegang tot die lêerstelsel. PostgreSQL-bedienerkant-`COPY ... TO 'filename'` skryf as die databasisbediener se OS-rekening, maar [PostgreSQL limits](https://www.postgresql.org/docs/current/sql-copy.html) hierdie lêervorm tot databasis-superusers of rolle soos `pg_write_server_files`. Bevestig beide die databasisrol en die databasisbediener se OS-lêertoestemmings; ’n toepassing se verbindingstring verleen nie op sigself skryftoegang tot lêers nie. Hou die bevoorregte lanseerder en die databasisrekening se vermoëns apart wanneer jy die ketting beoordeel.

## Ondersoek runtime-artefakte

```bash
readlink /proc/<PID>/exe
tr '\0' ' ' </proc/<PID>/cmdline; echo
ls -l /proc/<PID>/fd 2>/dev/null
lsof -p <PID> 2>/dev/null
lsof +L1 2>/dev/null
```

Verwyderde uitvoerbare lêers en verwyderde maar steeds oop lêers bly verwys totdat hul laaste descriptor gesluit word. Hulle kan bewyse of toeganklike geheime bewaar. Prosesomgewings en geheue kan credentials bevat, maar toegang tot ’n ander proses word beperk deur eienaarskap, `/proc`-monteeropsies, Yama se ptrace-beleid en ander sekuriteitsmaatreëls. Sien [file descriptors](../main-system-information/filesystem-links-and-file-descriptors.md) en [post-exploitation credential hunting](../post-exploitation/README.md) vir verwante tegnieke.

Gestoorde syscall-traces is nog ’n lêertoestemminggrens. [`strace` records syscall arguments to an output file](https://man7.org/linux/man-pages/man1/strace.1.html), dus kan ’n leesbare spoor van [`execve` arguments](https://man7.org/linux/man-pages/man2/execve.2.html) ’n wagwoord blootlê wat ’n bevoorregte taak op sy opdragreël deurgegee het. Stel eers vas dat die huidige gebruiker die spesifieke spoor kan lees en dat die argument werklik ’n credential bevat; ’n latere Unix-rekeningoorskakeling vereis afsonderlike bewys dat die credential daar aanvaar word. Lêermetadata is ’n nuttige passiewe leidraad sonder dat elke spoor geskandeer of die inhoud daarvan tydens roetine-enumerasie vertoon hoef te word.

## Bevoorregte kantooroutomatiseringsockets

LibreOffice en OpenOffice kan hul UNO API via ’n `--accept=socket,host=<host>,port=<port>;urp;`-argument blootstel. ’n Kantoorproses wat deur root besit word en ’n bereikbaar endpoint het, kan ’n plaaslike gebruiker met minder voorregte toelaat om API-dienste in daardie proses se sekuriteitskonteks aan te roep. Die `SystemShellExecute`-diens sluit ’n bewerking in om ’n stelselopdrag te begin. Binding aan loopback beperk bereikbaarheid van buite, maar laat die socket steeds bereikbaar vir plaaslike gebruikers, tensy ’n ander beheer toegang voorkom.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
ps -eo user,args | grep -E '[s]office|[l]ibreoffice|[o]penoffice'
ss -ltn 2>/dev/null
```

Korrelleer die proseseienaar, die presiese `--accept`-argument en die huidige luisteradres en -poort. ’n Gekonfigureerde acceptor wat nie kon bind nie, is slegs ’n leidraad; moenie tydens passiewe enumerasie aan die API koppel of dit aanroep nie. Moenie bloot om hierdie toestand te toets ’n geprivilegieerde office-instansie begin nie.

## System V shared memory wat deur geprivilegieerde prosesse gebruik word

’n Helper wat deur root besit word, kan ’n System V shared-memory-segment skep waaraan ’n ander gebruiker kan skryf. As die helper later data uit daardie segment in ’n shell-opdrag of ’n ander sensitiewe bewerking vertrou, kruis die segment ’n privilegiegrens, selfs wanneer die uitvoerbare lêer en sy lêers beskerm is. `shmget()` neem toegangstoestemmings van die laagste nege bisse van sy vlae; modus `0666` laat ander gebruikers toe om te skryf, terwyl ’n `IPC_CREAT`-vlag nie daardie toestemmings beperk nie. Ondersoek aktiewe segmente passief met `ipcs -m` en korreleer hul eienaar, modus en leeftyd met die geprivilegieerde proses en sy invoerhantering. ’n Wêreldskryfbare segment bewys op sigself nie dat opdragte uitgevoer kan word nie.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
ipcs -m
```

System V-segmente verskil van POSIX-gedeeldegeheuelêers onder `/dev/shm`. ’n Segment wat net vir ’n oomblik geskep word, is moontlik afwesig uit ’n enkele `ipcs`-kiekie, dus sluit leë uitvoer nie ’n helper uit wat gedeelde geheue gebruik nie. Gaan die bronkode of binêre gedrag daarvan na, asook enige `sudo`-reël wat dit begin; moenie die bevoorregte helper aanroep net om ’n segment tydens enumerasie te laat verskyn nie. Die [IPC-namespace-gids](../containers-namespaces/container-security/protections/namespaces/ipc-namespace.md) verduidelik hoe namespaces sigbaarheid beïnvloed.<sup>[[2]](#references)[[3]](#references)</sup>

## Consul-agent-skripkontroles

Consul kan skripgesondheidstoetse uitvoer met die bedryfstelsel-identiteit van sy agent. As ’n agent as root loop, `enable_script_checks` aktiveer en ’n gebruiker met laer voorregte toelaat om ’n diens met ’n skripkontrole via die plaaslike HTTP API te registreer, kan daardie gebruiker veroorsaak dat opdragte as root uitgevoer word. Deur die API slegs aan `127.0.0.1` te bind, kan plaaslike gebruikers dit steeds bereik. Die `enable_local_script_checks`-instelling is enger: dit sluit skripkontroles uit wat deur HTTP API-registrasies ingedien word. Wanneer Consul ACLs geaktiveer is, vereis diensregistrasie `service:write`; ’n `acl.default_policy=allow`-reël op sigself bewys nie dat ’n anonieme oproeper kan registreer nie. Gaan die werklike agent-identiteit, gelaaide instellings, API-binding en magtiging saam na.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

```bash
ps -eo user,args | grep '[c]onsul agent'
ls -l /etc/consul.d 2>/dev/null
```

Volg die lopende agent se `-config-dir`- en `-config-file`-argumente na die relevante konfigurasie, en inspekteer slegs die script-check- en ACL-veldname en -instellings. Konfigurasielêers kan ook gossip-sleutels of tokens bevat; moenie dit in gedeelde logs plak nie. Moenie ’n diens registreer of ’n gesondheidkontrole uitvoer bloot om hierdie toestand te lys nie.

’n Aparte plaaslike-lêerpad bestaan wanneer ’n gebruiker met laer voorregte **skryf- en soektoegang** het tot die gids wat deur ’n root-agent se `-config-dir` benoem word: ’n nuwe `.hcl`- of `.json`-diensdefinisie kan uit daardie gids gelaai word. Soek- en skryftoegang tot ’n gids kan dit moontlik maak om ’n lêer by te voeg, selfs wanneer die gidslys nie vertoon mag word nie. Vir root-opdraguitvoering, bevestig dat die agent daardie gids werklik laai, dat die **effektiewe** script-check-instelling plaaslike definisies toelaat, dat die definisie gelaai word, en dat die agent root-voorregte behou. [Consul dokumenteer](https://developer.hashicorp.com/consul/docs/fundamentals/agent#reloadable-configurations) watter instellings en gesondheidkontroledefinisies herlaai kan word; dit kan nodig wees om te herbegin om script checks te aktiveer, dus moet jy die geïnstalleerde weergawe se gedrag verifieer. Wanneer ACLs die agent beskerm, vereis [`consul reload` die `agent:write`-regte](https://developer.hashicorp.com/consul/api-docs/agent#reload-agent); KV-skryftoestemming alleen verskaf dit nie. Beskou aanduidings dat ’n gids skryfbaar is as ’n rede vir hersiening, nie as bewys van ’n gemagtigde herlaai, herbegin of opdraguitvoering nie. Inspekteer paaie, toestemmings en beleid sonder om konfigurasie te skryf of die API aan te roep.

## Volg die diensuitvoeringsketting

```bash
systemctl cat <unit>.service
systemctl show <unit>.service -p User -p Group -p ExecStart -p EnvironmentFiles -p WorkingDirectory
namei -l /path/from/ExecStart
```

Kontroleer die unit, drop-ins, `EnvironmentFile=`, helperskripte, relatiewe opdragte, skryfbare gidse en socket-aktivering. ’n Root-besitte unit kan steeds onveilig wees as dit ’n konfigurasie of skrip lees wat deur ’n gebruiker geskryf kan word. Die [arbitrary file write](../interesting-files-permissions/write-to-root.md)-bladsy dek algemene misbruikpaaie vir services en units. Monitor kortstondige take met [pspy](https://github.com/DominicBreuker/pspy) of oudit-/prosestelemetrie wanneer ’n eenmalige `ps`-lys hulle miskyk.

Vir ’n pasgemaakte **xinetd**-service, korreleer die geaktiveerde stanza se `server`, `user` en toegangsbeheer met die aktiewe listener en presiese uitvoerbare lêer. Die [`user`-instelling](https://manpages.debian.org/testing/xinetd/xinetd.conf.5.en.html) kies die prosesidentiteit waaronder die proses begin word, terwyl ’n set-user-ID-bit op die uitvoerbare lêer sy effektiewe identiteit afsonderlik kan verander as [`execve` daardie oorgang toelaat](https://man7.org/linux/man-pages/man2/execve.2.html). ’n Bereikbare, bevoorregte binêre lêer wat onbetroubare invoer aanvaar, verdien ’n vanlyn bronkode- of disassemblagehersiening vir geheueveiligheidsfoute, soos ’n onbeperkte [`scanf`-stringomskakeling](https://www.gnu.org/software/libc/manual/html_node/String-Input-Conversions.html) na ’n vaste buffer. Die service-kartering en set-user-ID-metadata is leidrade, nie bewys van so ’n fout nie; moenie ineenstortingsinvoer stuur of die aktiewe bevoorregte service ontfout tydens passiewe enumerasie nie.

Vir ’n pasgemaakte, bevoorregte listener met leesbare bronkode, hersien elke lengte wat deur die oproeper beheer word en wat vir ’n kopieerbewerking soos [`memcpy`](https://man7.org/linux/man-pages/man3/memcpy.3.html) gebruik word. Om slegs te kontroleer dat die huidige skryfindeks binne ’n vaste buffer is, bewys nie dat die **kopielengte** in die oorblywende spasie pas nie; verifieer `copy_length <= capacity - index` nadat bevestig is dat die indeks binne die grense is, en kontroleer getekendheid en rekenkundige oorloop. Dit is slegs ’n hersieningsleidraad wanneer die invoer daardie bewerking bereik, die listener vir die gebruiker met laer voorregte toeganklik is, en die proses ’n hoër effektiewe identiteit behou. Inspekteer bronkode en prosesmetadata vanlyn; moenie tydens enumerasie ineenstortingsinvoer na die aktiewe service stuur nie.

Op stelsels wat **Upstart** gebruik, kan stelseltaakdefinisies onder `/etc/init/*.conf` voorkom. ’n Taaklêer wat deur die huidige gebruiker geskryf kan word, is relevant wanneer die aktiewe init-daemon daardie presiese taak laai, sy `script`- of `exec`-stanza as ’n identiteit met hoër voorregte loop, en die gebruiker dit deur ’n toegelate `initctl`-opdrag of ’n ander werklike sneller kan begin. ’n sudo-toekenning vir `initctl` bewys op sigself nie dat enige taaklêer skryfbaar is of dat ’n gewysigde taak sal loop nie. Kontroleer die presiese taaklêertoestemmings, effektiewe run-as-instelling, aktiewe daemon en sneller sonder om die taak tydens enumerasie te wysig of te begin. Sien die handleidings vir [Upstart-taakkonfigurasie](https://manpages.ubuntu.com/manpages/trusty/man5/init.5.html) en [`initctl`](https://manpages.ubuntu.com/manpages/xenial/man8/initctl.8.html).

’n Leesbare outo-aanmeldwagwoordlêer, soos `/etc/autologin/passwd` op stelsels waarvan die [opstarttaak daardie presiese pad lees](https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/master/chromeos-base/autologin/files/init/autologin.conf), is ’n leidraad vir blootgestelde geloofsbriewe. Bevestig dat die opstarttaak geïnstalleer is en die lêer gebruik, en verifieer dan afsonderlik of die wagwoord vir ’n ander plaaslike rekening of service geldig is. Die lêernaam alleen bewys nie dat die wagwoord hergebruik word nie; teken pad- en toegangmetadata aan sonder om die wagwoord in gedeelde enumerasie-uitvoer te plaas.

’n Unit se `ExecStart=` of ’n geskeduleerde opdrag kan die presiese padnaam van ’n skrip in ’n lys-onleesbare gids bekend maak. [Soektoestemming op ’n gids](https://man7.org/linux/man-pages/man7/path_resolution.7.html) kan die huidige identiteit steeds toelaat om daardie bekende pad te volg; bevestig soektoegang op elke ouergids en leestoestemming op die lêer eerder as om aan te neem dat ’n mislukte gidslys dit beskerm. ’n Leesbare skrip kan ’n oordraggeloofsbrief bevat, maar om na ’n ander rekening oor te skakel vereis dat daardie geloofsbrief geldig bly en onafhanklik daar aanvaar word. Teken die pad en toestemmingsbewyse aan sonder om geheime waardes in gedeelde logs te druk.

Vir ’n geskeduleerde CommonJS Node.js-skrip, hersien kaal invoere soos `require('package')`, selfs wanneer die skrip self leesalleen is. [Node soek `node_modules` langs die lêer wat invoer en dan in sy ouergidse](https://nodejs.org/api/modules.html#loading-from-node_modules-folders), voordat dit na gekonfigureerde globale paaie terugval. ’n Gebruiker met laer voorregte wat een van daardie ouergidse kan **skryf en soek**, kan moontlik ’n pakket skep wat vroeër ooreenstem. Bevestig dat die presiese invoer bereik word, die gekose pakket nie ’n ingeboude module is nie, die relevante pad geskep of verander kan word, die module daar in die geïnstalleerde runtime opgelos word, en ’n taak met hoër voorregte dit by ’n toekomstige uitvoering sal laai. Skryfbare ouergidsmetadata is slegs ’n aanduiding vir hersiening; inspekteer die skrip en skeduleerder passief sonder om ’n module te plaas of die taak te aktiveer.

’n Privaat Python-pakketindeks is nog ’n vertrouensgrens wanneer ’n outomatiese taak pakkette onder ’n ander OS-identiteit installeer. Korreleer die presiese taak en run-as-rekening met sy gekonfigureerde indeks, geselekteerde pakketname en of ’n gebruiker met laer voorregte ’n pakket kan publiseer of vervang wat die taak werklik sal installeer. Die bou van ’n brondistribusie kan die bou-agterkant of verouderde `setup.py` onder die installeerder se identiteit laat loop; die invoer van die geïnstalleerde pakket is ’n afsonderlike uitvoeringspad. ’n Indekslistener, leesbare oplaaierwagwoord-hash of pakketlêernaam alleen bewys nie daardie ketting nie. Hersien die taak, indeksmagtiging en pakketherkoms sonder om tydens enumerasie enigiets op te laai of te installeer. Sien [pip se boustelsel-koppelvlak](https://pip.pypa.io/en/stable/reference/build-system/) en [riglyne vir veilige installasie](https://pip.pypa.io/en/stable/topics/secure-installs/).

’n Bevoorregte agent kan ’n taakry navraag doen wat deur ’n aparte webservice of container bestuur word. As ’n identiteit met laer vertroue die service se taakdatabasis kan skryf, bepaal of daardie rye werklik aan die agent bedien word en of ’n opdragtaak met die agent se OS-identiteit loop. Bevestig databasis-skryftoegang, die teikensessie of roeteringsleutel, aktiewe navrae, taakmagtiging en die agent se effektiewe gebruiker afsonderlik. Root binne ’n container impliseer nie op sigself toegang as host-root nie; die grens word slegs oorgesteek as ’n host-bevoorregte verbruiker aanvallerbeheerde taakdata uitvoer. Inspekteer proses-, databasislêer- en servicemetadata sonder om die ry te wysig of tydens enumerasie ’n taak te stuur.

’n Herhalende taak kan eerder ’n opdrag lees uit ’n konfigurasie-ry in ’n toepassingsdatabasis. Bevestig dat die databasisrol met laer voorregte daardie presiese ry kan verander, dat die aktiewe taak dit ná die verandering lees, en dat die waarde ’n shell of soortgelyke opdraguitvoerder onder ’n OS-identiteit met hoër voorregte bereik. Databasis-skryftoegang of ’n waarde wat soos ’n opdrag lyk, bewys nie op sigself uitvoering nie; inspekteer die taak en toestemmings sonder om die ry tydens passiewe enumerasie te verander.

’n Geplaasde boodskap kan ook ’n URL eerder as kode bevat. As ’n bevoorregte verbruiker daardie URL haal en die antwoord as ’n Lua- of ander uitvoerbare plugin laai, verifieer die uitgewer se toestemming op die presiese exchange en roeteringsleutel, die binding aan die verbruikte queue, die haal- en plugin-laaipad, en die worker se effektiewe identiteit. [RabbitMQ roeteer gepubliseerde boodskappe deur exchanges](https://www.rabbitmq.com/docs/exchanges); ’n broker-listener of geldige aanmelding bewys op sigself nie aflewering aan hierdie worker nie. Onderskepte cleartext-broker-geloofsbriewe is ’n afsonderlike leidraad wat werklike pakkievasleggings-toegang en leesbare verkeer vereis; dit bewys nie publiseerbevoegdheid nie. ’n Lua-plugin kan shell-opdragte deur [`os.execute`](https://www.lua.org/manual/5.4/manual.html#pdf-os.execute) uitvoer slegs as daardie API in sy runtime beskikbaar is. Hersien konfigurasie en kode sonder om verkeer vas te vang, boodskappe te publiseer of ’n plugin tydens passiewe enumerasie te gaan haal.

Wanneer ’n bevoorregte Python-service ’n plaaslike HTTP- of socket-eindpunt blootstel, kan ’n leesbare skrip ’n invoer-na-kode-pad onthul, selfs al verhinder sy lêertoestemmings wysiging. Korreleer die aktiewe proses en unit-identiteit met die presiese skrip, listener, roetemagtiging en velde wat deur die oproeper beheer word. Volg dan daardie velde deur ontleding en validering tot by ’n dinamiese `eval()`- of `exec()`-sink. In die besonder kan die bou van ’n nuwe f-string uit versoekteks en die evaluering daarvan aanvalleraangeleverde vervangingsvelde as Python-uitdrukkings interpreteer ([Python se `eval`-waarskuwing](https://docs.python.org/3/library/functions.html#eval); [f-string-semantiek](https://docs.python.org/3/reference/lexical_analysis.html#f-strings)). ’n Losstaande `eval`-treffer of loopback-binding bewys nie dat ’n onbetroubare oproeper die sink bereik nie; hersien die werklike datavloei en toegangsbeheer sonder om tydens enumerasie ’n toetspayload te stuur.

’n Getekende-versoekhek op daardie roete vereis ’n eie hersiening. As leesbare bronkode die ondertekeningsleutel aflei deur ’n aantoonbaar klein of voorspelbare uitsetruimte, en die service ’n geldige getekende voorbeeld blootstel, beskerm die handtekening moontlik nie meer ’n bevoorregte `eval()`-sink nie. Verifieer die presiese sleutelafleiding en verifieerder, die aktiewe service-identiteit en plaaslike oproepertoegang, en of die getekende veld die sink bereik; ’n invoer van Python se [`random`-module](https://docs.python.org/3/library/random.html) of ’n voorbeeldhandtekening bewys nie een van daardie voorwaardes nie. Python waarsku ook dat die beperking van `__builtins__` [nie ’n sekuriteitsgrens vir onbetroubare `eval()`-invoer is nie](https://docs.python.org/3/library/functions.html#eval). Hou sleutelontleding vanlyn en moenie tydens passiewe enumerasie vervalste versoeke indien nie.

’n Leë maar skryfbare `/etc/systemd/system/<unit>.service.d`-gids is relevant selfs wanneer die unitlêer en elke bestaande drop-in beskerm is: die gebruiker kan ’n nuwe `.conf`-oorheersing skep. Kontroleer dat die huidige identiteit in die gids kan skryf en soek, dat die unit gelaai is en as root loop, en of ’n daemon-herlaai gevolg deur ’n herbegin sal plaasvind. ’n Herlaai- of herbeginreg, timer of latere selflaai kan die verandering van krag maak; skryftoegang tot die gids alleen voer dit nie onmiddellik uit nie.

Vir lopende services, volg letterlike `EnvironmentFile=`-paaie vanaf die unit se `[Service]`-afdeling, insluitend lêers waarvan die name nie met `.env` begin nie. As ’n gebruiker met lae voorregte een kan lees, lys geloofsbriefagtige sleutelname soos `API_TOKEN` of `APP_SECRET_KEY` sonder om die waardes in gedeelde logs te druk. Kontroleer drop-in-oorheersings en opsionele `-`-voorvoegsels wanneer die effektiewe unit beoordeel word. Leesbaarheid is ’n leidraad vir blootgestelde geloofsbriewe; die waarde moet steeds geldig wees vir ’n bevoorregte handeling om eskalasie te bewerkstellig.

### Bevoorregte verwerking van onbetroubare oplaaie

’n Lêerwagter wat as root loop, kan lêers uit ’n oplaaigids wat deur gebruikers geskryf kan word, aan ’n kortstondige ontleder of uittrekker oorhandig. Volg die lopende wagter se ouerskrip of service en bevestig die presiese gids, wie lêers daar kan plaas, die child-opdrag en sy argumente, en die identiteit waaronder die child loop. ’n Prosessnapshot kan die wagter wys terwyl dit die uittrekker tussen oplaaie miskyk. Moenie ’n toetspayload plaas of die wagter tydens passiewe enumerasie aktiveer nie.

Een konkrete voorbeeld is Binwalk se uittrekmodus (`-e`) wat aanvallerbeheerde PFS-data verwerk. [CVE-2022-4510](https://github.com/ReFirmLabs/binwalk/pull/617) het die PFS-uittrekker toegelaat om buite die beoogde gids te skryf, insluitend na ’n plugin-pad wat Binwalk later kon laai. Die stroomopprojek het die regstelling in [2.3.4](https://github.com/ReFirmLabs/binwalk/releases/tag/v2.3.4) ingesluit, maar terugportering deur verspreidings kan ’n ouer vertoonde weergawe behou; kontroleer die geïnstalleerde pakket se sekuriteitstatus, soos die [Debian-spoorsnyer](https://security-tracker.debian.org/tracker/CVE-2022-4510), voordat jy die toepaslikheid beoordeel. ’n Geïnstalleerde Binwalk-weergawe alleen bewys nie ’n voorreg-eskalasiepad nie: ’n meer bevoorregte proses moet die uittrekking werklik uitvoer op invoer wat die gebruiker met laer voorregte kan beheer.

### Geskeduleerde bouwerk met plaaslike afhanklikhede

’n Geskeduleerde `cargo run` herkompileer bronkode as die taak se run-as-gebruiker. Inspekteer die manifes se plaaslike `{ path = "..." }`-afhanklikhede en die bronkode- en ouergidstoestemmings van elke afhanklikheid, nie net dié van die hoofcrate nie. As ’n gebruiker met laer voorregte ’n afhanklikheid kan wysig wat Cargo kompileer, en die geskeduleerde taak die resultaat uitvoer, kan die gekompileerde kode as daardie run-as-gebruiker loop. Bevestig die effektiewe skeduleerderopdrag, werkgids, afhanklikheidsresolusie en of ’n herbou sal plaasvind; ’n skryfbare Rust-bronlêer elders is slegs ’n leidraad. Om die manifes en padmetadata te lees, is genoeg vir passiewe triage. Sien die [Cargo-dokumentasie oor pad-afhanklikhede](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#specifying-path-dependencies).

## Xvfb-raambufferlêers

`Xvfb -fbdir <directory>` gebruik geheuegekoppelde lêers met die naam `Xvfb_screen<n>` vir sy virtuele skerms. As ’n ander gebruiker se lopende Xvfb-proses ’n gids aandui waarvan die skermlêers vir die huidige gebruiker leesbaar is, kan die raambuffer daardie gebruiker se lessenaarinhoud blootlê. Bevestig die proses, lêereienaarskap en toestemmings saam; ’n leesbare lêer alleen bewys nie dat bruikbare inhoud op die skerm is nie. Inspekteer eers paaie en metadata, sonder om beelddata na gedeelde enumerasie-uitvoer te kopieer. Die [Xvfb-handleiding](https://xorg.freedesktop.org/archive/X11R7.5/doc/man/man1/Xvfb.1.html) dokumenteer die gedrag van `-fbdir`.

```bash
pgrep -a -x Xvfb
ls -l /path/from/-fbdir/Xvfb_screen*
```

## References

1. [Linux `shmget(2)`-handleiding](https://man7.org/linux/man-pages/man2/shmget.2.html)
2. [Linux `ipcs(1)`-handleiding](https://man7.org/linux/man-pages/man1/ipcs.1.html)
3. [OpenBSD `ipcs(1)`-handleiding](https://man.openbsd.org/ipcs.1)
4. [Consul-agentkonfigurasie: skripkontroles](https://developer.hashicorp.com/consul/docs/reference/agent/configuration-file/general)
5. [Consul-agentdiensregistrasie-API](https://developer.hashicorp.com/consul/api-docs/agent/service)
6. [Consul-ACL-konfigurasie](https://developer.hashicorp.com/consul/docs/reference/agent/configuration-file/acl)
7. [LibreOffice-hulp: maak ’n socket oop vir eksterne API-kliënte](https://help.libreoffice.org/latest/en-US/text/sbasic/shared/03/sf_intro.html)
8. [LibreOffice SDK: `XSystemShellExecute`](https://api.libreoffice.org/docs/idl/ref/interfacecom_1_1sun_1_1star_1_1system_1_1XSystemShellExecute.html)

{{#include ../../banners/hacktricks-training.md}}
