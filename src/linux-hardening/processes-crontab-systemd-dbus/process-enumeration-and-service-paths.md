# Prosesenumerasie en dienspaaie

{{#include ../../banners/hacktricks-training.md}}

Die nuttige vraag is watter bevoorregte proses data of kode gebruik wat ’n gebruiker met minder voorregte kan beïnvloed. Inspekteer die prosesboom, aktiewe omgewing, oop lêers en die unit of script wat elke kandidaat geloods het.

## Karteer prosesse en eienaarskap

```bash
ps -eo user,pid,ppid,tty,comm,args --sort=ppid
pstree -alp 2>/dev/null
systemctl list-units --type=service --state=running 2>/dev/null
ss -lntup
```

'n Ouer-kind-verhouding tussen verskillende gebruikers kan normaal wees, maar 'n onverwagte oorgang regverdig 'n hersiening van die oueropdrag, argumente, uitvoerbare lêer, werkgids en lêers waarna verwys word. Gebruik [users and sessions](../user-information/user-and-session-triage.md) om die eienaar- en aanmeldkonteks te interpreteer.

### Plaaslike virtuelemasjienkonsoles

Hersien 'n QEMU-proses se `-spice`-opsies saam met sy luisteradres. [QEMU documents](https://www.qemu.org/docs/master/system/qemu-manpage.html) dat `disable-ticketing` SPICE-kliënte sonder verifikasie laat koppel. 'n Luisteraar wat aan loopback gebind is, kan steeds moontlik deur ander plaaslike gasheergebruikers bereik word. Bevestig die aktiewe luisteraar, verifikasie-opsies en plaaslike toegang voordat jy die opdragreël as 'n blootgestelde konsole beskou. Konsolebeheer raak die **guest**; om 'n gasheerrekening te bekom of sy selflaaitoestand te verander, vereis afsonderlike toestande binne die gas en verleen nie root op die virtualisasiegasheer nie. Lees prosesargumente en sokmetadata sonder om tydens passiewe enumerasie aan die gas te koppel of dit te herlaai.

'n Plaaslik bereikbare webkoppelvlak kan kode met sy diensrekening uitvoer, selfs wanneer die eerste shell nie toegang tot daardie rekening se lêers het nie. CVE-2023-0297 het byvoorbeeld pyLoad se `/flash/addcrypted2`-hantering geraak wanneer onbetroubare JavaScript Js2Py bereik het met Python-invoere geaktiveer; die [upstream fix](https://github.com/pyload/pyload/commit/7d73ba7919e594d783b3411d7ddb87885aea782d) het `pyimport` gedeaktiveer. Vergelyk die lopende proses se eienaar, luisteradres, eindpuntblootstelling en geïnstalleerde pleister of verskaffer-terugvoerpleister voordat jy 'n pyLoad-proses as 'n eskalasiepad beskou. 'n Prosesnaam, oop poort of pakketweergawe alleen bewys nie blootstelling nie; passiewe enumerasie behoort nie 'n uitvoerlading te stuur nie.

### Bevoorregte aanmeldingshells wat 'n terminaal deel

'n Bevoorregte interaktiewe shell wat `su --login <user>` uitvoer sonder 'n onafhanklike pseudo-terminaal, kan sy terminaal met die laerbevoorregte aanmeldingshell deel. As daardie gebruiker se opstartlêer beheerbaar is en kode daarin `TIOCSTI` kan gebruik om terminaalinvoer in te spuit, kan die invoer die bevoorregte shell bereik wanneer dit hervat. [The util-linux `su` manual](https://man7.org/linux/man-pages/man1/su.1.html#SECURITY_NOTES) beskryf die risiko van 'n gedeelde terminaal en beveel `su --pty`/`-P` vir interaktiewe gebruik aan; `su -c` begin 'n aparte sessie sonder 'n beherende terminaal. Die risiko vereis die werklike ouershell, terminaalverhouding, teikenopstartlêer en kernbeleid. 'n Prosesnaam of `su -l`-argument alleen is bloot 'n leidraad vir hersiening.

Inspekteer die waargenome prosesboom en TTY-kolomme, en daarna die leesbare lanseerder en die eienaarskap/toestemmings van die opstartlêer. Op Linux kan `/proc/sys/dev/tty/legacy_tiocsti`, indien dit bestaan, help om die beleid te interpreteer; die afwesigheid daarvan bewys nie dat dit veilig is nie. [The Linux `TIOCSTI` manual](https://man7.org/linux/man-pages/man2/TIOCSTI.2const.html) meld dat die bewerking sedert Linux 6.2 moontlik `CAP_SYS_ADMIN` vereis wanneer hierdie sysctl false is. Moenie die ioctl aanroep bloot om die gasheer te enumereer nie.

'n Databasisrekening kan soms die teikengebruiker se opstartlêer verander sonder direkte skryftoegang tot die lêerstelsel. PostgreSQL-bedienerkantse `COPY ... TO 'filename'` skryf as die databasisbediener se OS-rekening, maar [PostgreSQL limits](https://www.postgresql.org/docs/current/sql-copy.html) beperk hierdie lêervorm tot databasis-supergebruikers of rolle soos `pg_write_server_files`. Bevestig beide die databasisrol en die bediener se OS-lêertoestemmings; 'n toepassingsverbindingsstring alleen verleen nie skryftoegang tot lêers nie. Beoordeel die bevoorregte lanseerder en die databasisrekening se vermoëns afsonderlik wanneer jy die ketting evalueer.

## Inspekteer looptydartefakte

```bash
readlink /proc/<PID>/exe
tr '\0' ' ' </proc/<PID>/cmdline; echo
ls -l /proc/<PID>/fd 2>/dev/null
lsof -p <PID> 2>/dev/null
lsof +L1 2>/dev/null
```

Geskrapte uitvoerbare lêers en geskrapte maar steeds oop lêers bly verwys totdat hul laaste descriptor gesluit word. Hulle kan bewyse of toeganklike geheime bewaar. Prosesomgewings en geheue kan geloofsbriewe bevat, maar toegang tot ’n ander proses word beperk deur eienaarskap, `/proc`-monteeropsies, Yama se ptrace-beleid en ander sekuriteitskontroles. Sien [file descriptors](../main-system-information/filesystem-links-and-file-descriptors.md) en [post-exploitation credential hunting](../post-exploitation/README.md) vir verwante tegnieke.

Gestoorde syscall-traces is nog ’n lêertoestemminggrens. [`strace` teken syscall-argumente in ’n uitvoerlêer aan](https://man7.org/linux/man-pages/man1/strace.1.html), dus kan ’n leesbare trace van [`execve`-argumente](https://man7.org/linux/man-pages/man2/execve.2.html) ’n wagwoord blootlê wat ’n bevoorregte taak op sy opdragreël deurgegee het. Stel eers vas dat die huidige gebruiker die spesifieke trace kan lees en dat die argument werklik ’n geloofsbrief bevat; ’n latere Unix-rekening-oorgang vereis afsonderlike bewys dat die geloofsbrief daar aanvaar word. Lêermetadata is ’n nuttige passiewe leidraad sonder om elke trace te skandeer of die inhoud daarvan tydens roetine-enumerasie te vertoon.

## Bevoorregte kantooroutomatiseringsokke

LibreOffice en OpenOffice kan hul UNO API via ’n `--accept=socket,host=<host>,port=<port>;urp;`-argument blootstel. ’n Kantoorproses wat deur root besit word en ’n bereikbare eindpunt het, kan ’n plaaslike gebruiker met laer voorregte toelaat om API-dienste in daardie proses se sekuriteitskonteks aan te roep. Die `SystemShellExecute`-diens sluit ’n bewerking in om ’n stelselopdrag te begin. Binding aan loopback beperk bereikbaarheid op afstand, maar laat die sok steeds vir plaaslike gebruikers bereikbaar, tensy ’n ander beheer toegang verhinder.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
ps -eo user,args | grep -E '[s]office|[l]ibreoffice|[o]penoffice'
ss -ltn 2>/dev/null
```

Korrelleer die proseseienaar, die presiese `--accept`-argument en die huidige luisteradres en -poort. ’n Geconfigureerde acceptor wat nie kon bind nie, is slegs ’n leidraad; moenie tydens passiewe enumerasie aan die API koppel of dit aanroep nie. Vermy dit om bloot hierdie toestand te toets ’n bevoorregte office-instansie te begin.

## System V-gedeelde geheue wat deur bevoorregte prosesse gebruik word

’n Hulpdiens wat deur root besit word, kan ’n System V-gedeeldegeheuesegment skep waarna ’n ander gebruiker kan skryf. As die hulpdiens later data uit daardie segment in ’n shell-opdrag of ’n ander sensitiewe bewerking vertrou, kruis die segment ’n bevoorregtingsgrens, selfs wanneer die uitvoerbare lêer en sy lêers beskerm is. `shmget()` neem toegangstoestemmings van die laagste nege bisse van sy vlae; modus `0666` laat ander gebruikers toe om te skryf, terwyl ’n `IPC_CREAT`-vlag nie daardie toestemmings beperk nie. Inspekteer aktiewe segmente passief met `ipcs -m` en korreleer hul eienaar, modus en leeftyd met die bevoorregte proses en die hantering van sy invoer. ’n Wêreldskryfbare segment alleen bewys nie dat opdragte uitgevoer kan word nie.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
ipcs -m
```

System V-segmente verskil van POSIX-gedeeldegehe lêers onder `/dev/shm`. ’n Segment wat net vir ’n oomblik geskep word, kan ontbreek in ’n enkele `ipcs`-momentopname; leë uitvoer sluit dus nie ’n helper uit wat gedeelde geheue gebruik nie. Gaan die bronkode of binêre gedrag na, asook enige `sudo`-reël wat dit begin; moenie die bevoorregte helper uitvoer net om ’n segment tydens enumerasie te laat verskyn nie. Die [IPC-namespace-gids](../containers-namespaces/container-security/protections/namespaces/ipc-namespace.md) verduidelik hoe namespaces sigbaarheid beïnvloed.<sup>[[2]](#references)[[3]](#references)</sup>

## Consul-agent-skripkontroles

Consul kan skripgesondheidskontroles uitvoer met die bedryfstelsel-identiteit van sy agent. As ’n agent as root loop, `enable_script_checks` aktiveer en ’n gebruiker met laer voorregte toelaat om ’n diens met ’n skripkontrole via die plaaslike HTTP API te registreer, kan daardie gebruiker opdragte laat uitvoer wat as root loop. As die API slegs aan `127.0.0.1` gebind is, kan plaaslike gebruikers dit steeds bereik. Die instelling `enable_local_script_checks` is enger: dit sluit skripkontroles uit wat via HTTP API-registrasies ingedien word. Wanneer Consul ACLs geaktiveer is, vereis diensregistrasie `service:write`; ’n `acl.default_policy=allow`-reël op sigself bewys nie dat ’n anonieme oproeper kan registreer nie. Gaan die agent se werklike identiteit, gelaaide instellings, API-binding en magtiging saam na.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

```bash
ps -eo user,args | grep '[c]onsul agent'
ls -l /etc/consul.d 2>/dev/null
```

Volg die lopende agent se `-config-dir`- en `-config-file`-argumente na die relevante konfigurasie, en inspekteer slegs die script-check- en ACL-veldname en -instellings. Konfigurasielêers kan ook gossip-sleutels of tokens bevat; vermy dit om in gedeelde logs te plak. Moenie ’n diens registreer of ’n gesondheidkontrole uitvoer bloot om hierdie toestand te lys nie.

’n Afsonderlike plaaslike-lêerpad bestaan wanneer ’n gebruiker met minder voorregte **skryf- en soektoegang** het tot die gids wat deur ’n root-uitgevoerde agent se `-config-dir` benoem word: ’n nuwe `.hcl`- of `.json`-diensdefinisie kan uit daardie gids gelaai word. Soek- en skryftoegang tot ’n gids kan toelaat dat ’n lêer bygevoeg word, selfs wanneer die gids se inhoud nie gelys mag word nie. Bevestig vir root-opdraguitvoering dat die agent wel daardie gids laai, dat die **effektiewe** script-check-instelling plaaslike definisies toelaat, dat die definisie gelaai word en dat die agent root-regte behou. [Consul se dokumentasie](https://developer.hashicorp.com/consul/docs/fundamentals/agent#reloadable-configurations) beskryf watter instellings en gesondheidkontroledefinisies herlaai kan word; om script checks te aktiveer, kan self ’n herbegin vereis, so verifieer die gedrag van die geïnstalleerde weergawe. Wanneer ACLs die agent beskerm, vereis [`consul reload` `agent:write`](https://developer.hashicorp.com/consul/api-docs/agent#reload-agent); KV-skryftoestemming alleen verleen dit nie. Beskou skryfbare gidsmetadata as ’n aanduiding vir hersiening, nie as bewys van ’n gemagtigde herlaai, herbegin of opdraguitvoering nie. Inspekteer paaie, toestemmings en beleid sonder om konfigurasie te skryf of die API aan te roep.

## Volg die diensuitvoeringsketting

```bash
systemctl cat <unit>.service
systemctl show <unit>.service -p User -p Group -p ExecStart -p EnvironmentFiles -p WorkingDirectory
namei -l /path/from/ExecStart
```

Kontroleer die unit, drop-ins, `EnvironmentFile=`, helper scripts, relatiewe opdragte, skryfbare gidse en socket activation. ’n Root-besitte unit kan steeds onveilig wees as dit ’n gebruiker-skryfbare konfigurasie of script lees. Die [arbitrary file write](../interesting-files-permissions/write-to-root.md)-bladsy dek algemene diens- en unit-misbruikpaaie. Monitor kortstondige take met [pspy](https://github.com/DominicBreuker/pspy) of audit-/prosestelemetrie wanneer ’n eenmalige `ps`-lys hulle mis.

Vir ’n pasgemaakte **xinetd**-diens, korreleer die geaktiveerde stanza se `server`, `user` en toegangsbeheer met die aktiewe listener en presiese uitvoerbare lêer. Die [`user`-instelling](https://manpages.debian.org/testing/xinetd/xinetd.conf.5.en.html) kies die identiteit van die voortgebringde proses, terwyl ’n set-user-ID-bit op die uitvoerbare lêer sy effektiewe identiteit afsonderlik kan verander as [`execve` daardie oorgang toelaat](https://man7.org/linux/man-pages/man2/execve.2.html). ’n Bereikbare bevoorregte binêre lêer wat onvertroude invoer aanvaar, verdien ’n vanlyn bronkode- of disassembleringsoorsig vir geheueveiligheidsfoute, soos ’n onbeperkte [`scanf`-stringomskakeling](https://www.gnu.org/software/libc/manual/html_node/String-Input-Conversions.html) na ’n vaste buffer. Die dienskartering en set-user-ID-metadata is leidrade, nie bewys van so ’n fout nie; moenie crash-invoer stuur of die aktiewe bevoorregte diens ontfout tydens passiewe enumerasie nie.

Vir ’n pasgemaakte bevoorregte listener met leesbare bronkode, hersien elke lengte wat deur die aanroeper beheer word en in ’n kopieerbewerking soos [`memcpy`](https://man7.org/linux/man-pages/man3/memcpy.3.html) gebruik word. Om net te kontroleer dat die huidige skryfindeks binne ’n vaste buffer val, bewys nie dat die **kopielengte** in die oorblywende ruimte pas nie; verifieer `copy_length <= capacity - index` nadat jy bevestig het dat die indeks binne bereik is, en kontroleer getekendheid en rekenkundige oorloop. Dit is slegs ’n hersieningsleidraad as die invoer daardie bewerking bereik, die listener vir die laerbevoorregte gebruiker toeganklik is en die proses ’n hoër effektiewe identiteit behou. Inspekteer bronkode en prosesmetadata vanlyn; moenie crash-invoer na die aktiewe diens stuur tydens enumerasie nie.

Op stelsels wat **Upstart** gebruik, kan stelseltaakdefinisies onder `/etc/init/*.conf` wees. ’n Taaklêer wat deur die huidige gebruiker geskryf kan word, is relevant wanneer die aktiewe init-daemon daardie presiese taak laai, die `script`- of `exec`-stanza as ’n hoërbevoorregte identiteit loop en die gebruiker dit deur ’n toegelate `initctl`-opdrag of ’n ander werklike sneller kan begin. ’n sudo `initctl`-toekenning bewys op sigself nie dat enige taaklêer skryfbaar is of dat ’n gewysigde taak sal loop nie. Kontroleer die presiese taaklêertoestemmings, effektiewe run-as-instelling, aktiewe daemon en sneller sonder om die taak tydens enumerasie te wysig of te begin. Sien die [Upstart-taakkonfigurasie](https://manpages.ubuntu.com/manpages/trusty/man5/init.5.html)- en [`initctl`](https://manpages.ubuntu.com/manpages/xenial/man8/initctl.8.html)-handleidings.

’n Leesbare autologin-wagwoordlêer, soos `/etc/autologin/passwd` op stelsels waarvan die [boot-taak daardie presiese pad lees](https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/master/chromeos-base/autologin/files/init/autologin.conf), is ’n leidraad oor blootgestelde geloofsbriewe. Bevestig dat die boot-taak geïnstalleer is en die lêer gebruik, en verifieer dan afsonderlik of die wagwoord vir ’n ander plaaslike rekening of diens geldig is. Die lêernaam alleen bewys nie dat die wagwoord hergebruik word nie; teken pad- en toegangmetadata aan sonder om die wagwoord in gedeelde enumerasie-uitvoer te plaas.

’n Unit se `ExecStart=` of ’n geskeduleerde opdrag kan die presiese padnaam onthul van ’n script in ’n gids waarvan die inhoud nie gelys kan word nie. [Gidursoektoestemming](https://man7.org/linux/man-pages/man7/path_resolution.7.html) kan die huidige identiteit steeds toelaat om deur daardie bekende pad te gaan; bevestig soektoegang op elke ouergids en leestoestemming op die lêer eerder as om te aanvaar dat ’n mislukte gidslys dit beskerm. ’n Leesbare script kan ’n oordragbewysstuk bevat, maar om na ’n ander rekening oor te gaan vereis dat daardie bewysstuk geldig bly en onafhanklik daar aanvaar word. Teken die pad- en toestemmingsbewyse aan sonder om geheime waardes in gedeelde logs af te druk.

Vir ’n geskeduleerde CommonJS Node.js-script, hersien kaal imports soos `require('package')`, selfs wanneer die script self leesalleen is. [Node soek na `node_modules` langs die lêer wat die import doen en daarna in sy ouergidse](https://nodejs.org/api/modules.html#loading-from-node_modules-folders), voordat dit na gekonfigureerde globale paaie terugval. ’n Laerbevoorregte gebruiker wat een van daardie ouergidse kan **skryf en deursoek**, kan moontlik ’n pakket skep wat vroeër ooreenstem. Bevestig dat die presiese import bereik word, die gekose pakket nie ’n ingeboude module is nie, die relevante pad geskep of verander kan word, die module daar in die geïnstalleerde runtime opgelos word en ’n hoërbevoorregte taak dit tydens ’n toekomstige uitvoering sal laai. Skryfbare ouermetadata is slegs ’n leidraad vir hersiening; inspekteer die script en scheduler passief sonder om ’n module te plant of die taak te aktiveer.

’n Private Python-pakketindeks is nog ’n vertrouensgrens wanneer ’n outomatiese taak pakkette onder ’n ander OS-identiteit installeer. Korreleer die presiese taak en run-as-rekening met sy gekonfigureerde indeks, gekose pakketname en of ’n laerbevoorregte gebruiker ’n pakket kan publiseer of vervang wat die taak werklik sal installeer. Die bou van ’n brondistribusie kan sy build backend of verouderde `setup.py` onder die installeerder se identiteit laat loop; die invoer van die geïnstalleerde pakket is ’n afsonderlike uitvoeringspad. ’n Indekslistener, leesbare oplaai-wagwoordhash of pakketlêernaam alleen bewys nie daardie ketting nie. Hersien die taak, indeksmagtiging en pakketherkoms sonder om enigiets tydens enumerasie op te laai of te installeer. Sien [pip se build-system-koppelvlak](https://pip.pypa.io/en/stable/reference/build-system/) en [riglyne vir veilige installasie](https://pip.pypa.io/en/stable/topics/secure-installs/).

’n Bevoorregte agent kan ’n taakry wat deur ’n afsonderlike webdiens of container bestuur word, pols. As ’n identiteit met laer vertroue die diens se taakdatabasis kan skryf, bepaal of daardie rye werklik aan die agent bedien word en of ’n command-taak met die agent se OS-identiteit loop. Bevestig databasis-skryftoegang, die teikensessie of roeteringsleutel, aktiewe polling, taakmagtiging en die agent se effektiewe gebruiker afsonderlik. Root binne ’n container impliseer nie op sigself toegang as host-root nie; die grens word slegs oorgesteek as ’n verbruiker met host-bevoorregte toegang aanvallerbeheerde taakdata uitvoer. Inspekteer proses-, databasislêer- en diensmetadata sonder om die ry te wysig of tydens enumerasie ’n taak te stuur.

’n Herhalende taak kan eerder ’n opdrag uit ’n toepassingsdatabasis se konfigurasiery lees. Bevestig dat die laerbevoorregte databasisrol daardie presiese ry kan verander, dat die aktiewe taak dit ná die verandering lees en dat die waarde ’n shell of ’n soortgelyke opdraguitvoerder onder ’n hoër OS-identiteit bereik. Databasis-skryftoegang of ’n waarde wat soos ’n opdrag lyk, bewys nie op sigself dat dit uitgevoer word nie; inspekteer die taak en toestemmings sonder om die ry tydens passiewe enumerasie te verander.

’n Boodskap in ’n ry kan ook ’n URL eerder as kode bevat. As ’n bevoorregte verbruiker daardie URL ophaal en die antwoord as ’n Lua- of ander uitvoerbare plugin laai, verifieer die uitgewer se toestemming op die presiese exchange en routing key, die binding aan die verbruikte queue, die ophaal- en plugin-laaipad en die werker se effektiewe identiteit. [RabbitMQ roeteer gepubliseerde boodskappe deur exchanges](https://www.rabbitmq.com/docs/exchanges); ’n broker-listener of geldige aanmelding bewys nie op sigself aflewering aan hierdie werker nie. Vasgelegde duidelikteks-brokerbewysstukke is ’n afsonderlike leidraad wat werklike toegang tot packet capture en leesbare verkeer vereis; dit bewys nie publiseerregte nie. ’n Lua-plugin kan shell-opdragte deur [`os.execute`](https://www.lua.org/manual/5.4/manual.html#pdf-os.execute) uitvoer slegs as daardie API in sy runtime beskikbaar is. Hersien konfigurasie en kode sonder om verkeer vas te lê, boodskappe te publiseer of tydens passiewe enumerasie ’n plugin op te haal.

Wanneer ’n bevoorregte Python-diens ’n plaaslike HTTP- of socket-endpoint blootstel, kan ’n leesbare script ’n invoer-na-kode-pad onthul, selfs al verhinder die lêertoestemmings dat dit gewysig word. Korreleer die aktiewe proses en unit-identiteit met die presiese script, listener, roete-magtiging en velde wat deur die aanroeper beheer word. Volg dan daardie velde deur ontleding en validering tot by ’n dinamiese `eval()`- of `exec()`-sink. Veral kan die bou van ’n nuwe f-string uit versoekteks en die evaluering daarvan aanvaller-verskafde vervangingsvelde as Python-uitdrukkings interpreteer ([Python `eval`-waarskuwing](https://docs.python.org/3/library/functions.html#eval); [f-string-semantiek](https://docs.python.org/3/reference/lexical_analysis.html#f-strings)). ’n Losstaande `eval`-treffer of loopback-binding bewys nie dat ’n onvertroude aanroeper die sink bereik nie; hersien die werklike datavloei en toegangsbeheer sonder om tydens enumerasie ’n toets-payload te stuur.

’n Poort vir getekende versoeke op daardie roete verg ’n eie hersiening. As leesbare bronkode die ondertekeningsleutel uit ’n aantoonbaar klein of voorspelbare uitvoerruimte aflei, en die diens ’n geldige getekende voorbeeld blootstel, beskerm die handtekening moontlik nie meer ’n bevoorregte `eval()`-sink nie. Verifieer die presiese sleutelafleiding en verifikasie, die aktiewe diensidentiteit en plaaslike aanroepertoegang, en of die getekende veld die sink bereik; ’n import van Python se [`random`-module](https://docs.python.org/3/library/random.html) of ’n voorbeelhandtekening bewys nie een van daardie voorwaardes nie. Python waarsku ook dat die beperking van `__builtins__` [nie ’n sekuriteitsgrens vir onvertroude `eval()`-invoer is nie](https://docs.python.org/3/library/functions.html#eval). Hou sleutelontleding vanlyn en moenie tydens passiewe enumerasie vervalste versoeke indien nie.

’n Leë maar skryfbare `/etc/systemd/system/<unit>.service.d`-gids is relevant, selfs wanneer die unit-lêer en elke bestaande drop-in beskerm is: die gebruiker kan ’n nuwe `.conf`-oorheersing skep. Kontroleer dat die huidige identiteit die gids kan skryf en deursoek, dat die unit gelaai is en as root loop, en of ’n daemon-herlaai gevolg deur ’n herbegin sal plaasvind. ’n Herlaai- of herbegintoestemming, timer of latere selflaai kan die verandering effektief maak; skryftoegang tot die gids alleen voer dit nie onmiddellik uit nie.

Vir dienste wat loop, volg letterlike `EnvironmentFile=`-paaie vanaf die unit se `[Service]`-afdeling, insluitend lêers waarvan die name nie met `.env` begin nie. As ’n gebruiker met lae voorregte een kan lees, lys sleutelname wat waarskynlik op geloofsbriewe dui, soos `API_TOKEN` of `APP_SECRET_KEY`, sonder om die waardes in gedeelde logs af te druk. Kontroleer drop-in-oorheersings en opsionele `-`-voorvoegsels wanneer jy die effektiewe unit beoordeel. Leesbaarheid is ’n leidraad oor blootgestelde geloofsbriewe; die waarde moet steeds geldig wees vir ’n bevoorregte handeling om eskalasie teweeg te bring.

### Bevoorregte verwerking van onvertroude oplaaie

’n Lêerkyker wat as root loop, kan lêers uit ’n gebruiker-skryfbare oplaai-gids aan ’n kortstondige ontleder of uitpakker oorhandig. Volg die aktiewe kyker se ouerscript of diens en bevestig die presiese gids, wie lêers daar kan plaas, die child-opdrag en sy argumente, en die identiteit waaronder die child loop. ’n Prosessnapshot kan die kyker wys terwyl dit die uitpakker tussen oplaaie mis. Moenie tydens passiewe enumerasie ’n toets-payload plaas of die kyker aktiveer nie.

Een konkrete voorbeeld is Binwalk se ekstraksiemodus (`-e`) wat aanvallerbeheerde PFS-data verwerk. [CVE-2022-4510](https://github.com/ReFirmLabs/binwalk/pull/617) het die PFS-uitpakker toegelaat om buite sy beoogde gids te skryf, insluitend na ’n plugin-pad wat Binwalk later kon laai. Die stroomop-projek het die regstelling in [2.3.4](https://github.com/ReFirmLabs/binwalk/releases/tag/v2.3.4) ingesluit, maar distro-backports kan ’n ouer weergawe behou wat vertoon word; kontroleer die geïnstalleerde pakket se sekuriteitstatus, soos die [Debian-spoorsnyer](https://security-tracker.debian.org/tracker/CVE-2022-4510), voordat jy die toepaslikheid beoordeel. ’n Geïnstalleerde Binwalk-weergawe alleen bewys nie ’n voorreg-eskalasiepad nie: ekstraksie moet werklik deur ’n meer bevoorregte proses op invoer uitgevoer word wat die laerbevoorregte gebruiker kan beheer.

### Geskeduleerde builds met plaaslike afhanklikhede

’n Geskeduleerde `cargo run` herkompileer bronkode as die taak se run-as-gebruiker. Inspekteer die manifest se plaaslike `{ path = "..." }`-afhanklikhede en die bronkode- en ouergidstoestemmings van elke afhanklikheid, nie net dié van die hoofcrate nie. As ’n laerbevoorregte gebruiker ’n afhanklikheid kan wysig wat Cargo saamstel en die geskeduleerde taak die resultaat uitvoer, kan die saamgestelde kode as daardie run-as-gebruiker loop. Bevestig die effektiewe scheduler-opdrag, werkgids, afhanklikheidsresolusie en of ’n herbou sal plaasvind; ’n skryfbare Rust-bronlêer elders is slegs ’n leidraad. Om die manifest en padmetadata te lees, is genoeg vir passiewe triage. Sien die [Cargo-dokumentasie oor pad-afhanklikhede](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#specifying-path-dependencies).

## Xvfb-raambufferlêers

`Xvfb -fbdir <directory>` gebruik geheuegekoppelde lêers met die name `Xvfb_screen<n>` vir sy virtuele skerms. As ’n ander gebruiker se aktiewe Xvfb-proses ’n gids benoem waarvan die skermlêers vir die huidige gebruiker leesbaar is, kan die raambuffer daardie gebruiker se werkskerminhoud blootstel. Bevestig die proses, lêereienaarskap en toestemmings saam; ’n leesbare lêer alleen bewys nie dat nuttige inhoud op die skerm is nie. Inspekteer eers paaie en metadata, sonder om beelddata na gedeelde enumerasie-uitvoer te kopieer. Die [Xvfb-handleiding](https://xorg.freedesktop.org/archive/X11R7.5/doc/man/man1/Xvfb.1.html) dokumenteer die gedrag van `-fbdir`.

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
6. [Consul ACL-konfigurasie](https://developer.hashicorp.com/consul/docs/reference/agent/configuration-file/acl)
7. [LibreOffice-hulp: maak 'n socket oop vir eksterne API-kliënte](https://help.libreoffice.org/latest/en-US/text/sbasic/shared/03/sf_intro.html)
8. [LibreOffice SDK: `XSystemShellExecute`](https://api.libreoffice.org/docs/idl/ref/interfacecom_1_1sun_1_1star_1_1system_1_1XSystemShellExecute.html)

{{#include ../../banners/hacktricks-training.md}}
