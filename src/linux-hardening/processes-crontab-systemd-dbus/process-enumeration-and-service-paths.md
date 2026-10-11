# Prosesenumerering en dienspaaie

{{#include ../../banners/hacktricks-training.md}}

Die nuttige vraag is watter bevoorregte proses data of kode verbruik wat ’n gebruiker met minder voorregte kan beïnvloed. Inspekteer die prosesboom, die lewendige omgewing, oop lêers en die unit of skrip wat elke kandidaat geloods het.

## Karteer prosesse en eienaarskap

```bash
ps -eo user,pid,ppid,tty,comm,args --sort=ppid
pstree -alp 2>/dev/null
systemctl list-units --type=service --state=running 2>/dev/null
ss -lntup
```

’n Ouer-kind-verhouding tussen verskillende gebruikers kan normaal wees, maar ’n onverwagte oorgang regverdig ’n ondersoek van die oueropdrag, argumente, uitvoerbare lêer, werkgids en verwysde lêers. Gebruik [users and sessions](../user-information/user-and-session-triage.md) om die eienaar en aanmeldkonteks te interpreteer.

### Plaaslike virtuelemasjienkonsoles

Gaan ’n QEMU-proses se `-spice`-opsies saam met sy luisteradres na. [QEMU dokumenteer](https://www.qemu.org/docs/master/system/qemu-manpage.html) dat `disable-ticketing` SPICE-kliënte sonder verifikasie laat koppel. ’n Luisteraar wat aan loopback gebind is, kan steeds moontlik deur ander plaaslike gasheergebruikers bereik word. Bevestig die aktiewe luisteraar, verifikasie-opsies en plaaslike toegang voordat jy die opdragreël as ’n blootgestelde konsole beskou. Konsolebeheer raak die **guest**; om ’n guest-rekening te verkry of sy selflaaitoestand te verander, vereis afsonderlike guest-kant-voorwaardes en verleen nie root op die virtualiseringsgasheer nie. Lees prosesargumente en sokmetadata sonder om tydens passiewe enumerasie aan die guest te koppel of dit te herlaai.

’n Plaaslik bereikbare webkoppelvlak kan kode met sy diensrekening uitvoer, selfs wanneer die eerste shell nie toegang tot daardie rekening se lêers het nie. CVE-2023-0297 het byvoorbeeld pyLoad se `/flash/addcrypted2`-hantering geraak wanneer onbetroubare JavaScript Js2Py bereik het met Python-invoere geaktiveer; die [upstream-regstelling](https://github.com/pyload/pyload/commit/7d73ba7919e594d783b3411d7ddb87885aea782d) het `pyimport` gedeaktiveer. Vergelyk die lopende proses se eienaar, luisteradres, blootstelling van die eindpunt en geïnstalleerde regstelling of verskaffer-terugportering voordat jy ’n pyLoad-proses as ’n eskalasieroete beskou. ’n Prosesnaam, oop poort of pakketweergawe alleen bewys nie blootstelling nie; passiewe enumerasie behoort nie ’n uitvoeringspayload te stuur nie.

### Bevoorregte aanmeldshells wat ’n terminaal deel

’n Bevoorregte interaktiewe shell wat `su --login <user>` uitvoer sonder ’n onafhanklike pseudo-terminaal, kan veroorsaak dat sy terminaal met die laerbevoorregte aanmeldshell gedeel word. As daardie gebruiker se opstartlêer beheerbaar is en kode daarin `TIOCSTI` kan gebruik om terminaalinvoer in te spuit, kan die invoer die bevoorregte shell bereik wanneer dit hervat. [Die util-linux `su`-handleiding](https://man7.org/linux/man-pages/man1/su.1.html#SECURITY_NOTES) beskryf die risiko van ’n gedeelde terminaal en beveel `su --pty`/`-P` vir interaktiewe gebruik aan; `su -c` begin ’n afsonderlike sessie sonder ’n beherende terminaal. Die risiko hang af van die werklike ouershell, terminaalverhouding, teiken se opstartlêer en kernbeleid. ’n Prosesnaam of `su -l`-argument alleen is slegs ’n rede vir ondersoek.

Gaan die waargenome proseshierargie en TTY-kolomme na, en daarna die leesbare lanseerder en eienaarskap/toestemmings van die opstartlêer. Op Linux kan `/proc/sys/dev/tty/legacy_tiocsti`, indien teenwoordig, help om die beleid te interpreteer; die afwesigheid daarvan bewys nie veiligheid nie. [Die Linux `TIOCSTI`-handleiding](https://man7.org/linux/man-pages/man2/TIOCSTI.2const.html) meld dat die bewerking sedert Linux 6.2 moontlik `CAP_SYS_ADMIN` vereis wanneer hierdie sysctl false is. Moenie die ioctl uitvoer bloot om die gasheer te enumereer nie.

’n Databasisrekening kan soms die teikengebruiker se opstartlêer verander sonder direkte skryftoegang tot die lêerstelsel. PostgreSQL-bedienerkant-`COPY ... TO 'filename'` skryf as die databasisbediener se OS-rekening, maar [PostgreSQL se beperkings](https://www.postgresql.org/docs/current/sql-copy.html) laat hierdie lêervorm slegs aan databasis-supergebruikers of rolle soos `pg_write_server_files` toe. Bevestig beide die databasisrol en die bediener se OS-lêertoestemmings; ’n toepassing se verbindingsstring alleen verleen nie skryftoegang tot lêers nie. Hou die bevoorregte lanseerder en die databasisrekening se vermoëns apart wanneer jy die ketting beoordeel.

## Inspekteer runtime-artefakte

```bash
readlink /proc/<PID>/exe
tr '\0' ' ' </proc/<PID>/cmdline; echo
ls -l /proc/<PID>/fd 2>/dev/null
lsof -p <PID> 2>/dev/null
lsof +L1 2>/dev/null
```

Geskrapte uitvoerbare lêers en geskrapte-maar-oop lêers bly verwys totdat hul laaste descriptor toegemaak word. Hulle kan bewyse of toeganklike geheime bewaar. Prosesomgewings en geheue kan geloofsbriewe bevat, maar toegang tot 'n ander proses word beperk deur eienaarskap, `/proc`-monteeropsies, Yama ptrace-beleid en ander sekuriteitskontroles. Sien [file descriptors](../main-system-information/filesystem-links-and-file-descriptors.md) en [post-exploitation credential hunting](../post-exploitation/README.md) vir verwante tegnieke.

Gestoorde syscall-spore is nog 'n lêertoegang-grens. [`strace` records syscall arguments to an output file](https://man7.org/linux/man-pages/man1/strace.1.html), dus kan 'n leesbare spoor van [`execve` arguments](https://man7.org/linux/man-pages/man2/execve.2.html) 'n wagwoord blootlê wat 'n bevoorregte taak op sy opdragreël deurgegee het. Stel eers vas dat die huidige gebruiker die spesifieke spoor kan lees en dat die argument werklik 'n geloofsbrief bevat; 'n latere Unix-rekening-oorgang vereis afsonderlike bewys dat die geloofsbrief daar aanvaar word. Lêermetadata is 'n nuttige passiewe leidraad sonder om elke spoor te skandeer of die inhoud daarvan tydens roetine-enumerasie te druk.

## Bevoorregte kantoortoepassingsokette

LibreOffice en OpenOffice kan hul UNO API blootstel via 'n `--accept=socket,host=<host>,port=<port>;urp;`-argument. 'n Kanto proses in root-eienaarskap met 'n bereikbare eindpunt kan 'n plaaslike gebruiker met minder voorregte moontlik maak om API-dienste in daardie proses se sekuriteitskonteks aan te roep. Die `SystemShellExecute`-diens sluit 'n bewerking in om 'n stelselopdrag te begin. Binding aan loopback beperk bereikbaarheid op afstand, maar laat die soket steeds vir plaaslike gebruikers bereikbaar, tensy 'n ander beheer toegang verhoed.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
ps -eo user,args | grep -E '[s]office|[l]ibreoffice|[o]penoffice'
ss -ltn 2>/dev/null
```

Korreleer die proseseienaar, die presiese `--accept`-argument en die huidige luisteradres en -poort. ’n Gekonfigureerde acceptor wat nie kon bind nie, is slegs ’n leidraad; moenie tydens passiewe enumerasie aan die API koppel of dit aanroep nie. Moenie ’n bevoorregte office-instansie begin bloot om hierdie toestand te toets nie.

## System V shared memory wat deur bevoorregte prosesse gebruik word

’n Hulpprogram wat deur root besit word, kan ’n System V shared-memory-segment skep waarna ’n ander gebruiker kan skryf. As die hulpprogram later data uit daardie segment in ’n shell-opdrag of ’n ander sensitiewe bewerking vertrou, kruis die segment ’n privilegiegrens, selfs wanneer die uitvoerbare lêer en sy lêers beskerm is. `shmget()` neem toegangsregte uit die laagste nege bisse van sy vlae; modus `0666` laat ander gebruikers toe om te skryf, terwyl ’n `IPC_CREAT`-vlag nie daardie regte beperk nie. Inspekteer aktiewe segmente passief met `ipcs -m` en korreleer hul eienaar, modus en leeftyd met die bevoorregte proses en sy invoerhantering. ’n Wêreldskryfbare segment alleen bewys nie dat opdraguitvoering moontlik is nie.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
ipcs -m
```

System V-segmente verskil van POSIX-gedeeldegeheuelêers onder `/dev/shm`. ’n Segment wat net vir ’n oomblik geskep word, is dalk afwesig in ’n enkele `ipcs`-momentopname; leë uitvoer sluit dus nie uit dat ’n helper gedeelde geheue gebruik nie. Gaan die helper se bronkode of binêre gedrag na, asook enige `sudo`-reël wat dit begin; moenie die bevoorregte helper aanroep net om ’n segment tydens enumerasie te laat verskyn nie. Die [IPC-naamruimtegids](../containers-namespaces/container-security/protections/namespaces/ipc-namespace.md) verduidelik hoe naamruimtes sigbaarheid beïnvloed.<sup>[[2]](#references)[[3]](#references)</sup>

## Consul-agent-scriptkontroles

Consul kan script-gesondheidskontroles uitvoer met die bedryfstelsel-identiteit van sy agent. As ’n agent as root loop, `enable_script_checks` aktiveer en ’n gebruiker met laer voorregte toelaat om ’n diens met ’n scriptkontrole via die plaaslike HTTP API te registreer, kan dié gebruiker veroorsaak dat opdragte as root uitgevoer word. Deur die API slegs aan `127.0.0.1` te bind, kan plaaslike gebruikers dit steeds bereik. Die `enable_local_script_checks`-instelling is meer beperk: dit sluit scriptkontroles uit wat via HTTP API-registrasies ingedien word. Wanneer Consul ACLs geaktiveer is, vereis diensregistrasie `service:write`; ’n `acl.default_policy=allow`-reël op sy eie bewys nie dat ’n anonieme oproeper kan registreer nie. Gaan die agent se werklike identiteit, gelaaide instellings, API-binding en magtiging saam na.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

```bash
ps -eo user,args | grep '[c]onsul agent'
ls -l /etc/consul.d 2>/dev/null
```

Volg die lopende agent se `-config-dir`- en `-config-file`-argumente na die relevante konfigurasie, en ondersoek slegs die veldname en instellings vir script checks en ACL's. Konfigurasielêers kan ook gossip-sleutels of tokens bevat; moenie dit in gedeelde logs plak nie. Moenie ’n diens registreer of ’n gesondheidskontrole uitvoer net om hierdie toestand te lys nie.

’n Aparte plaaslike-lêerpad bestaan wanneer ’n gebruiker met minder voorregte die gids wat deur ’n agent wat as root loop se `-config-dir` benoem word, kan **skryf en deursoek**: ’n nuwe `.hcl`- of `.json`-diensdefinisie kan uit daardie gids gelaai word. Deursoek- en skryftoestemming vir die gids kan dit moontlik maak om ’n lêer by te voeg, selfs wanneer lysing van die gids geweier word. Vir uitvoering van opdragte as root, bevestig dat die agent daardie gids werklik laai, dat die **effektiewe** script-check-instelling plaaslike definisies toelaat, dat die definisie gelaai word, en dat die agent root-voorregte behou. [Consul dokumenteer](https://developer.hashicorp.com/consul/docs/fundamentals/agent#reloadable-configurations) watter instellings en gesondheidskontroledefinisies herlaai kan word; om script checks te aktiveer, kan self ’n herbegin vereis, dus verifieer hoe die geïnstalleerde weergawe optree. Wanneer ACL's die agent beskerm, vereis [`consul reload` `agent:write`](https://developer.hashicorp.com/consul/api-docs/agent#reload-agent); KV-skryftoestemming alleen verleen dit nie. Beskou skryfbare gidsmetadata as ’n aanduiding vir hersiening, nie as bewys van ’n gemagtigde herlaai, herbegin of opdraguitvoering nie. Ondersoek paaie, toestemmings en beleide sonder om konfigurasie te skryf of die API aan te roep.

## Volg die diensuitvoeringsketting

```bash
systemctl cat <unit>.service
systemctl show <unit>.service -p User -p Group -p ExecStart -p EnvironmentFiles -p WorkingDirectory
namei -l /path/from/ExecStart
```

Gaan die unit, drop-ins, `EnvironmentFile=`, helper scripts, relatiewe opdragte, skryfbare gidse en socket activation na. ’n Unit wat deur root besit word, kan steeds onveilig wees as dit ’n konfigurasie- of scriptlêer lees waarop ’n gebruiker kan skryf. Die [arbitrary file write](../interesting-files-permissions/write-to-root.md)-bladsy dek algemene misbruikpaaie vir services en units. Monitor kortlewende take met [pspy](https://github.com/DominicBreuker/pspy) of oudit-/proses-telemetrie wanneer ’n eenmalige `ps`-lys hulle mis.

Vir ’n pasgemaakte **xinetd**-service, korreleer die geaktiveerde stanza se `server`, `user` en toegangskontroles met die aktiewe listener en presiese uitvoerbare lêer. Die [`user`-instelling](https://manpages.debian.org/testing/xinetd/xinetd.conf.5.en.html) kies die identiteit waaronder die geskepte proses loop, terwyl ’n set-user-ID-bit op die uitvoerbare lêer sy effektiewe identiteit afsonderlik kan verander as [`execve` daardie oorgang toelaat](https://man7.org/linux/man-pages/man2/execve.2.html). ’n Bereikbare bevoorregte binary wat onbetroubare invoer aanvaar, verdien ’n vanlyn bronkode- of disassembly-oorsig vir geheueveiligheidsfoute, soos ’n onbeperkte [`scanf`-stringomskakeling](https://www.gnu.org/software/libc/manual/html_node/String-Input-Conversions.html) na ’n vaste buffer. Die dienskartering en set-user-ID-metadata is leidrade, nie bewys van so ’n fout nie; moenie crash-invoer stuur of die aktiewe bevoorregte service ontfout tydens passiewe enumerasie nie.

Vir ’n pasgemaakte bevoorregte listener met leesbare bronkode, hersien elke lengte wat deur die oproeper beheer word en in ’n kopieerbewerking gebruik word, soos [`memcpy`](https://man7.org/linux/man-pages/man3/memcpy.3.html). Om net na te gaan dat die huidige skryf-indeks binne ’n vaste buffer val, bewys nie dat die **kopielengte** in die oorblywende spasie pas nie; verifieer `copy_length <= capacity - index` nadat jy bevestig het dat die indeks binne die omvang is, en kontroleer getaltekens en rekenkundige oorloop. Dit is slegs ’n leidraad vir hersiening as die invoer daardie bewerking bereik, die listener vir die minderbevoorregte gebruiker toeganklik is en die proses ’n hoër effektiewe identiteit behou. Inspekteer bronkode en prosesmetadata vanlyn; moenie crash-invoer tydens enumerasie na die aktiewe service stuur nie.

Op stelsels wat **Upstart** gebruik, kan stelsel-job-definisies onder `/etc/init/*.conf` wees. ’n Job-lêer waarop die huidige gebruiker kan skryf, is relevant wanneer die aktiewe init-daemon daardie presiese job laai, die `script`- of `exec`-stanza daarvan as ’n hoërbevoorregte identiteit loop, en die gebruiker dit deur ’n toegelate `initctl`-opdrag of ’n ander werklike sneller kan begin. ’n sudo `initctl`-toestemming alleen bewys nie dat enige job-lêer skryfbaar is of dat ’n gewysigde job sal loop nie. Gaan die toestemmings van die presiese job-lêer, effektiewe run-as-instelling, aktiewe daemon en sneller na sonder om die job tydens enumerasie te wysig of te begin. Sien die handleidings vir [Upstart-jobkonfigurasie](https://manpages.ubuntu.com/manpages/trusty/man5/init.5.html) en [`initctl`](https://manpages.ubuntu.com/manpages/xenial/man8/initctl.8.html).

’n Leesbare autologin-wagwoordlêer, soos `/etc/autologin/passwd` op stelsels waar die [boot-job daardie presiese pad lees](https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/master/chromeos-base/autologin/files/init/autologin.conf), is ’n leidraad van blootgestelde credentials. Bevestig dat die boot-job geïnstalleer is en die lêer gebruik, en verifieer dan afsonderlik of die wagwoord vir ’n ander plaaslike account of service geldig is. Die lêernaam alleen bewys nie dat die wagwoord hergebruik word nie; teken pad- en toegangmetadata aan sonder om die wagwoord in gedeelde enumerasie-uitvoer te plaas.

’n Unit se `ExecStart=` of ’n geskeduleerde opdrag kan die presiese padnaam van ’n script binne ’n lys-onbeskikbare gids aandui. [Gidsoektoestemming](https://man7.org/linux/man-pages/man7/path_resolution.7.html) kan die huidige identiteit steeds toelaat om die bekende pad te deurkruis; bevestig soektoegang op elke ouergids en leestoestemming op die lêer, eerder as om aan te neem dat ’n mislukte gidslys dit beskerm. ’n Leesbare script kan ’n oordragcredential bevat, maar toegang tot ’n ander account vereis dat die credential steeds geldig is en onafhanklik daar aanvaar word. Teken die pad en toestemmingbewyse aan sonder om geheime waardes in gedeelde logs te druk.

Vir ’n geskeduleerde CommonJS Node.js-script, hersien kaal imports soos `require('package')`, selfs wanneer die script self leesalleen is. [Node soek `node_modules` langs die lêer wat importeer en daarna in sy ouergidse](https://nodejs.org/api/modules.html#loading-from-node_modules-folders), voordat dit na gekonfigureerde globale paaie terugval. ’n Minderbevoorregte gebruiker wat een van daardie ouergidse kan **skryf en deursoek**, kan moontlik ’n package skep wat vroeër pas. Bevestig dat die presiese import bereik word, dat die geselekteerde package nie ’n ingeboude module is nie, dat die betrokke pad geskep of gewysig kan word, dat die module daar in die geïnstalleerde runtime resolveer, en dat ’n hoërbevoorregte job dit tydens ’n toekomstige aanroep sal laai. Skryfbare ouergidsmetadata is slegs ’n aanduiding vir hersiening; inspekteer die script en scheduler passief sonder om ’n module te plaas of die job te aktiveer.

’n Private Python-package-index is nog ’n vertrouensgrens wanneer ’n outomatiese job packages onder ’n ander OS-identiteit installeer. Korreleer die presiese job en run-as-account met sy gekonfigureerde index, geselekteerde packagename, en of ’n minderbevoorregte gebruiker ’n package kan publiseer of vervang wat die job werklik sal installeer. Die bou van ’n source distribution kan sy build-backend of verouderde `setup.py` onder die installeerder se identiteit laat loop; die import van die geïnstalleerde package is ’n afsonderlike uitvoeringspad. ’n Index-listener, leesbare oplaai-wagwoordhash of packagenaam op sigself bewys nie daardie ketting nie. Hersien die job, index-magtiging en package-oorsprong sonder om tydens enumerasie enigiets op te laai of te installeer. Sien [pip se build-system-koppelvlak](https://pip.pypa.io/en/stable/reference/build-system/) en [riglyne vir veilige installasie](https://pip.pypa.io/en/stable/topics/secure-installs/).

’n Bevoorregte agent kan ’n taakry monitor wat deur ’n afsonderlike webservice of container bestuur word. As ’n identiteit met laer vertroue na die diens se taakdatabasis kan skryf, bepaal of daardie rye werklik aan die agent bedien word en of ’n command-taak met die agent se OS-identiteit loop. Bevestig databasis-skryftoegang, die teikensessie of routing key, aktiewe polling, taagmagtiging en die agent se effektiewe gebruiker afsonderlik. Root binne ’n container impliseer nie vanself toegang as host-root nie; die grens word slegs oorgesteek as ’n host-bevoorregte verbruiker aanvallerbeheerde taakdata uitvoer. Inspekteer proses-, databasislêer- en servicemetadata sonder om die ry te wysig of tydens enumerasie ’n taak te stuur.

’n Herhalende job kan eerder ’n opdrag lees uit ’n konfigurasie-ry in ’n application-databasis. Bevestig dat die minderbevoorregte databasisrol daardie presiese ry kan verander, dat die aktiewe job dit ná die verandering lees, en dat die waarde ’n shell of soortgelyke command-runner onder ’n hoër OS-identiteit bereik. Databasis-skryftoegang of ’n waarde wat soos ’n opdrag lyk, bewys nie op sigself uitvoering nie; inspekteer die job en toestemmings sonder om die ry tydens passiewe enumerasie te verander.

’n Boodskap in ’n ry kan ook ’n URL bevat eerder as kode. As ’n bevoorregte verbruiker daardie URL ophaal en die antwoord as ’n Lua- of ander uitvoerbare plugin laai, verifieer die uitgewer se toestemming op die presiese exchange en routing key, die binding aan die verbruikte ry, die ophaal- en plugin-laaipad, en die werker se effektiewe identiteit. [RabbitMQ stuur gepubliseerde boodskappe deur exchanges](https://www.rabbitmq.com/docs/exchanges); ’n broker-listener of geldige aanmelding alleen bewys nie aflewering aan hierdie werker nie. Vasgelegde duideliketeks-broker-credentials is ’n afsonderlike leidraad wat werklike toegang tot pakkievaslegging en leesbare verkeer vereis; dit bewys nie publiseerregte nie. ’n Lua-plugin kan shell-opdragte deur [`os.execute`](https://www.lua.org/manual/5.4/manual.html#pdf-os.execute) uitvoer slegs as daardie API in sy runtime beskikbaar is. Hersien konfigurasie en kode sonder om verkeer vas te lê, boodskappe te publiseer of tydens passiewe enumerasie ’n plugin op te haal.

Wanneer ’n bevoorregte Python-service ’n plaaslike HTTP- of socket-endpoint blootstel, kan ’n leesbare script ’n pad van invoer na kode onthul, selfs al verhinder sy lêertoestemmings wysiging. Korreleer die aktiewe proses- en unit-identiteit met die presiese script, listener, roetemagtiging en velde wat deur die oproeper beheer word. Volg dan daardie velde deur ontleding en validering tot by ’n dinamiese `eval()`- of `exec()`-sink. Om veral ’n nuwe f-string uit request-teks te bou en dit te evalueer, kan aanvaller-verskafte vervangingsvelde as Python-expressies interpreteer ([Python `eval`-waarskuwing](https://docs.python.org/3/library/functions.html#eval); [f-string-semantiek](https://docs.python.org/3/reference/lexical_analysis.html#f-strings)). ’n Blote `eval`-treffer of loopback-binding bewys nie dat ’n onbetroubare oproeper die sink bereik nie; hersien die werklike datavloei en toegangskontroles sonder om tydens enumerasie ’n toets-payload te stuur.

’n Signed-request-poort op daardie roete vereis sy eie hersiening. As leesbare bronkode die signing key aflei uit ’n aantoonbaar klein of voorspelbare uitvoerruimte, en die service ’n geldige getekende voorbeeld blootstel, beskerm die handtekening moontlik nie meer ’n bevoorregte `eval()`-sink nie. Verifieer die presiese sleutelafleiding en verifier, die aktiewe service-identiteit en plaaslike oproepertoegang, en of die getekende veld die sink bereik; ’n import van Python se [`random`-module](https://docs.python.org/3/library/random.html) of ’n voorbeeldhandtekening bewys nie enige van dié voorwaardes nie. Python waarsku ook dat die beperking van `__builtins__` [nie ’n sekuriteitsgrens vir onbetroubare `eval()`-invoer is nie](https://docs.python.org/3/library/functions.html#eval). Ontleed sleutels vanlyn en moenie tydens passiewe enumerasie vervalste requests indien nie.

’n Leë maar skryfbare `/etc/systemd/system/<unit>.service.d`-gids is relevant selfs wanneer die unit-lêer en elke bestaande drop-in beskerm is: die gebruiker kan ’n nuwe `.conf`-override skep. Gaan na of die huidige identiteit in die gids kan skryf en soek, of die unit gelaai is en as root loop, en of ’n daemon-herlaai gevolg deur ’n herbegin sal plaasvind. Toestemming om te herlaai of te herbegin, ’n timer of ’n latere boot kan die verandering van krag laat word; skryftoegang tot die gids alleen voer dit nie onmiddellik uit nie.

Vir aktiewe services, volg letterlike `EnvironmentFile=`-paaie vanaf die unit se `[Service]`-afdeling, insluitend lêers waarvan die name nie met `.env` begin nie. As ’n gebruiker met lae regte een kan lees, lys credential-agtige sleutelname soos `API_TOKEN` of `APP_SECRET_KEY` sonder om die waardes in gedeelde logs te druk. Gaan drop-in-oorrides en opsionele `-`-voorvoegsels na wanneer jy die effektiewe unit beoordeel. Leesbaarheid is ’n leidraad van blootgestelde credentials; die waarde moet steeds vir ’n bevoorregte handeling geldig wees om tot eskalasie te lei.

### Bevoorregte verwerking van onbetroubare oplaaie

’n Lêerwagter wat as root loop, kan lêers uit ’n skryfbare oplaai-gids aan ’n kortlewende ontleder of extractor oorhandig. Volg die aktiewe wagter se ouerscript of service en bevestig die presiese gids, wie lêers daar kan plaas, die child-opdrag en sy argumente, en die identiteit waaronder die child loop. ’n Prosesopname kan die wagter wys terwyl dit die extractor tussen oplaaie mis. Moenie tydens passiewe enumerasie ’n toets-payload plaas of die wagter aktiveer nie.

Een konkrete voorbeeld is Binwalk se extraction mode (`-e`) wat aanvallerbeheerde PFS-data verwerk. [CVE-2022-4510](https://github.com/ReFirmLabs/binwalk/pull/617) het toegelaat dat die PFS-extractor buite sy beoogde gids skryf, insluitend na ’n plugin-pad wat Binwalk later kon laai. Upstream het die regstelling in [2.3.4](https://github.com/ReFirmLabs/binwalk/releases/tag/v2.3.4) ingesluit, maar backports deur distribusies kan ’n ouer vertoonde weergawe behou; gaan die geïnstalleerde package se sekuriteitstatus na, soos die [Debian tracker](https://security-tracker.debian.org/tracker/CVE-2022-4510), voordat jy bepaal of dit van toepassing is. ’n Geïnstalleerde Binwalk-weergawe alleen bewys nie ’n privilege-escalation-pad nie: ’n meer bevoorregte proses moet die extraction werklik op invoer uitvoer wat die minderbevoorregte gebruiker kan beheer.

### Geskeduleerde builds met plaaslike dependencies

’n Geskeduleerde `cargo run` herkompileer bronkode as die job se run-as-gebruiker. Inspekteer die manifest se plaaslike `{ path = "..." }`-dependencies en die bronkode- en ouergidstoestemmings van elke dependency, nie net dié van die hoof-crate nie. As ’n minderbevoorregte gebruiker ’n dependency kan wysig wat Cargo kompileer en die geskeduleerde job die resultaat uitvoer, kan die gekompileerde kode as daardie run-as-gebruiker loop. Bevestig die effektiewe scheduler-opdrag, werksgids, dependency-resolusie en of ’n herbou sal plaasvind; ’n skryfbare Rust-bronlêer elders is slegs ’n leidraad. Om die manifest en padmetadata te lees, is genoeg vir passiewe triage. Sien die [Cargo-dokumentasie oor path-dependencies](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#specifying-path-dependencies).

## Xvfb-raambufferlêers

`Xvfb -fbdir <directory>` gebruik geheuegekoppelde lêers met die name `Xvfb_screen<n>` vir sy virtuele skerms. As ’n ander gebruiker se aktiewe Xvfb-proses ’n gids benoem waarvan die skermlêers vir die huidige gebruiker leesbaar is, kan die raambuffer daardie gebruiker se lessenaarinhoud blootlê. Bevestig die proses, lêereienaarskap en toestemmings saam; ’n leesbare lêer op sigself bewys nie dat bruikbare inhoud op die skerm is nie. Inspekteer eers paaie en metadata, sonder om beelddata na gedeelde enumerasie-uitvoer te kopieer. Die [Xvfb-handleiding](https://xorg.freedesktop.org/archive/X11R7.5/doc/man/man1/Xvfb.1.html) dokumenteer die gedrag van `-fbdir`.

```bash
pgrep -a -x Xvfb
ls -l /path/from/-fbdir/Xvfb_screen*
```

## References

1. [Linux `shmget(2)`-handleiding](https://man7.org/linux/man-pages/man2/shmget.2.html)
2. [Linux `ipcs(1)`-handleiding](https://man7.org/linux/man-pages/man1/ipcs.1.html)
3. [OpenBSD `ipcs(1)`-handleiding](https://man.openbsd.org/ipcs.1)
4. [Consul-agentkonfigurasie: scriptkontroles](https://developer.hashicorp.com/consul/docs/reference/agent/configuration-file/general)
5. [Consul-agentdiensregistrasie-API](https://developer.hashicorp.com/consul/api-docs/agent/service)
6. [Consul ACL-konfigurasie](https://developer.hashicorp.com/consul/docs/reference/agent/configuration-file/acl)
7. [LibreOffice-hulp: maak ’n socket oop vir eksterne API-kliënte](https://help.libreoffice.org/latest/en-US/text/sbasic/shared/03/sf_intro.html)
8. [LibreOffice SDK: `XSystemShellExecute`](https://api.libreoffice.org/docs/idl/ref/interfacecom_1_1sun_1_1star_1_1system_1_1XSystemShellExecute.html)

{{#include ../../banners/hacktricks-training.md}}
