# macOS xpc_connection_get_audit_token Aanval

{{#include ../../../../../../banners/hacktricks-training.md}}

**Vir verdere inligting, kyk die oorspronklike pos:** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/). Dit is 'n opsomming:

## Mach Berigte Basiese Inligting

As jy nie weet wat Mach Berigte is nie, begin om hierdie bladsy te kyk:

{{#ref}}
../../
{{#endref}}

Vir die oomblik onthou dat ([definisie van hier](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):\
Mach berigte word oor 'n _mach poort_ gestuur, wat 'n **enkele ontvanger, veelvuldige sender kommunikasie** kanaal is wat in die mach-kern ingebou is. **Meerdere prosesse kan berigte** na 'n mach poort stuur, maar op enige tydstip **kan slegs 'n enkele proses dit lees**. Net soos lêer beskrywings en sokke, word mach poorte toegeken en bestuur deur die kern en prosesse sien slegs 'n heelgetal, wat hulle kan gebruik om aan die kern aan te dui watter van hul mach poorte hulle wil gebruik.

## XPC Verbinding

As jy nie weet hoe 'n XPC verbinding gevestig word nie, kyk:

{{#ref}}
../
{{#endref}}

## Kwetsbaarheid Opsomming

Wat interessant is om te weet, is dat **XPC se abstraksie 'n een-tot-een verbinding is**, maar dit is gebaseer op 'n tegnologie wat **meerdere senders kan hê, so:**

- Mach poorte is enkele ontvanger, **meerdere sender**.
- 'n XPC verbinding se audit token is die audit token van **gekopieer van die mees onlangs ontvangde boodskap**.
- Om die **audit token** van 'n XPC verbinding te verkry, is krities vir baie **veiligheidskontroles**.

Alhoewel die vorige situasie belowend klink, is daar sommige scenario's waar dit nie probleme gaan veroorsaak nie ([van hier](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):

- Audit tokens word dikwels gebruik vir 'n outorisering kontrole om te besluit of 'n verbinding aanvaar moet word. Aangesien dit gebeur deur 'n boodskap na die dienspoort, is daar **nog geen verbinding gevestig nie**. Meer boodskappe op hierdie poort sal net hanteer word as addisionele verbindingsversoeke. So enige **kontroles voordat 'n verbinding aanvaar word, is nie kwesbaar nie** (dit beteken ook dat binne `-listener:shouldAcceptNewConnection:` die audit token veilig is). Ons is dus **op soek na XPC verbindings wat spesifieke aksies verifieer**.
- XPC gebeurtenis hanteerders word sinchronies hanteer. Dit beteken dat die gebeurtenis hanteerder vir een boodskap voltooi moet wees voordat dit vir die volgende een aangeroep kan word, selfs op gelyktydige afleweringsrye. So binne 'n **XPC gebeurtenis hanteerder kan die audit token nie oorgeskryf word** deur ander normale (nie-antwoorde!) boodskappe nie.

Twee verskillende metodes wat dalk uitgebuit kan word:

1. Variant1:
- **Eksploiteer** **verbinde** na diens **A** en diens **B**
- Diens **B** kan 'n **bevoorregte funksionaliteit** in diens A aanroep wat die gebruiker nie kan nie
- Diens **A** roep **`xpc_connection_get_audit_token`** aan terwyl _**nie**_ binne die **gebeurtenis hanteerder** vir 'n verbinding in 'n **`dispatch_async`**.
- So 'n **ander** boodskap kan die **Audit Token oorgeskryf** omdat dit asynchrone gestuur word buite die gebeurtenis hanteerder.
- Die eksploiteer gee aan **diens B die SEND reg na diens A**.
- So diens **B** sal eintlik **boodskappe** na diens **A** **stuur**.
- Die **eksploiteer** probeer om die **bevoorregte aksie aan te roep.** In 'n RC diens **A** **kontroleer** die outorisering van hierdie **aksie** terwyl **diens B die Audit token oorgeskryf het** (wat die eksploiteer toegang gee om die bevoorregte aksie aan te roep).
2. Variant 2:
- Diens **B** kan 'n **bevoorregte funksionaliteit** in diens A aanroep wat die gebruiker nie kan nie
- Eksploiteer verbind met **diens A** wat **stuur** die eksploiteer 'n **boodskap wat 'n antwoord verwag** in 'n spesifieke **herhalings** **poort**.
- Eksploiteer stuur **diens** B 'n boodskap wat **daardie antwoordpoort** oorplaas.
- Wanneer diens **B antwoord**, dit **stuur die boodskap na diens A**, **terwyl** die **eksploiteer** 'n ander **boodskap na diens A** stuur wat probeer om 'n **bevoorregte funksionaliteit** te bereik en verwag dat die antwoord van diens B die Audit token op die perfekte oomblik sal oorgeskryf (Race Condition).

## Variant 1: roep xpc_connection_get_audit_token aan buite 'n gebeurtenis hanteerder <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Scenario:

- Twee mach dienste **`A`** en **`B`** waartoe ons albei kan verbind (gebaseer op die sandbox profiel en die outorisering kontroles voordat die verbinding aanvaar word).
- _**A**_ moet 'n **outorisering kontrole** hê vir 'n spesifieke aksie wat **`B`** kan deurgee (maar ons app kan nie).
- Byvoorbeeld, as B 'n paar **regte** het of as **root** loop, kan dit hom dalk toelaat om A te vra om 'n bevoorregte aksie uit te voer.
- Vir hierdie outorisering kontrole, **`A`** verkry die audit token asynchrone, byvoorbeeld deur `xpc_connection_get_audit_token` aan te roep vanaf **`dispatch_async`**.

> [!CAUTION]
> In hierdie geval kan 'n aanvaller 'n **Race Condition** aktiveer wat 'n **eksploiteer** wat **A vra om 'n aksie** verskeie kere uit te voer terwyl **B boodskappe na `A`** stuur. Wanneer die RC **suksesvol** is, sal die **audit token** van **B** in geheue gekopieer word **terwyl** die versoek van ons **eksploiteer** hanteer word deur A, wat dit **toegang gee tot die bevoorregte aksie wat slegs B kon aanvra**.

Dit het gebeur met **`A`** as `smd` en **`B`** as `diagnosticd`. Die funksie [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) van smb kan gebruik word om 'n nuwe bevoorregte helper gereedskap te installeer (as **root**). As 'n **proses wat as root loop** **smd** kontak, sal geen ander kontroles uitgevoer word nie.

Daarom is die diens **B** **`diagnosticd`** omdat dit as **root** loop en gebruik kan word om 'n proses te **monitor**, so sodra monitering begin het, sal dit **meerdere boodskappe per sekonde stuur.**

Om die aanval uit te voer:

1. Begin 'n **verbinding** na die diens genaamd `smd` met behulp van die standaard XPC protokol.
2. Vorm 'n sekondêre **verbinding** na `diagnosticd`. In teenstelling met die normale prosedure, eerder as om twee nuwe mach poorte te skep en te stuur, word die kliëntpoort stuurreg vervang met 'n duplikaat van die **stuurreg** wat geassosieer is met die `smd` verbinding.
3. As gevolg hiervan kan XPC boodskappe na `diagnosticd` gestuur word, maar antwoorde van `diagnosticd` word hergeroute na `smd`. Vir `smd` lyk dit asof die boodskappe van beide die gebruiker en `diagnosticd` afkomstig is van dieselfde verbinding.

![Beeld wat die eksploiteer proses uitbeeld](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. Die volgende stap behels om `diagnosticd` te instrueer om monitering van 'n gekose proses (potensieel die gebruiker se eie) te begin. Gelyktydig word 'n vloed van roetine 1004 boodskappe na `smd` gestuur. Die bedoeling hier is om 'n gereedskap met verhoogde regte te installeer.
5. Hierdie aksie aktiveer 'n race condition binne die `handle_bless` funksie. Die tydsberekening is krities: die `xpc_connection_get_pid` funksie-aanroep moet die PID van die gebruiker se proses teruggee (aangesien die bevoorregte gereedskap in die gebruiker se app bundel is). Maar die `xpc_connection_get_audit_token` funksie, spesifiek binne die `connection_is_authorized` subroutine, moet die audit token wat aan `diagnosticd` behoort, verwys.

## Variant 2: antwoord herleiding

In 'n XPC (Cross-Process Communication) omgewing, alhoewel gebeurtenis hanteerders nie gelyktydig uitvoer nie, het die hantering van antwoord boodskappe 'n unieke gedrag. Spesifiek bestaan daar twee verskillende metodes om boodskappe te stuur wat 'n antwoord verwag:

1. **`xpc_connection_send_message_with_reply`**: Hier word die XPC boodskap ontvang en verwerk op 'n aangewese ry.
2. **`xpc_connection_send_message_with_reply_sync`**: Omgekeerd, in hierdie metode, word die XPC boodskap ontvang en verwerk op die huidige afleweringsry.

Hierdie onderskeid is belangrik omdat dit die moontlikheid toelaat van **antwoord pakkette wat gelyktydig geparseer word met die uitvoering van 'n XPC gebeurtenis hanteerder**. Opmerklik is dat terwyl `_xpc_connection_set_creds` wel vergrendeling implementeer om teen die gedeeltelike oorgeskryf van die audit token te beskerm, strek dit nie hierdie beskerming na die hele verbinding objek nie. Gevolglik skep dit 'n kwesbaarheid waar die audit token vervang kan word gedurende die interval tussen die parsing van 'n pakket en die uitvoering van sy gebeurtenis hanteerder.

Om hierdie kwesbaarheid uit te buit, is die volgende opstelling nodig:

- Twee mach dienste, genoem **`A`** en **`B`**, wat albei 'n verbinding kan vestig.
- Diens **`A`** moet 'n outorisering kontrole insluit vir 'n spesifieke aksie wat slegs **`B`** kan uitvoer (die gebruiker se toepassing kan nie).
- Diens **`A`** moet 'n boodskap stuur wat 'n antwoord verwag.
- Die gebruiker kan 'n boodskap na **`B`** stuur wat dit sal antwoord.

Die eksploitasie proses behels die volgende stappe:

1. Wag vir diens **`A`** om 'n boodskap te stuur wat 'n antwoord verwag.
2. In plaas daarvan om direk aan **`A`** te antwoord, word die antwoordpoort gekaap en gebruik om 'n boodskap na diens **`B`** te stuur.
3. Vervolgens word 'n boodskap wat die verbode aksie behels, gestuur, met die verwagting dat dit gelyktydig verwerk sal word met die antwoord van **`B`**.

Hieronder is 'n visuele voorstelling van die beskryfde aanval scenario:

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../images/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../images/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Ontdekking Probleme

- **Moeilikhede om Voorbeelde te Vind**: Soek na voorbeelde van `xpc_connection_get_audit_token` gebruik was uitdagend, beide staties en dinamies.
- **Metodologie**: Frida is gebruik om die `xpc_connection_get_audit_token` funksie te haak, wat oproepe gefilter het wat nie van gebeurtenis hanteerders afkomstig was nie. Hierdie metode was egter beperk tot die gehaakte proses en het aktiewe gebruik vereis.
- **Analise Gereedskap**: Gereedskap soos IDA/Ghidra is gebruik om bereikbare mach dienste te ondersoek, maar die proses was tydrowend, bemoeilik deur oproepe wat die dyld gedeelde kas betrek.
- **Scripting Beperkings**: Pogings om die analise te script vir oproepe na `xpc_connection_get_audit_token` van `dispatch_async` blokke is belemmer deur kompleksiteite in die parsing van blokke en interaksies met die dyld gedeelde kas.

## Die oplossing <a href="#the-fix" id="the-fix"></a>

- **Gerapporteerde Probleme**: 'n Verslag is ingedien by Apple wat die algemene en spesifieke probleme wat in `smd` gevind is, uiteengesit het.
- **Apple se Antwoord**: Apple het die probleem in `smd` aangespreek deur `xpc_connection_get_audit_token` te vervang met `xpc_dictionary_get_audit_token`.
- **Natuur van die Oplossing**: Die `xpc_dictionary_get_audit_token` funksie word beskou as veilig aangesien dit die audit token direk van die mach boodskap wat aan die ontvangde XPC boodskap gekoppel is, verkry. Dit is egter nie deel van die openbare API nie, soortgelyk aan `xpc_connection_get_audit_token`.
- **Afwesigheid van 'n Breër Oplossing**: Dit bly onduidelik waarom Apple nie 'n meer omvattende oplossing geïmplementeer het nie, soos om boodskappe wat nie ooreenstem met die gestoor audit token van die verbinding nie, te verwerp. Die moontlikheid van legitieme audit token veranderinge in sekere scenario's (bv. `setuid` gebruik) mag 'n faktor wees.
- **Huidige Status**: Die probleem bestaan voort in iOS 17 en macOS 14, wat 'n uitdaging vir diegene wat dit wil identifiseer en verstaan.

{{#include ../../../../../../banners/hacktricks-training.md}}
