# macOS xpc_connection_get_audit_token Attack

{{#include ../../../../../../banners/hacktricks-training.md}}

**Za dodatne informacije pogledajte originalnu objavu:** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/). Ovo je sažetak:<sup>[[1]](#references)</sup>

## Osnovne informacije o Mach Messages

Ako ne znate šta su Mach Messages, počnite od ove stranice:


{{#ref}}
../../
{{#endref}}

Za sada zapamtite sledeće ([definicija odavde](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):<sup>[[1]](#references)</sup>\
Mach messages se šalju preko _mach port_-a, koji predstavlja komunikacioni kanal ugrađen u mach kernel i namenjen **jednom primaocu i većem broju pošiljalaca**. **Više procesa može slati messages** na mach port, ali u svakom trenutku **samo jedan proces može čitati sa njega**. Kao i file descriptors i sockets, mach ports se dodeljuju i njima upravlja kernel, dok procesi vide samo ceo broj koji mogu koristiti da kernelu označe koji od svojih mach ports žele da koriste.

## XPC Connection

Ako ne znate kako se uspostavlja XPC connection, pogledajte:


{{#ref}}
../
{{#endref}}

## Sažetak ranjivosti

Važno je da znate da je **XPC apstrakcija one-to-one connection**, ali je zasnovana na tehnologiji koja **može imati više pošiljalaca, dakle:**

- Mach ports imaju jednog primaoca i **više pošiljalaca**.
- Audit token XPC connection-a je audit token **kopiran iz poslednje primljene poruke**.
- Dobavljanje **audit token-a** XPC connection-a ključno je za mnoge **security provere**.<sup>[[1]](#references)</sup>

Iako prethodna situacija zvuči obećavajuće, postoje scenariji u kojima ovo neće izazvati probleme ([odavde](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):<sup>[[1]](#references)</sup>

- Audit tokens se često koriste za authorization check kojim se odlučuje da li će connection biti prihvaćen. Pošto se ovo obavlja pomoću message-a poslatog na service port, **connection još nije uspostavljen**. Dodatne messages na ovom port-u samo će biti obrađene kao dodatni zahtevi za connection. Zato **provere pre prihvatanja connection-a nisu ranjive** (što takođe znači da je unutar `-listener:shouldAcceptNewConnection:` audit token bezbedan). Zbog toga **tražimo XPC connections koje proveravaju konkretne akcije**.
- XPC event handlers se obrađuju sinhrono. To znači da event handler za jednu poruku mora biti završen pre nego što se pozove za sledeću poruku, čak i na konkurentnim dispatch queues. Zato unutar **XPC event handler-a audit token ne može biti prepisan** drugim normalnim (non-reply!) porukama.<sup>[[1]](#references)</sup>

Postoje dva različita načina na koja ovo može biti exploitable:

1. Variant1:
- **Exploit** se **povezuje** na service **A** i service **B**
- Service **B** može pozvati **privileged functionality** u service-u A koju korisnik ne može
- Service **A** poziva **`xpc_connection_get_audit_token`** dok se _**ne**_ nalazi unutar **event handler-a** za connection u okviru **`dispatch_async`**.
- Zato bi **drugačija** poruka mogla **prepisati Audit Token**, jer se obrađuje asinhrono izvan event handler-a.
- Exploit prosleđuje **service-u B SEND right ka service-u A**.
- Tako će svc **B** zapravo **slati** **messages** service-u **A**.
- **Exploit** pokušava da pozove **privileged action**. U RC-u svc **A** proverava authorization za ovu **action** dok je **svc B prepisao Audit token** (dajući exploit-u pristup pozivanju privileged action-a).
2. Variant 2:
- Service **B** može pozvati **privileged functionality** u service-u A koju korisnik ne može
- Exploit se povezuje sa **service-om A**, koji exploit-u **šalje** **message koji očekuje odgovor** na određeni **replay** **port**.
- Exploit šalje service-u B message koji prosleđuje **taj reply port**.
- Kada service **B** odgovori, on **šalje poruku service-u A**, **dok** **exploit** šalje drugačiju **poruku service-u A** pokušavajući da **dostigne privileged functionality** i očekujući da će odgovor service-a B u pravom trenutku prepisati Audit token (Race Condition).

## Variant 1: calling xpc_connection_get_audit_token outside of an event handler <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Scenario:

- Dva mach services, **`A`** i **`B`**, na koje možemo da se povežemo (na osnovu sandbox profile-a i authorization checks pre prihvatanja connection-a).
- _**A**_ mora imati **authorization check** za konkretnu akciju koju **B** može proći (ali naša aplikacija ne može).
- Na primer, ako B ima određene **entitlements** ili se izvršava kao **root**, može mu biti dozvoljeno da zatraži od A izvršavanje privileged action-a.
- Za ovaj authorization check, **A** asinhrono dobavlja audit token, na primer pozivanjem `xpc_connection_get_audit_token` iz `dispatch_async`-a.

> [!CAUTION]
> U ovom slučaju attacker može izazvati **Race Condition** tako što pravi **exploit** koji od **A** više puta traži izvršavanje action-a, dok **B** šalje messages ka **A**. Kada je RC **uspešan**, **audit token** od **B** biće kopiran u memoriju **dok** A obrađuje zahtev našeg **exploit-a**, dajući mu **pristup privileged action-u koji je mogao da zatraži samo B**.

Ovo se dogodilo sa **`A`** kao `smd` i **`B`** kao `diagnosticd`. Funkcija [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) iz smb može se koristiti za instaliranje novog privileged helper alata (kao **root**). Ako **process koji se izvršava kao root kontaktira** **smd**, neće biti izvršene nikakve druge provere.

Zato je service **B** zapravo **`diagnosticd`**, jer se izvršava kao **root** i može se koristiti za **monitoring** procesa, pa će, kada monitoring počne, **slati više messages-a u sekundi.**

Za izvođenje napada:

1. Inicirajte **connection** ka service-u nazvanom `smd` koristeći standardni XPC protocol.
2. Uspostavite sekundarni **connection** ka `diagnosticd`. Za razliku od uobičajene procedure, umesto kreiranja i slanja dva nova mach ports, client port send right se zamenjuje duplikatom **send right-a** povezanog sa `smd` connection-om.
3. Kao rezultat, XPC messages mogu biti prosleđene service-u `diagnosticd`, ali se odgovori od `diagnosticd` preusmeravaju ka `smd`. Service-u `smd` izgleda kao da messages i od korisnika i od `diagnosticd` potiču iz istog connection-a.

![Image depicting the exploit process](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. Sledeći korak podrazumeva nalaženje service-u `diagnosticd` da započne monitoring izabranog procesa (potencijalno sopstvenog procesa korisnika). Istovremeno se service-u `smd` šalje veliki broj uobičajenih 1004 messages-a. Cilj je instaliranje alata sa povišenim privileges.
5. Ova action izaziva race condition unutar funkcije `handle_bless`. Vreme je ključno: poziv funkcije `xpc_connection_get_pid` mora vratiti PID procesa korisnika (pošto se privileged tool nalazi u app bundle-u korisnika). Međutim, funkcija `xpc_connection_get_audit_token`, konkretno unutar potprograma `connection_is_authorized`, mora referencirati audit token koji pripada service-u `diagnosticd`.<sup>[[1]](#references)</sup>

## Variant 2: reply forwarding

U XPC (Cross-Process Communication) okruženju, iako se event handlers ne izvršavaju konkurentno, obrada reply messages-a ima jedinstveno ponašanje. Konkretno, postoje dva različita metoda za slanje messages-a koji očekuju reply:

1. **`xpc_connection_send_message_with_reply`**: Ovde se XPC message prima i obrađuje na određenom queue-u.
2. **`xpc_connection_send_message_with_reply_sync`**: Nasuprot tome, kod ovog metoda XPC message se prima i obrađuje na trenutnom dispatch queue-u.

Ova razlika je ključna jer omogućava da se **reply packets parsiraju konkurentno sa izvršavanjem XPC event handler-a**. Važno je napomenuti da, iako `_xpc_connection_set_creds` koristi locking radi zaštite od delimičnog prepisivanja audit token-a, ova zaštita se ne proširuje na ceo connection object. Posledično nastaje ranjivost u kojoj audit token može biti zamenjen tokom intervala između parsiranja packet-a i izvršavanja njegovog event handler-a.

Za exploit ove ranjivosti potrebno je sledeće podešavanje:

- Dva mach services-a, označena kao **`A`** i **`B`**, od kojih oba mogu uspostaviti connection.
- Service **`A`** treba da sadrži authorization check za konkretnu action koju samo **`B`** može izvršiti (aplikacija korisnika ne može).
- Service **`A`** treba da pošalje message koji očekuje reply.
- Korisnik može poslati message service-u **`B`**, na koji će on odgovoriti.

Proces exploitation-a obuhvata sledeće korake:

1. Sačekajte da service **`A`** pošalje message koji očekuje reply.
2. Umesto direktnog odgovora service-u **`A`**, reply port se preuzima i koristi za slanje message-a service-u **`B`**.
3. Zatim se šalje message koji uključuje zabranjenu action, uz očekivanje da će biti obrađen konkurentno sa reply-em service-a **`B`**.<sup>[[1]](#references)</sup>

U nastavku je vizuelni prikaz opisanog scenarija napada:

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../images/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../images/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Problemi pri otkrivanju

- **Teškoće pri pronalaženju instanci**: Pronalaženje instanci korišćenja `xpc_connection_get_audit_token` bilo je zahtevno, i statički i dinamički.
- **Metodologija**: Frida je korišćena za hook-ovanje funkcije `xpc_connection_get_audit_token`, uz filtriranje poziva koji ne potiču iz event handler-a. Međutim, ovaj metod je bio ograničen na hook-ovani process i zahtevao je njegovu aktivnu upotrebu.
- **Alati za analizu**: Alati poput IDA/Ghidra korišćeni su za ispitivanje dostupnih mach services-a, ali je proces bio dugotrajan, uz dodatne komplikacije zbog poziva koji uključuju dyld shared cache.
- **Ograničenja scripting-a**: Pokušaji da se analiza automatizuje za pozive `xpc_connection_get_audit_token` iz `dispatch_async` blokova bili su otežani složenošću parsiranja blokova i interakcijama sa dyld shared cache-om.<sup>[[1]](#references)</sup>

## Ispravka <a href="#the-fix" id="the-fix"></a>

- **Prijavljeni problemi**: Apple-u je poslat report sa detaljima opštih i konkretnih problema pronađenih u okviru `smd`.
- **Apple-ov odgovor**: Apple je rešio problem u `smd` tako što je zamenio `xpc_connection_get_audit_token` funkcijom `xpc_dictionary_get_audit_token`.<sup>[[1]](#references)[[2]](#references)</sup>
- **Priroda ispravke**: Funkcija `xpc_dictionary_get_audit_token` smatra se bezbednom jer audit token dobavlja direktno iz mach message-a povezanog sa primljenim XPC message-om. Međutim, ona nije deo public API-ja, slično kao `xpc_connection_get_audit_token`.
- **Nepostojanje šire ispravke**: Ostaje nejasno zašto Apple nije implementirao sveobuhvatniju ispravku, kao što je odbacivanje messages-a koji se ne podudaraju sa sačuvanim audit token-om connection-a. Moguće je da su razlog legitimne promene audit token-a u određenim scenarijima (npr. korišćenje `setuid`).
- **Trenutni status**: Problem i dalje postoji u iOS 17 i macOS 14, što predstavlja izazov za one koji pokušavaju da ga identifikuju i razumeju.<sup>[[1]](#references)</sup>

## Pronalaženje ranjivih code paths u praksi (2024–2025)

Prilikom auditovanja XPC services-a za ovu klasu bug-ova, fokusirajte se na authorization koja se izvršava izvan event handler-a message-a ili konkurentno sa obradom reply-a.

Saveti za statičku trijažu:
- Pretražite pozive ka `xpc_connection_get_audit_token` do kojih se može doći iz blokova stavljenih u queue pomoću `dispatch_async`/`dispatch_after` ili drugih worker queues-a koji se izvršavaju izvan message handler-a.
- Potražite authorization helpers koji mešaju stanje po connection-u i stanje po message-u (npr. PID se dobavlja pomoću `xpc_connection_get_pid`, a audit token pomoću `xpc_connection_get_audit_token`).
- U NSXPC code-u proverite da li se checks izvršavaju u `-listener:shouldAcceptNewConnection:` ili, kod provera po message-u, da li implementacija koristi audit token po message-u (npr. dictionary message-a preko `xpc_dictionary_get_audit_token` u lower-level code-u).

Saveti za dinamičku trijažu:
- Hook-ujte `xpc_connection_get_audit_token` i označite pozive čiji user stack ne sadrži putanju za isporuku event-a (npr. `_xpc_connection_mach_event`). Primer Frida hook-a:
```javascript
Interceptor.attach(Module.getExportByName(null, 'xpc_connection_get_audit_token'), {
onEnter(args) {
const bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
.map(DebugSymbol.fromAddress).join('\n');
if (!bt.includes('_xpc_connection_mach_event')) {
console.log('[!] xpc_connection_get_audit_token outside handler\n' + bt);
}
}
});
```
Napomene:
- Na macOS-u, instrumentacija zaštićenih/Apple binarnih datoteka može zahtevati onemogućen SIP ili razvojno okruženje; prednost dajte testiranju sopstvenih buildova ili userland servisa.
- Za trke pri prosleđivanju odgovora (Varijanta 2), pratite istovremeno parsiranje reply paketa fuzzovanjem vremenskih intervala između `xpc_connection_send_message_with_reply` i normalnih zahteva i proverite da li se može uticati na efektivni audit token koji se koristi tokom autorizacije.

## Eksploatacioni primitivi koji će vam verovatno biti potrebni

- Podešavanje sa više pošiljalaca (Varijanta 1): kreirajte konekcije ka A i B; duplicirajte send right klijentskog porta A i koristite ga kao klijentski port B, tako da se odgovori za B isporučuju A.
```c
// Duplicate a SEND right you already hold
mach_port_t dup;
mach_port_insert_right(mach_task_self(), a_client, a_client, MACH_MSG_TYPE_MAKE_SEND);
dup = a_client; // use `dup` when crafting B’s connect packet instead of a fresh client port
```
- Reply hijack (Variant 2): preuzmite send-once right iz A-ovog pending request-a (reply port), zatim pošaljite crafted message ka B koristeći taj reply port, tako da B-ov odgovor stigne do A dok se vaš privilegovani request parsira.

Ovo zahteva low-level mach message crafting za XPC bootstrap i formate poruka; pregledajte mach/XPC primer stranice u ovom odeljku za tačne rasporede paketa i flags.

## Korisni alati

- XPC sniffing/dynamic inspection: gxpc (open-source XPC sniffer) može pomoći pri nabrajanju konekcija i posmatranju saobraćaja radi validacije multi-sender podešavanja i vremenskog usklađivanja. Primer: `gxpc -p <PID> --whitelist <service-name>`.
- Classic dyld interposing za libxpc: izvršite interpose nad `xpc_connection_send_message*` i `xpc_connection_get_audit_token` da biste beležili call sites i stack-ove tokom black-box testiranja.



## Reference

- [1] [Sector 7 – Ne pričajte svi odjednom! Elevating Privileges on macOS by Audit Token Spoofing](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [2] [Apple – About the security content of macOS Ventura 13.4 (CVE‑2023‑32405)](https://support.apple.com/en-us/106333)


{{#include ../../../../../../banners/hacktricks-training.md}}
