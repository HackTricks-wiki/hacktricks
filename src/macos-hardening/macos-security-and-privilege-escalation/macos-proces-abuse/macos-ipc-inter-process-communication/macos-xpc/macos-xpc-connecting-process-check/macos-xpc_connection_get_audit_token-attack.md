# macOS xpc_connection_get_audit_token Attack

{{#include ../../../../../../banners/hacktricks-training.md}}

**Za više informacija pogledajte originalnu objavu:** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/). Ovo je sažetak:

## Osnovne informacije o Mach Messages

Ako ne znate šta su Mach Messages, počnite od ove stranice:


{{#ref}}
../../
{{#endref}}

Za sada zapamtite sledeće ([definicija odavde](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):\
Mach messages se šalju preko _mach port_-a, koji je komunikacioni kanal sa **jednim receiver-om i više sender-a**, ugrađen u mach kernel. **Više procesa može slati messages** na mach port, ali u bilo kom trenutku **samo jedan proces može čitati sa njega**. Kao i file descriptors i sockets, mach ports se alociraju i njima upravlja kernel, a procesi vide samo ceo broj koji mogu koristiti da kernelu navedu koji od svojih mach ports žele da koriste.

## XPC Connection

Ako ne znate kako se uspostavlja XPC connection, pogledajte:


{{#ref}}
../
{{#endref}}

## Sažetak ranjivosti

Važno je znati da je **XPC apstrakcija one-to-one connection**, ali se zasniva na tehnologiji koja **može imati više sender-a, dakle:**

- Mach ports imaju jednog receiver-a i **više sender-a**.
- Audit token XPC connection-a je audit token **kopiran iz najskorije primljene poruke**.
- Dobavljanje **audit token-a** XPC connection-a ključno je za mnoge **security checks**.<sup>[[1]](#references)</sup>

Iako prethodna situacija zvuči obećavajuće, postoje scenariji u kojima ovo neće izazvati probleme ([odavde](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):

- Audit tokens se često koriste za authorization check kojim se odlučuje da li treba prihvatiti connection. Pošto se ovo dešava pomoću message-a poslatog na service port, **connection još nije uspostavljen**. Dodatne messages na ovom port-u samo će biti obrađene kao dodatni zahtevi za connection. Zato **checks pre prihvatanja connection-a nisu ranjivi** (što takođe znači da je audit token unutar `-listener:shouldAcceptNewConnection:` bezbedan). Zato tražimo XPC connections koji proveravaju konkretne actions.
- XPC event handlers se obrađuju sinhrono. To znači da event handler za jednu message mora biti završen pre nego što se pozove za sledeću, čak i na konkurentnim dispatch queues. Zato unutar **XPC event handler-a audit token ne može biti overwritten** drugim uobičajenim messages (koje nisu reply!).<sup>[[1]](#references)</sup>

Postoje dva načina na koja bi ovo moglo biti exploitable:

1. Variant1:
- **Exploit** se **connects** na service **A** i service **B**
- Service **B** može pozvati **privileged functionality** u service-u A koju korisnik ne može.
- Service **A** poziva **`xpc_connection_get_audit_token`** dok _**nije**_ unutar **event handler-a** za connection u **`dispatch_async`**.
- Zato bi drugačija message mogla **overwrite-ovati Audit Token**, jer se dispatch-uje asinhrono izvan event handler-a.
- Exploit prosleđuje **SEND right service-a A** service-u **B**.
- Zato će svc **B** zapravo **slati** **messages** service-u **A**.
- **Exploit** pokušava da pozove **privileged action**. U RC-u svc **A** **proverava** authorization za ovu **action** dok je **svc B overwrite-ovao Audit token** (dajući exploit-u pristup pozivanju privileged action-a).
2. Variant 2:
- Service **B** može pozvati **privileged functionality** u service-u A koju korisnik ne može.
- Exploit se povezuje sa **service-om A**, koji exploit-u šalje **message koja očekuje response** na određeni **replay** **port**.
- Exploit šalje service-u B message koja prosleđuje **taj reply port**.
- Kada service **B** odgovori, on **šalje message service-u A**, dok **exploit** šalje drugačiju **message service-u A** u pokušaju da **dostigne privileged functionality** i očekuje da će reply od service-a B overwrite-ovati Audit token u pravom trenutku (Race Condition).

## Variant 1: pozivanje xpc_connection_get_audit_token izvan event handler-a <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Scenario:

- Dva mach services, **`A`** i **`B`**, na koje možemo da se povežemo (na osnovu sandbox profile-a i authorization checks pre prihvatanja connection-a).
- _**A**_ mora imati **authorization check** za konkretnu action koju **B** može proći (ali naša app ne može).
- Na primer, ako B ima određene **entitlements** ili radi kao **root**, može mu biti dozvoljeno da zatraži od A izvršavanje privileged action-a.
- Za ovaj authorization check, **A** asinhrono dobavlja audit token, na primer pozivanjem `xpc_connection_get_audit_token` iz `dispatch_async`-a.

> [!CAUTION]
> U ovom slučaju attacker može izazvati **Race Condition** i napraviti **exploit** koji više puta traži od A da izvrši action, dok istovremeno **B šalje messages service-u `A`**. Kada je RC **uspešan**, **audit token** od **B** biće kopiran u memoriju **dok A obrađuje zahtev našeg exploita**, dajući mu **access** privilegovanoj action-i koju bi samo B mogao da zatraži.

Ovo se dogodilo sa **`A`** kao `smd` i **`B`** kao `diagnosticd`. Funkcija [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) iz smb može se koristiti za instaliranje novog privileged helper tool-a (kao **root**). Ako **process running as root contact**-uje **`smd`**, neće biti izvršene nikakve druge checks.

Zato je service **B** **`diagnosticd`**, jer radi kao **root** i može se koristiti za **monitoring** procesa, pa kada monitoring počne, on će **slati više messages-a u sekundi.**

Za izvršavanje napada:

1. Inicijalizujte **connection** ka service-u pod imenom `smd` koristeći standardni XPC protocol.
2. Uspostavite sekundarnu **connection** ka `diagnosticd`. Suprotno uobičajenom postupku, umesto kreiranja i slanja dva nova mach ports, client port send right se zamenjuje duplikatom **send right-a** povezanog sa `smd` connection-om.
3. Kao rezultat, XPC messages mogu biti dispatch-ovane ka `diagnosticd`, ali se responses od `diagnosticd` preusmeravaju ka `smd`. Za `smd`, izgleda kao da messages i od korisnika i od `diagnosticd` potiču iz istog connection-a.

![Slika koja prikazuje proces exploita](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. Sledeći korak je nalaženje da `diagnosticd` započne monitoring izabranog procesa (potencijalno sopstvenog procesa korisnika). Istovremeno se `smd` šalje flood uobičajenih 1004 messages. Cilj je instaliranje tool-a sa elevated privileges.
5. Ova action izaziva race condition unutar funkcije `handle_bless`. Vreme je kritično: poziv funkcije `xpc_connection_get_pid` mora vratiti PID procesa korisnika (jer se privileged tool nalazi u bundle-u user app-a). Međutim, funkcija `xpc_connection_get_audit_token`, konkretno unutar subroutine-a `connection_is_authorized`, mora referencirati audit token koji pripada `diagnosticd`-u.<sup>[[1]](#references)</sup>

## Variant 2: prosleđivanje reply-a

U XPC (Cross-Process Communication) okruženju, iako se event handlers ne izvršavaju konkurentno, obrada reply messages ima jedinstveno ponašanje. Konkretno, postoje dva različita načina slanja messages koje očekuju reply:

1. **`xpc_connection_send_message_with_reply`**: Ovde se XPC message prima i obrađuje na određenom queue-u.
2. **`xpc_connection_send_message_with_reply_sync`**: Nasuprot tome, kod ove metode XPC message se prima i obrađuje na trenutnom dispatch queue-u.

Ova razlika je ključna jer omogućava da se **reply packets parsiraju konkurentno sa izvršavanjem XPC event handler-a**. Važno je da `_xpc_connection_set_creds` zaista koristi locking kako bi zaštitio audit token od delimičnog overwrite-a, ali ova zaštita se ne proširuje na ceo connection object. Posledično nastaje ranjivost u kojoj audit token može biti zamenjen tokom intervala između parsiranja packet-a i izvršavanja njegovog event handler-a.

Za iskorišćavanje ove ranjivosti potrebno je sledeće podešavanje:

- Dva mach services-a, označena kao **`A`** i **`B`**, koji oba mogu uspostaviti connection.
- Service **`A`** treba da sadrži authorization check za konkretnu action koju samo **`B`** može izvršiti (user application ne može).
- Service **`A`** treba da pošalje message koja očekuje reply.
- Korisnik može poslati message service-u **`B`**, a on će na nju odgovoriti.

Proces exploitation-a obuhvata sledeće korake:

1. Sačekajte da service **`A`** pošalje message koja očekuje reply.
2. Umesto direktnog odgovora service-u **`A`**, reply port se preuzima i koristi za slanje message service-u **`B`**.
3. Zatim se dispatch-uje message koja uključuje zabranjenu action, uz očekivanje da će biti obrađena konkurentno sa reply-em service-a **`B`**.<sup>[[1]](#references)</sup>

U nastavku je vizuelni prikaz opisanog attack scenario-a:

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../images/image (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../images/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Problemi pri otkrivanju

- **Poteškoće pri pronalaženju instanci**: Pretraga instances upotrebe `xpc_connection_get_audit_token` bila je zahtevna, kako statički tako i dinamički.
- **Methodology**: Frida je korišćena za hook-ovanje funkcije `xpc_connection_get_audit_token`, uz filtriranje poziva koji ne potiču iz event handler-a. Međutim, ova metoda je bila ograničena na hook-ovani process i zahtevala je njegovu aktivnu upotrebu.
- **Analysis Tooling**: Alati kao što su IDA/Ghidra korišćeni su za ispitivanje dostupnih mach services-a, ali je proces bio dugotrajan i dodatno komplikovan pozivima koji uključuju dyld shared cache.
- **Scripting Limitations**: Pokušaji da se analiza skriptuje za pozive ka `xpc_connection_get_audit_token` iz `dispatch_async` blocks bili su otežani složenošću parsiranja blocks i interakcijama sa dyld shared cache-om.<sup>[[1]](#references)</sup>

## Ispravka <a href="#the-fix" id="the-fix"></a>

- **Prijavljeni problemi**: Apple-u je poslat report sa detaljima o opštim i specifičnim problemima pronađenim u `smd`-u.
- **Apple-ov odgovor**: Apple je rešio problem u `smd`-u tako što je zamenio `xpc_connection_get_audit_token` funkcijom `xpc_dictionary_get_audit_token`.<sup>[[1]](#references)[[2]](#references)</sup>
- **Priroda ispravke**: Funkcija `xpc_dictionary_get_audit_token` smatra se bezbednom jer audit token dobavlja direktno iz mach message-a povezanog sa primljenom XPC message-om. Međutim, ona nije deo public API-ja, kao ni `xpc_connection_get_audit_token`.
- **Nepostojanje šire ispravke**: Ostaje nejasno zašto Apple nije implementirao sveobuhvatniju ispravku, kao što je odbacivanje messages koje se ne podudaraju sa sačuvanim audit token-om connection-a. Moguće je da su legitimne promene audit token-a u određenim scenarijima (npr. korišćenje `setuid`-a) bile faktor.
- **Trenutni status**: Problem i dalje postoji u iOS 17 i macOS 14, što predstavlja izazov za one koji pokušavaju da ga identifikuju i razumeju.<sup>[[1]](#references)</sup>

## Praktično pronalaženje ranjivih code paths (2024–2025)

Prilikom audit-ovanja XPC services-a za ovu klasu bug-ova, usmerite pažnju na authorization koji se izvršava izvan message event handler-a ili konkurentno sa obradom reply-a.

Saveti za static triage:
- Tražite pozive ka `xpc_connection_get_audit_token` do kojih se može doći iz blocks queued preko `dispatch_async`/`dispatch_after` ili drugih worker queues koji se izvršavaju izvan message handler-a.
- Tražite authorization helpers koji kombinuju state po connection-u i state po message-i (npr. dobavljanje PID-a preko `xpc_connection_get_pid`, a audit token-a preko `xpc_connection_get_audit_token`).
- U NSXPC code-u proverite da li se checks izvršavaju u `-listener:shouldAcceptNewConnection:` ili, za checks po message-i, da li implementation koristi audit token po message-i (npr. dictionary message-a preko `xpc_dictionary_get_audit_token` u lower-level code-u).

Saveti za dynamic triage:
- Hook-ujte `xpc_connection_get_audit_token` i označite invocations čiji user stack ne uključuje event-delivery path (npr. `_xpc_connection_mach_event`). Primer Frida hook-a:
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
- Na macOS-u, instrumentacija zaštićenih/Apple binaries može zahtevati da SIP bude onemogućen ili development environment; preferirajte testiranje sopstvenih buildova ili userland services.
- Za reply-forwarding races (Variant 2), pratite istovremeno parsiranje reply packets tako što ćete fuzzing-om menjati tajming poziva `xpc_connection_send_message_with_reply` u odnosu na normal requests i proveravati da li se na effective audit token korišćen tokom authorization može uticati.

## Exploitation primitives koje će vam verovatno biti potrebne

- Multi-sender setup (Variant 1): kreirajte connections ka A i B; duplicirajte send right klijentskog porta A i koristite ga kao klijentski port za B, tako da se B-ovi replies isporučuju A-u.
```c
// Duplicate a SEND right you already hold
mach_port_t dup;
mach_port_insert_right(mach_task_self(), a_client, a_client, MACH_MSG_TYPE_MAKE_SEND);
dup = a_client; // use `dup` when crafting B’s connect packet instead of a fresh client port
```
- Reply hijack (Variant 2): presretanje send-once prava iz zahteva na čekanju procesa A (reply port), zatim slanje konstruisane poruke procesu B koristeći taj reply port, tako da B-ov odgovor stigne procesu A dok se vaš zahtev sa privilegijama obrađuje.

Ovo zahteva konstruisanje mach poruka niskog nivoa za XPC bootstrap i formate poruka; pogledajte stranice sa uvodom u mach/XPC u ovom odeljku za tačne rasporede paketa i flagove.

## Korisni alati

- XPC sniffing/dynamic inspection: gxpc (open-source XPC sniffer) može pomoći pri nabrajanju konekcija i posmatranju saobraćaja radi validacije podešavanja sa više pošiljalaca i vremenskog usklađivanja. Primer: `gxpc -p <PID> --whitelist <service-name>`.
- Classic dyld interposing za libxpc: izvršite interpose nad `xpc_connection_send_message*` i `xpc_connection_get_audit_token` da biste beležili call sites i stackove tokom black-box testiranja.



## Reference

- [1] [Sector 7 – Don’t Talk All at Once! Elevating Privileges on macOS by Audit Token Spoofing](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [2] [Apple – About the security content of macOS Ventura 13.4 (CVE‑2023‑32405)](https://support.apple.com/en-us/106333)


{{#include ../../../../../../banners/hacktricks-training.md}}
