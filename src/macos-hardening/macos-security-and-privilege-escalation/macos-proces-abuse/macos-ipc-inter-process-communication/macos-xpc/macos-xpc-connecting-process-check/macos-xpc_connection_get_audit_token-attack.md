# macOS xpc_connection_get_audit_token Napad

{{#include ../../../../../../banners/hacktricks-training.md}}

**Za dodatne informacije proverite originalni post:** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/). Ovo je sažetak:

## Mach Messages — Osnovne informacije

Ako ne znate šta su Mach Messages, počnite sa proverom ove stranice:


{{#ref}}
../../
{{#endref}}

Za sada zapamtite ([definicija odavde](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):\
Mach messages se šalju preko _mach port_, koji je **kanal komunikacije sa jednim prijemnikom i više pošiljalaca** ugrađen u mach kernel. **Više procesa može slati poruke** na mach port, ali u bilo kom trenutku **samo jedan proces može čitati iz njega**. Kao i file descriptors i sockets, mach ports alocira i upravlja kernel i procesi vide samo ceo broj koji mogu koristiti da naznače kernelu koji od njihovih mach portova žele da koriste.

## XPC Connection

Ako ne znate kako se uspostavlja XPC veza, proverite:


{{#ref}}
../
{{#endref}}

## Sažetak ranjivosti

Važno je znati da je **XPC apstrakcija jedno-na-jednu vezu**, ali je zasnovana na tehnologiji koja **može imati više pošiljalaca, tako da:**

- Mach ports su sa jednim prijemnikom, **više pošiljalaca**.
- Audit token XPC veze je audit token **kopiran iz najnovije primljene poruke**.
- Dobijanje **audit token** XPC veze je kritično za mnoge **bezbednosne provere**.

Iako prethodna situacija zvuči problematično, postoje scenariji u kojima ovo neće izazvati probleme ([odavde](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):

- Audit tokeni se često koriste za autorizacionu proveru da bi se odlučilo da li prihvatiti vezu. Pošto se to dešava koristeći poruku na service port-u, **veza još nije uspostavljena**. Više poruka na tom portu biće tretirano kao dodatni zahtevi za uspostavljanje veze. Dakle, bilo koje **provere pre prihvatanja veze nisu ranjive** (ovo takođe znači da unutar `-listener:shouldAcceptNewConnection:` audit token je bezbedan). Stoga tražimo **XPC veze koje verifikuju specifične akcije**.
- XPC event handler-i se obrađuju sinhrono. To znači da event handler za jednu poruku mora biti završen pre nego što se pozove za sledeću poruku, čak i na concurrent dispatch queue-ovima. Dakle, unutar **XPC event handler-a audit token ne može biti prepisan** od strane drugih normalnih (non-reply!) poruka.

Dva različita načina na koja bi ovo moglo biti eksploatisano:

1. Variant1:
- **Exploit** se **povezuje** na servis **A** i servis **B**
- Servis **B** može pozvati **privilegovanu funkcionalnost** u servisu A koju korisnik ne može
- Servis **A** poziva **`xpc_connection_get_audit_token`** dok _**nije**_ unutar **event handler-a** za konekciju, već u **`dispatch_async`**.
- Dakle, **druga** poruka može **prepisati Audit Token** zato što se šalje asinhrono van event handler-a.
- Exploit prosleđuje **svc B pravo SEND na svc A**.
- Tako će svc **B** zapravo **slati** **poruke** ka servisu **A**.
- **Exploit** pokušava da **pozove** **privilegovanu akciju.** U RC svc **A** **proverava** autorizaciju ove **akcije** dok je **svc B prepisao Audit token** (dajući exploit-u pristup da pozove privilegovanu akciju).
2. Variant 2:
- Servis **B** može pozvati **privilegovanu funkcionalnost** u servisu A koju korisnik ne može
- Exploit se povezuje sa **service A** koji **šalje** exploitu poruku koja očekuje odgovor na specifičan **reply** **port**.
- Exploit šalje **servisu B** poruku prosleđujući **taj reply port**.
- Kada servis **B** odgovori, on će **poslati poruku servisu A**, **dok** exploit šalje drugu **poruku servisu A** pokušavajući da **dođe do privilegovane funkcionalnosti** i očekujući da će odgovor od servisa B prepisati Audit token u savršenom trenutku (Race Condition).

## Variant 1: calling xpc_connection_get_audit_token outside of an event handler <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Scenario:

- Dva mach servisa **`A`** i **`B`** na koja se možemo oba povezati (na osnovu sandbox profila i autorizacionih provera pre prihvatanja konekcije).
- _**A**_ mora imati **autorizacionu proveru** za specifičnu akciju koju **`B`** može proslediti (ali naša aplikacija ne može).
- Na primer, ako B ima neka **entitlements** ili radi kao **root**, mogao bi tražiti od A da izvrši privilegovanu akciju.
- Za ovu autorizacionu proveru, **`A`** dobija audit token asinhrono, na primer pozivajući `xpc_connection_get_audit_token` iz **`dispatch_async`**.

> [!CAUTION]
> U ovom slučaju napadač može pokrenuti **Race Condition** praveći **exploit** koji **traži od A da izvrši akciju** više puta dok tera **B da šalje poruke ka `A`**. Kada je RC **uspešan**, **audit token** od **B** će biti kopiran u memoriju **dok** se zahtev našeg **exploit-a** obrađuje od strane A, dajući mu **pristup privilegovanoj akciji koju samo B može zatražiti**.

Ovo se dogodilo sa **`A`** kao `smd` i **`B`** kao `diagnosticd`. Funkcija [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) iz smb se može koristiti za instaliranje novog privilegovanog helper tool-a (kao **root**). Ako proces koji radi kao root kontaktira **smd**, neće se izvoditi druge provere.

Dakle, servis **B** je **`diagnosticd`** zato što radi kao **root** i može se koristiti za **monitorovanje** procesa, tako da jednom kada monitoring počne, on će **slati više poruka u sekundi.**

Da izvedete napad:

1. Inicijalizujte **konekciju** ka servisu nazvanom `smd` koristeći standardni XPC protokol.
2. Formirajte sekundarnu **konekciju** ka `diagnosticd`. Suprotno uobičajenoj proceduri, umesto kreiranja i slanja dva nova mach porta, client port send right se zamenjuje duplikatom **send right** povezane sa `smd` konekcijom.
3. Kao rezultat, XPC poruke mogu biti usmeravane ka `diagnosticd`, ali odgovori od `diagnosticd` bivaju preusmereni ka `smd`. Za `smd`, izgleda kao da poruke i od korisnika i od `diagnosticd` potiču iz iste konekcije.

![Prikaz procesa exploita](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. Sledeći korak uključuje nalaženje `diagnosticd` da počne monitoring izabranog procesa (potencijalno korisnikovog sopstvenog). Paralelno, šalje se poplava rutinskih 1004 poruka ka `smd`. Cilj je instaliranje tool-a sa povišenim privilegijama.
5. Ova akcija pokreće race condition unutar funkcije `handle_bless`. Vreme je kritično: poziv `xpc_connection_get_pid` mora vratiti PID korisničkog procesa (jer se privilegovani alat nalazi u korisničkom app bundle-u). Međutim, poziv `xpc_connection_get_audit_token`, konkretno unutar podrutine `connection_is_authorized`, mora referisati audit token koji pripada `diagnosticd`.

## Variant 2: reply forwarding

U XPC (Cross-Process Communication) okruženju, iako se event handler-i ne izvršavaju konkurentno, obrada reply poruka ima jedinstveno ponašanje. Konkretno, postoje dva različita načina slanja poruka koje očekuju odgovor:

1. **`xpc_connection_send_message_with_reply`**: Ovde se XPC poruka prima i obrađuje na određenoj queue.
2. **`xpc_connection_send_message_with_reply_sync`**: Suprotno tome, u ovom slučaju se XPC poruka prima i obrađuje na trenutnoj dispatch queue.

Ova distinkcija je ključna jer omogućava mogućnost da se **reply paketi parsiraju istovremeno dok se izvršava XPC event handler**. Inače, dok `_xpc_connection_set_creds` implementira locking da bi se zaštitilo od delimičnog prepisivanja audit token-a, on ne pruža zaštitu celom connection objektu. Posledično, to stvara ranjivost gde audit token može biti zamenjen u periodu između parsiranja paketa i izvršenja njegovog event handler-a.

Za eksploataciju ove ranjivosti, potreban je sledeći setup:

- Dva mach servisa, nazvana **`A`** i **`B`**, oba mogu uspostaviti konekciju.
- Servis **`A`** bi trebalo da uključi autorizacionu proveru za specifičnu akciju koju samo **`B`** može izvršiti (a korisnička aplikacija ne može).
- Servis **`A`** treba da pošalje poruku koja očekuje reply.
- Korisnik može poslati poruku **`B`** na koju će on odgovoriti.

Proces eksploatacije uključuje sledeće korake:

1. Sačekajte da servis **`A`** pošalje poruku koja očekuje odgovor.
2. Umesto da se odgovori direktno **`A`**, hijack-uje se reply port i koristi za slanje poruke servisu **`B`**.
3. Nakon toga, šalje se poruka koja uključuje zabranjenu akciju, očekujući da će biti obrađena istovremeno sa odgovorom od **`B`**.

Ispod je vizuelna reprezentacija opisanog scenarija napada:

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../images/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../images/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Problemi pri otkrivanju

- **Teškoće u lociranju instanci**: Pretraga za upotrebom `xpc_connection_get_audit_token` bila je izazovna, i statički i dinamički.
- **Metodologija**: Frida je korišćena za hook-ovanje `xpc_connection_get_audit_token` funkcije, filtrirajući pozive koji ne potiču iz event handler-a. Međutim, ova metoda je bila ograničena na hook-ovani proces i zahtevala je aktivno korišćenje.
- **Alati za analizu**: Alati kao IDA/Ghidra su korišćeni za ispitivanje dostupnih mach servisa, ali je proces bio dugotrajan, otežan pozivima koji uključuju dyld shared cache.
- **Ograničenja skriptovanja**: Pokušaji automatizacije analize za pozive `xpc_connection_get_audit_token` iz `dispatch_async` blokova su bili otežani komplikacijama u parsiranju blokova i interakcijama sa dyld shared cache-om.

## Ispravka <a href="#the-fix" id="the-fix"></a>

- **Prijavljeni problemi**: Podnet je izveštaj Apple-u koji detaljno opisuje opšte i specifične probleme pronađene u `smd`.
- **Apple-ov odgovor**: Apple je rešio problem u `smd` tako što je zamenio `xpc_connection_get_audit_token` sa `xpc_dictionary_get_audit_token`.
- **Priroda popravke**: Funkcija `xpc_dictionary_get_audit_token` se smatra sigurnom jer dobija audit token direktno iz mach message povezanog sa primljenom XPC porukom. Međutim, ona nije deo public API-ja, slično kao i `xpc_connection_get_audit_token`.
- **Odsustvo šire ispravke**: Nije jasno zašto Apple nije implementirao opsežnije rešenje, kao što je odbacivanje poruka koje nisu u skladu sa sačuvanim audit token-om konekcije. Mogućnost da audit token legitimno može da se promeni u određenim scenarijima (npr. upotreba `setuid`) može biti faktor.
- **Trenutni status**: Problem i dalje postoji na iOS 17 i macOS 14, što predstavlja izazov za one koji pokušavaju da ga identifikuju i razumeju.

## Pronalaženje ranjivih putanja koda u praksi (2024–2025)

Prilikom audita XPC servisa za ovu klasu baga, fokusirajte se na autorizacije izvršene van event handler-a poruke ili istovremeno sa obradom reply poruka.

Načini za statičku trižu:
- Pretražujte pozive `xpc_connection_get_audit_token` koji su dostupni iz blokova stavljanih preko `dispatch_async`/`dispatch_after` ili drugih worker queue-ova koji se izvršavaju izvan message handler-a.
- Tražite helper-e za autorizaciju koji mešaju stanje po konekciji i po poruci (npr. dobijanje PID pomoću `xpc_connection_get_pid` ali audit token iz `xpc_connection_get_audit_token`).
- U NSXPC kodu, proverite da li se provere rade u `-listener:shouldAcceptNewConnection:` ili, za provere po poruci, da implementacija koristi audit token po poruci (npr. dictionary poruke putem `xpc_dictionary_get_audit_token` u nižem nivou koda).

Dinamički saveti za trižu:
- Hook-ujte `xpc_connection_get_audit_token` i označite invokacije čiji korisnički stack ne uključuje path isporuke event-a (npr. `_xpc_connection_mach_event`). Primer Frida hook-a:
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
- Na macOS-u, instrumentovanje zaštićenih/Apple binarnih fajlova može zahtevati onemogućen SIP ili razvojno okruženje; preporučuje se testiranje sopstvenih build-ova ili userland servisa.
- Za reply-forwarding races (Variant 2), pratite istovremeno parsiranje reply paketa fuzzovanjem tajminga `xpc_connection_send_message_with_reply` naspram normalnih zahteva i proverite da li se može uticati na efektivni audit token koji se koristi tokom autorizacije.

## Eksploatacioni primitivи koje će vam verovatno biti potrebni

- Multi-sender setup (Variant 1): kreirajte konekcije ka A i B; duplirajte send right of A’s client port i koristite ga kao B’s client port tako da se B’s replies dostave A-ju.
```c
// Duplicate a SEND right you already hold
mach_port_t dup;
mach_port_insert_right(mach_task_self(), a_client, a_client, MACH_MSG_TYPE_MAKE_SEND);
dup = a_client; // use `dup` when crafting B’s connect packet instead of a fresh client port
```
- Reply hijack (Variant 2): uhvatite send-once right iz A-ovog pending request (reply port), zatim pošaljite crafted message ka B koristeći taj reply port tako da B-ov reply stigne na A dok se vaš privileged request parsira.

Ovo zahteva low-level mach message crafting za XPC bootstrap i message formats; pregledajte mach/XPC primer stranice u ovom odeljku za tačne packet layouts i flags.

## Korisni alati

- XPC sniffing/dynamic inspection: gxpc (open-source XPC sniffer) može pomoći da se enumerišu konekcije i posmatra saobraćaj radi validacije multi-sender setup-a i timing-a. Primer: `gxpc -p <PID> --whitelist <service-name>`.
- Classic dyld interposing for libxpc: interpose on `xpc_connection_send_message*` and `xpc_connection_get_audit_token` to log call sites and stacks during black-box testing.

## References

- Sector 7 – Don’t Talk All at Once! Elevating Privileges on macOS by Audit Token Spoofing: <https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/>
- Apple – About the security content of macOS Ventura 13.4 (CVE‑2023‑32405): <https://support.apple.com/en-us/106333>


{{#include ../../../../../../banners/hacktricks-training.md}}
