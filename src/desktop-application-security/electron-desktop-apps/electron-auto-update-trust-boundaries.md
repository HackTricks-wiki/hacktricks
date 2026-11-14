# Electron-outomatiese-opdatering-vertrouensgrense

{{#include ../../banners/hacktricks-training.md}}

## Aanvalsvlak vir Electron-outomatiese opdaterings

Behandel ’n updater as ’n remote-code-execution-grens: dit haal uitvoerbare inhoud op, bepaal of dié inhoud nuwer en vertroud is, plaas dit plaaslik in ’n staging-area en oorhandig dit aan ’n installer. Gaan die volledige vertrouensgrafiek na—release-indeks, metadata per weergawe, artifact, losstaande handtekeninge, ingebedde verifikasiesleutel, cache, tydelike pad en installer—nie net of die finale `.app` onderteken is nie.<sup>[[1]](#references)[[2]](#references)</sup>

### Toetse met hoë waarde

- **Rollback/replay:** speel ’n voorheen geldige manifest en sy steeds ondertekende artifact weer af. ’n Handtekening bevestig die egtheid van sy invoer, maar bied geen waarborg van varsheid nie; die client moet weergawes onder ’n volgehoue monotone ondergrens verwerp, tensy ’n geverifieerde herstelbeleid die rollback uitdruklik magtig.<sup>[[2]](#references)</sup>
- **Metadata-/artifact-vervanging:** verander die weergawe, URL, verwagte hash, artifact en losstaande handtekening afsonderlik. Probeer ook ’n geldige artifact-/handtekeningpaar van een release met metadata vir ’n ander meng. As die release-metadata nie onderteken is nie, keer TLS of ’n ondertekende finale uitvoerbare lêer nie dat ’n gekompromitteerde oorsprong/CDN die seleksielogika verander nie.<sup>[[1]](#references)[[2]](#references)</sup>
- **Verwarring oor ondertekende kanale:** bedien ’n wettig ondertekende alpha-, beta-, development- of debug-build via die production-feed. Deur dieselfde sleutel en beleid oor omgewings heen te hergebruik, kan die artifact ’n kontrole wat slegs die ondertekenaar nagaan, slaag; production-identiteit/kanaal moet deel wees van die geverifieerde beleid, of ’n afsonderlike trust root moet gebruik word.<sup>[[2]](#references)</sup>
- **TOCTOU met tydelike lêers:** bepaal of verifikasie ’n padnaam oopmaak en die installer later daardie padnaam weer oopmaak. As ’n plaaslike aanvaller die objek in staging tussen dié bewerkings kan hernoem, vervang of herlei, kan die installer grepe verwerk wat nooit geverifieer is nie. ’n staging-gids met modus `0700` beperk toegang, maar maak nie die twee bewerkings atomies nie.<sup>[[2]](#references)</sup>

Statiese en runtime-triage kan hierdie grense vinnig opspoor.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
npx asar extract /path/to/app.asar /tmp/app-src
rg -n 'autoUpdater|electron-updater|setFeedURL|latest\.yml|allowInsecureTLS|downgrade' /tmp/app-src
rg -n 'sha(256|512)|ed25519|verify|signature|version|mkdtemp|chmod|rename' /tmp/app-src
sudo fs_usage -w -f filesystem "$PID" | rg -i 'update|latest|\.ya?ml|\.zip|\.dmg|tmp'
```

Tydens ’n gemagtigde toets, onderskep die opdateringskontrole, argiveer elke antwoord en verander een veld op ’n slag. Inspekteer dan die eienaarskap en modus van die staging-gids, en spoor lêeropenings van aflaai tot installering na. Gaan op macOS voort met [installer trust-boundary testing](../../macos-hardening/macos-security-and-privilege-escalation/macos-files-folders-and-binaries/macos-installers-abuse.md) as die proses ’n bevoorregte helper bereik, en hersien [code-signing weaknesses](../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing-weaknesses-and-sandbox-escapes.md) eerder as om “signed” as ’n volledige identiteitskontrole te beskou.<sup>[[2]](#references)</sup>

### Verwagte binding en beleid

’n Verdedigbare ontwerp staaf beide seleksiemetadata en artefakgrepe. Die SafeUpdater-verwysingsontwerp demonstreer ’n ingebedde Ed25519-publieke sleutel, ondertekende manifeste en artefakte, ’n ondertekende boodskap wat afgelei is van `SHA-256(file)` plus die weergawe, en ’n SHA-512-artefakdigest wat in ondertekende metadata gestoor word; dit is uitdruklik ’n navorsingsverwysing, nie ’n produksiegereed pakket nie.<sup>[[1]](#references)[[2]](#references)</sup>

Verifieer dat die teiken ook die volgende eienskappe bied.<sup>[[1]](#references)[[2]](#references)</sup>

- ’n ondubbelsinnige, ondertekende voorstelling gebruik wat die artefakdigest aan die kanonieke weergawe en vrystellingsomgewing bind;
- downgrade by verstek deaktiveer en ’n minimum aanvaarde weergawe vir gemagtigde terugrol afdwing;
- produksie van nie-produksie skei deur afsonderlike sleutels/kanale of geverifieerde vrystellingsbeleidsdata; en
- die reeds geverifieerde oop lêer (of ’n ekwivalente onveranderlike handvatsel/objek) installeer, in plaas daarvan om dieselfde pad weer op te los.

## References

- [1] [Doyensec ElectronSafeUpdater-verwysingsimplementering](https://github.com/doyensec/ElectronSafeUpdater)
- [2] [Electron SafeUpdater: Ontwerp van ’n veilige Electron-outomatiese opdateringsmeganisme](https://blog.doyensec.com/2026/02/16/electron-safe-updater.html)
{{#include ../../banners/hacktricks-training.md}}
