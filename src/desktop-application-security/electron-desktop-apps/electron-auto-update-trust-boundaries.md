# Mipaka ya Uaminifu ya Electron Auto-Update

{{#include ../../banners/hacktricks-training.md}}

## attack surface ya Electron auto-update

Ichukulie updater kama mpaka wa remote-code-execution: hupakua maudhui yanayoweza kutekelezeka, huamua kama maudhui hayo ni mapya zaidi na yanaaminika, huyahifadhi kwa muda kwenye kifaa, kisha huyakabidhi kwa installer. Kagua grafu nzima ya uaminifu—release index, metadata ya kila toleo, artifact, detached signatures, embedded verification key, cache, njia ya muda na installer—si tu kama `.app` ya mwisho imesainiwa.<sup>[[1]](#references)[[2]](#references)</sup>

### Majaribio yenye thamani kubwa

- **Rollback/replay:** rudia manifest iliyokuwa halali na artifact yake ambayo bado imesainiwa. Signature huthibitisha ingizo lake, lakini haihakikishi kwamba ni la sasa; client lazima ikatae matoleo yaliyo chini ya kiwango cha chini cha kudumu, isipokuwa sera ya urejeshaji iliyothibitishwa kwa njia salama iidhinishe wazi rollback hiyo.<sup>[[2]](#references)</sup>
- **Metadata/artifact substitution:** badilisha version, URL, hash inayotarajiwa, artifact na detached signature kila kimoja kivyake. Pia jaribu kuchanganya artifact/signature pair halali ya release moja na metadata ya release nyingine. Ikiwa release metadata haijasainiwa, TLS au executable ya mwisho iliyosainiwa haiwezi kuzuia origin/CDN iliyoathiriwa kubadilisha mantiki ya uteuzi.<sup>[[1]](#references)[[2]](#references)</sup>
- **Signed channel confusion:** toa alpha, beta, development au debug build iliyosainiwa kihalali kupitia production feed. Kutumia tena key na sera ileile katika mazingira tofauti huruhusu artifact kupita ukaguzi unaotegemea signer pekee; utambulisho/channel ya production lazima iwe sehemu ya sera iliyothibitishwa au itumie trust root tofauti.<sup>[[2]](#references)</sup>
- **Temporary-file TOCTOU:** tambua kama uthibitishaji hufungua pathname na usakinishaji baadaye hufungua tena pathname hiyo. Ikiwa mshambuliaji wa ndani anaweza kubadilisha jina, kubadilisha au kuelekeza upya kitu kilichohifadhiwa kwa muda kati ya hatua hizo, installer inaweza kutumia bytes ambazo hazikuthibitishwa kamwe. Saraka ya kuhifadhi kwa muda yenye ruhusa `0700` hupunguza ufikiaji, lakini haifanyi shughuli hizo mbili kuwa za atomiki.<sup>[[2]](#references)</sup>

Triage ya static na runtime inaweza kusaidia kupata mipaka hii kwa haraka.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
npx asar extract /path/to/app.asar /tmp/app-src
rg -n 'autoUpdater|electron-updater|setFeedURL|latest\.yml|allowInsecureTLS|downgrade' /tmp/app-src
rg -n 'sha(256|512)|ed25519|verify|signature|version|mkdtemp|chmod|rename' /tmp/app-src
sudo fs_usage -w -f filesystem "$PID" | rg -i 'update|latest|\.ya?ml|\.zip|\.dmg|tmp'
```

Wakati wa jaribio lililoidhinishwa, kamata ukaguzi wa sasisho, hifadhi kila jibu, na ubadilishe sehemu moja kwa wakati. Kisha kagua umiliki/mode ya staging directory na fuatilia kufunguliwa kwa faili kuanzia upakuaji hadi usakinishaji. Kwenye macOS, endelea na [majaribio ya mipaka ya uaminifu ya kisakinishi](../../macos-hardening/macos-security-and-privilege-escalation/macos-files-folders-and-binaries/macos-installers-abuse.md) ikiwa mtiririko unafikia helper yenye upendeleo, na kagua [udhaifu wa code-signing](../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing-weaknesses-and-sandbox-escapes.md) badala ya kuchukulia “signed” kuwa ukaguzi kamili wa utambulisho.<sup>[[2]](#references)</sup>

### Ufungamanishaji na sera vinavyotarajiwa

Muundo unaoweza kutetewa huthibitisha metadata ya uteuzi na baiti za artifact. Muundo rejea wa SafeUpdater unaonyesha ufunguo wa umma wa Ed25519 uliopachikwa, manifests na artifacts zilizotiwa saini, ujumbe uliosainiwa unaotokana na `SHA-256(file)` pamoja na toleo, na digest ya artifact ya SHA-512 iliyohifadhiwa kwenye metadata iliyosainiwa; umeelezwa wazi kuwa ni rejea ya utafiti, si kifurushi kilicho tayari kwa matumizi ya uzalishaji.<sup>[[1]](#references)[[2]](#references)</sup>

Thibitisha kuwa lengwa pia lina sifa hizi.<sup>[[1]](#references)[[2]](#references)</sup>

- hutumia uwakilishi uliosainiwa usio na utata unaofungamanisha digest ya artifact na toleo lake la kikanoni pamoja na mazingira ya toleo;
- huzima kushusha toleo kwa chaguomsingi na kutekeleza toleo la chini kabisa linalokubaliwa kwa ajili ya kurejesha toleo la awali kulikoidhinishwa;
- hutenganisha uzalishaji na mazingira yasiyo ya uzalishaji kwa kutumia keys/channels tofauti au data ya sera ya toleo iliyothibitishwa; na
- husakinisha faili iliyo wazi ambayo tayari imethibitishwa (au handle/object isiyoweza kubadilika iliyo sawa) badala ya kutafuta tena njia ileile ya faili.

## References

- [1] [Utekelezaji rejea wa ElectronSafeUpdater wa Doyensec](https://github.com/doyensec/ElectronSafeUpdater)
- [2] [Electron SafeUpdater: Kubuni Utaratibu Salama wa Kusasisha Electron Kiotomatiki](https://blog.doyensec.com/2026/02/16/electron-safe-updater.html)
{{#include ../../banners/hacktricks-training.md}}
