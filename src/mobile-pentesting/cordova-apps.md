# Cordova Apps

{{#include ../banners/hacktricks-training.md}}

The cloning workflow below is based on this [Cordova application recreation write-up](https://infosecwriteups.com/recreating-cordova-mobile-apps-to-bypass-security-implementations-8845ff7bdc58).<sup>[[4]](#references)</sup>

Apache Cordova builds **hybrid applications** with JavaScript, HTML, and CSS rendered in a WebView. Its web assets remain recoverable from an APK or IPA unless the project adds obfuscation or other protection. React Native also normally ships recoverable JavaScript or bytecode artifacts, so its JavaScript VM should not be treated as source-code protection.

### Cloning a Cordova Application

Before cloning a Cordova application, install Node.js and the platform prerequisites, such as the Android SDK, JDK, and Gradle. Consult the Cordova CLI documentation for the versions required by the selected Cordova platform.<sup>[[5]](#references)</sup>

Consider an example application named `Bank.apk` with the package name `com.android.bank`. To access the source code, unzip `bank.apk` and navigate to the `bank/assets/www` folder. This folder contains the complete source code of the application, including HTML and JS files. The application's configuration can be found in `bank/res/xml/config.xml`.

To clone the application, follow these steps:

```bash
npm install -g cordova@latest
cordova create bank-new com.android.bank Bank
cd bank-new
```

Copy the contents of `bank/assets/www` to `bank-new/www`, excluding `cordova_plugins.js`, `cordova.js`, `cordova-js-src/`, and the `plugins/` directory.

Specify the platform (Android or iOS) when creating a new Cordova project. For an Android app, add the Android platform. Cordova platform versions and Android API levels are distinct; consult the Cordova Android documentation for supported combinations.<sup>[[6]](#references)</sup>

To determine the appropriate Cordova Android platform version, check the `PLATFORM_VERSION_BUILD_LABEL` in the original application's `cordova.js` file.

After setting up the platform, install the required plugins. The original application's `bank/assets/www/cordova_plugins.js` file lists all the plugins and their versions. Install each plugin individually as shown below:

```bash
cd bank-new
cordova plugin add cordova-plugin-dialogs@2.0.1
```

If a plugin is not available on npm, it can be sourced from GitHub:

```bash
cd bank-new
cordova plugin add https://github.com/moderna/cordova-plugin-cache.git
```

Ensure all prerequisites are met before compiling:

```bash
cd bank-new
cordova requirements
```

To build the APK, use the following command:

```bash
cd bank-new
cordova build android -- --packageType=apk
```

This command generates an APK with the debug option enabled, facilitating debugging via Google Chrome. It's crucial to sign the APK before installation, especially if the application includes code tampering detection mechanisms.

### Automation Tool

For those seeking to automate the cloning process, **[MobSecco](https://github.com/Anof-cyber/MobSecco)** is a recommended tool. It streamlines the cloning of Android applications, simplifying the steps outlined above.

---

## Security Risks & Recent Vulnerabilities (2023-2025)

Cordova’s plugin-based architecture means that **most of the attack surface sits inside third-party plugins and the WebView bridge**. The following issues have been actively exploited or publicly disclosed in the last few years:

* **Malicious NPM Packages.** In July 2024 the package `cordova-plugin-acuant` was removed from the NPM registry after it was discovered dropping malicious code during installation (OSV-ID MAL-2024-7845). Any developer machine that executed `npm install cordova-plugin-acuant` should be considered compromised. Audit `package.json`/`package-lock.json` for unexpected Cordova plugins and pin trusted versions. [OSV advisory](https://osv.dev/vulnerability/MAL-2024-7845)<sup>[[2]](#references)</sup>  
* **Unvalidated Deeplinks → XSS/RCE.** `CleverTap Cordova Plugin ≤ 2.6.2` (CVE-2023-2507) fails to sanitise deeplink input, allowing an attacker to inject arbitrary JavaScript that executes in the main WebView context when a crafted link is opened. Update to ≥ 2.6.3 or strip untrusted URI parameters at runtime. [CVE-2023-2507](https://github.com/advisories/GHSA-x2ph-qqwm-9cc6)<sup>[[3]](#references)</sup>  
* **Out-of-Date Platform Code.** `cordova-android` ≤ 12 ships with targetSdk 33 or lower. Beginning May 2024 Google Play requires API 34, and several WebView hardening features (e.g. auto-generated `exported="false"` for components) are only present in API 34+. Upgrade to `cordova-android@13.0.0` or later.<sup>[[1]](#references)</sup> 

### Quick checks during a pentest

1. **Look for `android:debuggable="true"`** in the decompiled `AndroidManifest.xml`. Debuggable builds expose the WebView over `chrome://inspect` allowing full JS injection.
2. Review `config.xml` for overly permissive `<access origin="*">` tags or missing CSP meta-tags in `www/index.html`.
3. Grep `www/` for `eval(`, `new Function(` or dynamically-constructed HTML that could turn CSP bypasses into XSS.
4. Identify embedded plugins in `plugins/` and run `npm audit --production` or `osv-scanner --lockfile` to find known CVEs.

---

## Dynamic Analysis Tips

### Remote WebView Debugging

If the application has been compiled in **debug** mode (or explicitly calls `WebView.setWebContentsDebuggingEnabled(true)`), you can attach Chrome DevTools:

```bash
adb forward tcp:9222 localabstract:chrome_devtools_remote
google-chrome --new-window "chrome://inspect/#devices"
```

This gives you a live JavaScript console, DOM inspector, and the ability to modify JavaScript functions at runtime.<sup>[[7]](#references)</sup>

### Hooking the JS ⇄ Native bridge with Frida

The Java-side entry point of most plugins is `org.apache.cordova.CordovaPlugin.execute(...)`. Hooking this method lets you monitor or tamper with calls made from JavaScript:

```javascript
// frida -U -f com.vulnerable.bank -l hook.js --no-pause
Java.perform(function () {
  var CordovaPlugin = Java.use('org.apache.cordova.CordovaPlugin');
  CordovaPlugin.execute.overload('java.lang.String','org.json.JSONArray','org.apache.cordova.CallbackContext').implementation = function(act, args, ctx) {
    console.log('[Cordova] ' + act + ' => ' + args);
    // Tamper the first argument of a sensitive action
    if (act === 'encrypt') {
      args.put(0, '1234');
    }
    return this.execute(act, args, ctx);
  };
});
```

---

## Hardening recommendations

* **Update the platform:** use a currently supported `cordova-android` release and meet the current Android target-SDK requirement. For historical orientation, `cordova-android@13` targeted API 34 in May 2024; the compatibility table now also records newer platform/API combinations, so do not treat version 13 as the latest.<sup>[[1]](#references)</sup><sup>[[6]](#references)</sup>
* **Remove debug artifacts:** Ensure `android:debuggable="false"` and avoid calling `setWebContentsDebuggingEnabled` in release builds.
* **Enforce a strict CSP & AllowList:** Add a `<meta http-equiv="Content-Security-Policy" ...>` tag in every HTML file and restrict `<access>` origins in `config.xml`.  
  Example minimal CSP that blocks inline scripts:
  ```html
  <meta http-equiv="Content-Security-Policy" content="default-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'">
  ```
* **Disable clear-text traffic:** In `AndroidManifest.xml` set `android:usesCleartextTraffic="false"` and/or provide a [network-security-config] that enforces TLS.
* **Plugin hygiene:**  
  * Pin plugin versions with `npm ci` and commit the generated `package-lock.json`.  
  * Periodically run `npm audit`, `osv-scanner` or `cordova-check-plugins`.
* **Obfuscation:** Minify JavaScript with Terser/UglifyJS and remove source maps from production builds to slow down casual reversing.

---

## References

- [1] [Cordova Android 13.0.0 Released - Apache Cordova](https://cordova.apache.org/announcements/2024/05/23/cordova-android-13.0.0.html)
- [2] [Malicious code in cordova-plugin-acuant (npm) - OSV-ID MAL-2024-7845](https://osv.dev/vulnerability/MAL-2024-7845)
- [3] [CleverTap Cordova Plugin vulnerable to Cross-site Scripting - CVE-2023-2507](https://github.com/advisories/GHSA-x2ph-qqwm-9cc6)
- [4] [Recreating Cordova Mobile Apps to Bypass Security Implementations](https://infosecwriteups.com/recreating-cordova-mobile-apps-to-bypass-security-implementations-8845ff7bdc58)
- [5] [Apache Cordova – The Command-Line Interface](https://cordova.apache.org/docs/en/latest/guide/cli/)
- [6] [Apache Cordova – Android Platform Guide](https://cordova.apache.org/docs/en/latest/guide/platforms/android/)
- [7] [Android Developers – `WebView.setWebContentsDebuggingEnabled`](https://developer.android.com/reference/android/webkit/WebView#setWebContentsDebuggingEnabled%28boolean%29)

{{#include ../banners/hacktricks-training.md}}
