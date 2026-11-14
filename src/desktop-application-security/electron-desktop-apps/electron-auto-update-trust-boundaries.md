# Electron 自動更新の信頼境界

{{#include ../../banners/hacktricks-training.md}}

## Electron 自動更新の攻撃対象領域

updater は remote-code-execution の境界として扱います。実行可能なコンテンツを取得し、そのコンテンツがより新しく信頼できるかを判断し、ローカルにステージングして、installer に渡します。最終的な `.app` に署名されているかどうかだけでなく、release index、バージョンごとの metadata、artifact、detached signature、埋め込みの検証キー、cache、一時パス、installer を含む信頼グラフ全体を確認します。<sup>[[1]](#references)[[2]](#references)</sup>

### 重要度の高いテスト

- **rollback/replay:** 以前に有効だった manifest と、まだ署名が有効な artifact を再送します。署名は署名対象を認証しますが、鮮度は保証しません。認証済みの復旧ポリシーが明示的に rollback を許可しない限り、クライアントは永続的な単調増加の下限を下回るバージョンを拒否する必要があります。<sup>[[2]](#references)</sup>
- **metadata/artifact の置換:** バージョン、URL、期待される hash、artifact、detached signature をそれぞれ個別に改変します。また、あるリリースの有効な artifact/signature の組み合わせと、別のリリースの metadata を混在させてみます。release metadata に署名がなければ、TLS や最終的な実行ファイルへの署名があっても、侵害された origin/CDN による選択ロジックの変更は防げません。<sup>[[1]](#references)[[2]](#references)</sup>
- **署名済み channel の混同:** 正規に署名された alpha、beta、development、または debug build を production feed 経由で配信します。環境間で同じキーとポリシーを再利用すると、signer のみを確認するチェックを artifact が通過してしまいます。production の識別情報/channel は認証済みポリシーに含めるか、別の信頼ルートを使用する必要があります。<sup>[[2]](#references)</sup>
- **一時ファイルの TOCTOU:** 検証時に pathname を開き、インストール時にその pathname を再度開くかどうかを確認します。ローカルの攻撃者がこの間にステージングされたオブジェクトを rename、置換、またはリダイレクトできる場合、installer は検証されていないデータを処理する可能性があります。mode-`0700` のステージングディレクトリはアクセスを制限しますが、2つの操作を atomic にするものではありません。<sup>[[2]](#references)</sup>

Static と runtime の triage で、これらの境界をすばやく特定できます。<sup>[[1]](#references)[[2]](#references)</sup>

```bash
npx asar extract /path/to/app.asar /tmp/app-src
rg -n 'autoUpdater|electron-updater|setFeedURL|latest\.yml|allowInsecureTLS|downgrade' /tmp/app-src
rg -n 'sha(256|512)|ed25519|verify|signature|version|mkdtemp|chmod|rename' /tmp/app-src
sudo fs_usage -w -f filesystem "$PID" | rg -i 'update|latest|\.ya?ml|\.zip|\.dmg|tmp'
```

許可を得たテストでは、更新チェックを傍受し、すべてのレスポンスを保存してから、一度に1つのフィールドだけを変更します。ステージングディレクトリの所有者と権限を確認し、ダウンロードからインストールまでのファイルオープンを追跡します。macOSでは、フローが特権ヘルパーに到達する場合は[インストーラーの信頼境界テスト](../../macos-hardening/macos-security-and-privilege-escalation/macos-files-folders-and-binaries/macos-installers-abuse.md)を続け、「署名済み」を完全なID確認として扱うのではなく、[コード署名の弱点](../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing-weaknesses-and-sandbox-escapes.md)を確認してください。<sup>[[2]](#references)</sup>

### 想定されるバインディングとポリシー

堅牢な設計では、選択メタデータとアーティファクトのバイト列の両方を認証します。SafeUpdaterのリファレンス設計では、埋め込みのEd25519公開鍵、署名済みマニフェストとアーティファクト、`SHA-256(file)`とバージョンから導出される署名済みメッセージ、署名済みメタデータに保存されたSHA-512アーティファクトダイジェストを示しています。ただし、これは本番環境向けの完成済みパッケージではなく、研究用リファレンスであることが明記されています。<sup>[[1]](#references)[[2]](#references)</sup>

対象がさらに以下の特性を備えていることを確認してください。<sup>[[1]](#references)[[2]](#references)</sup>

- アーティファクトのダイジェストを正規化されたバージョンおよびリリース環境に紐づける、曖昧さのない署名表現を使用する。
- デフォルトでダウングレードを無効にし、許可されたロールバックに対して最低受け入れバージョンを適用する。
- 別個のキー／チャネル、または認証済みのリリースポリシーデータを使って、本番環境と非本番環境を分離する。
- 同じパス名を再解決するのではなく、検証済みのオープン済みファイル（または同等の不変なハンドル／オブジェクト）をインストールする。

## References

- [1] [Doyensec ElectronSafeUpdaterのリファレンス実装](https://github.com/doyensec/ElectronSafeUpdater)
- [2] [Electron SafeUpdater：安全なElectron自動更新メカニズムの設計](https://blog.doyensec.com/2026/02/16/electron-safe-updater.html)
{{#include ../../banners/hacktricks-training.md}}
