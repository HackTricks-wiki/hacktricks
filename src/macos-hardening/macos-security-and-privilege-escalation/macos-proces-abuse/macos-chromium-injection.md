# macOS Chromium Injection

{{#include ../../../banners/hacktricks-training.md}}

## 基本情報

Chromiumベースのブラウザ、例えばGoogle Chrome、Microsoft Edge、Braveなどがあります。これらのブラウザはChromiumオープンソースプロジェクトに基づいて構築されているため、共通の基盤を共有し、したがって、類似の機能や開発者オプションを持っています。

#### `--load-extension` フラグ

`--load-extension` フラグは、コマンドラインまたはスクリプトからChromiumベースのブラウザを起動する際に使用されます。このフラグは、**ブラウザの起動時に1つ以上の拡張機能を自動的に読み込む**ことを可能にします。

#### `--use-fake-ui-for-media-stream` フラグ

`--use-fake-ui-for-media-stream` フラグは、Chromiumベースのブラウザを起動するために使用できる別のコマンドラインオプションです。このフラグは、**カメラやマイクからのメディアストリームへのアクセス許可を求める通常のユーザープロンプトをバイパスする**ように設計されています。このフラグが使用されると、ブラウザはカメラやマイクへのアクセスを要求する任意のウェブサイトやアプリケーションに自動的に許可を与えます。

### ツール

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop)
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO)

### 例
```bash
# Intercept traffic
voodoo intercept -b chrome
```
ツールリンクでさらに例を見つけてください

## 参考文献

- [https://twitter.com/RonMasas/status/1758106347222995007](https://twitter.com/RonMasas/status/1758106347222995007)

{{#include ../../../banners/hacktricks-training.md}}
