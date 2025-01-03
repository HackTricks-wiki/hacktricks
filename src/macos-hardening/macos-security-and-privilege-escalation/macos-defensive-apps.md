# macOS Defensive Apps

{{#include ../../banners/hacktricks-training.md}}

## Firewalls

- [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html): 各プロセスによって行われるすべての接続を監視します。モード（接続を静かに許可、接続を静かに拒否し警告）に応じて、新しい接続が確立されるたびに**警告を表示**します。また、すべての情報を確認するための非常に良いGUIがあります。
- [**LuLu**](https://objective-see.org/products/lulu.html): Objective-Seeのファイアウォール。これは、疑わしい接続に対して警告を出す基本的なファイアウォールです（GUIはありますが、Little Snitchのものほど豪華ではありません）。

## Persistence detection

- [**KnockKnock**](https://objective-see.org/products/knockknock.html): **マルウェアが持続している**可能性のあるいくつかの場所を検索するObjective-Seeのアプリケーションです（これは一回限りのツールで、監視サービスではありません）。
- [**BlockBlock**](https://objective-see.org/products/blockblock.html): KnockKnockのように、持続性を生成するプロセスを監視します。

## Keyloggers detection

- [**ReiKey**](https://objective-see.org/products/reikey.html): キーボードの「イベントタップ」をインストールする**キーロガー**を見つけるためのObjective-Seeのアプリケーションです。&#x20;

{{#include ../../banners/hacktricks-training.md}}
