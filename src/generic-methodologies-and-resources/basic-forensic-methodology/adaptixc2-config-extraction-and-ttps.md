# AdaptixC2 設定抽出とTTPs

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2 はモジュラーでオープンソースの post-exploitation/C2 フレームワークで、Windows x86/x64 の beacons（EXE/DLL/service EXE/raw shellcode）と BOF をサポートします。 このページでは以下を記載します:
- RC4でパックされた構成がどのように埋め込まれているか、そして beacons からそれを抽出する方法
- HTTP/SMB/TCP リスナーのネットワーク／プロファイル指標
- 実際に観測された一般的な loader と persistence の TTPs、および関連する Windows 技術ページへのリンク

## Beacon プロファイルとフィールド

AdaptixC2 は主に 3 種類の beacon タイプをサポートします:
- BEACON_HTTP: web C2 で、servers/ports/SSL、method、URI、headers、user-agent、カスタムパラメータ名を設定可能
- BEACON_SMB: named-pipe の peer-to-peer C2（イントラネット）
- BEACON_TCP: 直接ソケット、任意でプロトコル開始を難読化するための先頭マーカーを付与

HTTP beacon の設定（復号後）で観測される典型的なプロファイルフィールド:
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (array of strings), ports (array of u32)
- http_method, uri, parameter, user_agent, http_headers (length‑prefixed strings)
- ans_pre_size (u32), ans_size (u32) – レスポンスサイズの解析に使用
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

Example default HTTP profile (from a beacon build):
```json
{
"agent_type": 3192652105,
"use_ssl": true,
"servers_count": 1,
"servers": ["172.16.196.1"],
"ports": [4443],
"http_method": "POST",
"uri": "/uri.php",
"parameter": "X-Beacon-Id",
"user_agent": "Mozilla/5.0 (Windows NT 6.2; rv:20.0) Gecko/20121202 Firefox/20.0",
"http_headers": "\r\n",
"ans_pre_size": 26,
"ans_size": 47,
"kill_date": 0,
"working_time": 0,
"sleep_delay": 2,
"jitter_delay": 0,
"listener_type": 0,
"download_chunk_size": 102400
}
```
観測された悪意のある HTTP プロファイル（実際の攻撃）：
```json
{
"agent_type": 3192652105,
"use_ssl": true,
"servers_count": 1,
"servers": ["tech-system[.]online"],
"ports": [443],
"http_method": "POST",
"uri": "/endpoint/api",
"parameter": "X-App-Id",
"user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.160 Safari/537.36",
"http_headers": "\r\n",
"ans_pre_size": 26,
"ans_size": 47,
"kill_date": 0,
"working_time": 0,
"sleep_delay": 4,
"jitter_delay": 0,
"listener_type": 0,
"download_chunk_size": 102400
}
```
## 暗号化された構成のパッキングとロードパス

ビルダーでオペレーターが Create をクリックすると、AdaptixC2 は暗号化されたプロファイルを beacon の末尾ブロブとして埋め込みます。フォーマットは次のとおりです:
- 4 バイト: configuration size (uint32, little‑endian)
- N バイト: RC4‑encrypted configuration data
- 16 バイト: RC4 key

beacon loader は末尾から 16 バイトの key をコピーし、N バイトのブロックをその場で RC4 で復号します:
```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```
実務上の影響:
- 構造全体はしばしばPEの .rdata セクション内に格納されている。
- 抽出は決定的：サイズを読み、そのサイズ分のciphertextを読み、その直後に置かれた16‑byte keyを読み取ってからRC4‑decryptする。

## 設定抽出ワークフロー（防御者向け）

beacon logicを模倣する抽出ツールを書け:
1) PE内のblobを特定する（一般的には.rdata）。実用的な方法としては、.rdataをスキャンして妥当と思われる[size|ciphertext|16‑byte key]のレイアウトを探し、RC4で試すこと。
2) 最初の4バイトを読み → size（uint32 LE）。
3) 次のN=sizeバイトを読み → ciphertext。
4) 最後の16バイトを読み → RC4 key。
5) ciphertextをRC4‑decryptする。その後、平文のprofileを以下のように解析する：
- u32/boolean スカラー（上記の通り）
- 長さ接頭辞付き文字列（u32長さの後にバイト列；末尾にNULが存在することがある）
- 配列：servers_countの後に、その数だけ[string, u32 port]のペアが続く

事前に抽出したblobで動作する、外部依存なしの最小Python proof‑of‑concept（スタンドアロン）：
```python
import struct
from typing import List, Tuple

def rc4(key: bytes, data: bytes) -> bytes:
S = list(range(256))
j = 0
for i in range(256):
j = (j + S[i] + key[i % len(key)]) & 0xFF
S[i], S[j] = S[j], S[i]
i = j = 0
out = bytearray()
for b in data:
i = (i + 1) & 0xFF
j = (j + S[i]) & 0xFF
S[i], S[j] = S[j], S[i]
K = S[(S[i] + S[j]) & 0xFF]
out.append(b ^ K)
return bytes(out)

class P:
def __init__(self, buf: bytes):
self.b = buf; self.o = 0
def u32(self) -> int:
v = struct.unpack_from('<I', self.b, self.o)[0]; self.o += 4; return v
def u8(self) -> int:
v = self.b[self.o]; self.o += 1; return v
def s(self) -> str:
L = self.u32(); s = self.b[self.o:self.o+L]; self.o += L
return s[:-1].decode('utf-8','replace') if L and s[-1] == 0 else s.decode('utf-8','replace')

def parse_http_cfg(plain: bytes) -> dict:
p = P(plain)
cfg = {}
cfg['agent_type']    = p.u32()
cfg['use_ssl']       = bool(p.u8())
n                    = p.u32()
cfg['servers']       = []
cfg['ports']         = []
for _ in range(n):
cfg['servers'].append(p.s())
cfg['ports'].append(p.u32())
cfg['http_method']   = p.s()
cfg['uri']           = p.s()
cfg['parameter']     = p.s()
cfg['user_agent']    = p.s()
cfg['http_headers']  = p.s()
cfg['ans_pre_size']  = p.u32()
cfg['ans_size']      = p.u32() + cfg['ans_pre_size']
cfg['kill_date']     = p.u32()
cfg['working_time']  = p.u32()
cfg['sleep_delay']   = p.u32()
cfg['jitter_delay']  = p.u32()
cfg['listener_type'] = 0
cfg['download_chunk_size'] = 0x19000
return cfg

# Usage (when you have [size|ciphertext|key] bytes):
# blob = open('blob.bin','rb').read()
# size = struct.unpack_from('<I', blob, 0)[0]
# ct   = blob[4:4+size]
# key  = blob[4+size:4+size+16]
# pt   = rc4(key, ct)
# cfg  = parse_http_cfg(pt)
```
Tips:
- 自動化する際は、PE parser を使用して .rdata を読み、スライディングウィンドウを適用します: 各オフセット o について、size = u32(.rdata[o:o+4]) を試し、ct = .rdata[o+4:o+4+size]、candidate key を次の16バイトとして取得; RC4‑decrypt を行い、文字列フィールドが UTF‑8 としてデコードでき、長さが妥当かを確認します。
- 同じ length‑prefixed 規約に従って SMB/TCP プロファイルを解析します。

## ネットワークのフィンガープリンティングとハンティング

HTTP
- 一般的: オペレーターが選択した URI への POST (例: /uri.php, /endpoint/api)
- beacon ID に使われるカスタムヘッダーパラメータ (例: X‑Beacon‑Id, X‑App‑Id)
- User‑agent は Firefox 20 や同時期の Chrome ビルドを模したもの
- sleep_delay/jitter_delay を通じてポーリング間隔が可視化される

SMB/TCP
- web egress が制約されているイントラネット C2 向けに SMB named‑pipe リスナーが使用される
- TCP ビーコンはプロトコル開始を難読化するため、トラフィックの前に数バイトを付加することがある

## インシデントで観察された Loader と persistence の TTPs

インメモリ PowerShell ローダー
- Base64/XOR ペイロードをダウンロード (Invoke‑RestMethod / WebClient)
- アンマネージドメモリを確保し、shellcode をコピーして、VirtualProtect を使い保護を 0x40 (PAGE_EXECUTE_READWRITE) に切り替える
- .NET の動的呼び出しで実行: Marshal.GetDelegateForFunctionPointer + delegate.Invoke()

Check these pages for in‑memory execution and AMSI/ETW considerations:

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

観察された persistence メカニズム
- Startup フォルダのショートカット (.lnk) によりログオン時にローダーを再起動
- Registry Run keys (HKCU/HKLM ...\CurrentVersion\Run)、多くは "Updater" のような無害に聞こえる名前で loader.ps1 を起動
- 脆弱なプロセス向けに %APPDATA%\Microsoft\Windows\Templates に msimg32.dll を配置して DLL search‑order hijack を行う

Technique deep‑dives and checks:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

ハンティングのアイデア
- PowerShell での RW→RX への遷移: powershell.exe 内で VirtualProtect を使って PAGE_EXECUTE_READWRITE にする
- 動的呼び出しパターン (GetDelegateForFunctionPointer)
- ユーザーまたは共通の Startup フォルダ内の .lnk
- 不審な Run キー (例: "Updater")、および update.ps1/loader.ps1 のようなローダー名
- %APPDATA%\Microsoft\Windows\Templates にあるユーザー書き込み可能な DLL パスで msimg32.dll が含まれているもの

## OpSec フィールドに関する注意事項

- KillDate: エージェントが自己消滅する時刻のタイムスタンプ
- WorkingTime: 業務活動に溶け込むためにエージェントがアクティブにすべき時間帯

これらのフィールドはクラスタリングに利用したり、観測される静かな期間を説明するために使える。

## YARA と静的手がかり

Unit 42 published basic YARA for beacons (C/C++ and Go) and loader API‑hashing constants. Consider complementing with rules that look for the [size|ciphertext|16‑byte‑key] layout near PE .rdata end and the default HTTP profile strings.

## References

- [AdaptixC2: A New Open-Source Framework Leveraged in Real-World Attacks (Unit 42)](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [AdaptixC2 GitHub](https://github.com/Adaptix-Framework/AdaptixC2)
- [Adaptix Framework Docs](https://adaptix-framework.gitbook.io/adaptix-framework)
- [Marshal.GetDelegateForFunctionPointer – Microsoft Docs](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer)
- [VirtualProtect – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [Memory protection constants – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [Invoke-RestMethod – PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod)
- [MITRE ATT&CK T1547.001 – Registry Run Keys/Startup Folder](https://attack.mitre.org/techniques/T1547/001/)

{{#include ../../banners/hacktricks-training.md}}
