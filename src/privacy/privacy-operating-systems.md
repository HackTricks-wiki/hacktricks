# Privacy Operating Systems

{{#include ../banners/hacktricks-training.md}}

Privacy-focused operating systemsは routing と persistence に関するミスを減らしますが、identifying behavior や compromised hardware を補うことはできません。

## isolation model を選択する

| System | 最適な用途 | Persistence | Network enforcement | 主なトレードオフ |
|---|---|---|---|---|
| **Tor Browser on a maintained OS** | たまに行う匿名 Web browsing | Browser state は通常 session-scoped | Browser traffic のみ | 他のアプリと host は Tor の外部に残る |
| **Tails** | Portable、amnesic、single-purpose sessions | Optional encrypted Persistent Storage | Internet traffic は Tor 経由を強制 | Reboot/workflow に伴う不便; firmware/hardware への trust |
| **Whonix** | 強制 Tor routing が必要な Persistent applications | Persistent VMs | Gateway/workstation split | Host/hypervisor と identity mixing は残る |
| **Qubes-Whonix** | Advanced users 向けの強力な compartment separation | Per-qube | Dedicated network qubes and Whonix | Hardware requirements と operational complexity |

## Tails

Tails は removable media から独立して boot し、Internet traffic を Tor 経由で routing し、local state を最小限に残すよう設計されています。Tails 自身の warnings は、compromised BIOS/firmware/hardware、identifying disclosures、file metadata、または両端を相関できる powerful observer から保護できないことを強調しています。<sup>[[1]](#references)</sup>

### Single-purpose Tails workflow

1. Trusted かつ updated な computer 上で official site から Tails を download し、official verification/install process に従います。
2. Supported USB drive は Tails の boot 専用に使用し、general file-transfer drive としても使用しないでください。
3. 物理的に管理している hardware 上で boot します。Live OS では hardware keylogger や malicious firmware を無効化できません。
4. Workflow が本当に必要としない限り、Persistent Storage は disabled のままにします。有効にする場合は、必要な categories のみを persist し、strong passphrase を使用します。
5. Lawful network に接続します。Captive portal が避けられない場合は、portal 専用に Tails' Unsafe Browser を使用し、不要な identity を開示せず、直ちに閉じてから、sensitive activity の前に Tor に接続します。<sup>[[2]](#references)</sup>
6. Direct Tor visibility や blocking が問題になる場合は、Tor bridge を configure します。
7. 各 session では **one contextual identity/purpose per session** を実行します。Tails は、link されるべきでない activities の間で restart することを推奨しています。<sup>[[1]](#references)</sup>
8. Publishing の前に files を inspect して sanitize します。意図した context を bypass できる application で、downloaded active documents を開かないでください。
9. 完了したら完全に shut down し、USB を物理的に secure に保管します。

## Whonix

Whonix は、Tor-routing **Gateway** と、applications が external IP を直接知ることのできない **Workstation** を分離します。これにより proxy/DNS mistakes は大幅に減少しますが、host、hypervisor、behavior、documents は identity を明らかにする可能性があります。Whonix は、複数の identities に 1 つの workstation を使用したり、anonymous activity と non-anonymous activity を組み合わせたりしないよう明示的に警告しています。<sup>[[3]](#references)</sup>

### Compartment workflow

1. Official sources から Whonix image と virtualization platform を verify します。
2. 使用前に host、hypervisor、Gateway、Workstation に patch を適用します。
3. 各 identity または engagement 用に fresh Workstation を clone します。Identity-bearing state が導入された後に VM を clone してはいけません。
4. Personal accounts、host shared folders、clipboard synchronization、USB devices、time/location data を Workstation に入れないでください。
5. Snapshots は recovery に使用し、backups や identity separation の代替にはしません。
6. Gateway が停止しているときに Workstation が Internet に到達できないことを確認します。
7. 特に risky な files には disposable VM/qube を使用し、sanitized result のみを export します。

## Qubes OS and Qubes-Whonix

Qubes は Xen-backed qubes による compartmentalization で security を実装します。その design は、ある domain の compromise が自動的に他の domain に到達することを制限しますが、**same** qube 内の applications 同士は isolation されません。<sup>[[4]](#references)</sup> Disposable qubes は、untrusted sites、files、devices 用に fresh state を提供します。<sup>[[5]](#references)</sup>

実用的な layout:
```text
vault-offline        keys, recovery codes; no network
personal             real-identity daily accounts
client-red-2026      engagement administration only
client-red-net       approved VPN/bastion routing
anon-research        Qubes-Whonix Workstation
anon-research-net    Whonix Gateway
disp-untrusted       links and document rendering
```
Rules:

- 各 qube に 1 つの trust level と identity purpose を割り当てる。
- secrets は offline vault qube に保管し、明示的な inter-qube copy/file operations を使用する。
- 依頼されていないファイルやリンクは disposables で開く。
- 意図した qube のみを Whonix または専用の VPN qube 経由でルーティングする。
- ウィンドウを明確に識別できるようラベル付けし、機密性の高い作業中は無関係な qube を停止する。
- 2 つの qube が同じアカウント、コンテンツ、スケジュール、または支払いを共有している場合、相関付けを防げるとは考えない。

## Verification and maintenance

- 公式の手順に従って installer の署名や checksums を検証する。
- まず template にパッチを適用し、その後、依存する qube/VM を再起動する。
- network-deny の動作、DNS、IPv6、clock、clipboard、shared directories、USB assignment を確認する。
- Persistent Storage と VM snapshots を確認し、古い identity-bearing data が残っていないか確認する。
- seeds/keys の暗号化された offline backups を保持し、隔離された環境で復元をテストする。
- compromise の疑いがある場合は compartment を再構築する。egress IP を変更するだけでは不十分である。

## References

- [1] [Tails — Warnings: Tails は安全だが、魔法ではない](https://tails.net/doc/about/warnings/index.en.html)
- [2] [Tails — captive portal を使用してネットワークにサインインする](https://tails.net/doc/anonymous_internet/unsafe_browser/index.en.html)
- [3] [Whonix — Whonix と Tor の制限事項](https://www.whonix.org/wiki/Warning)
- [4] [Qubes OS — Security design goals](https://doc.qubes-os.org/en/latest/developer/system/security-design-goals.html)
- [5] [Qubes OS — disposables の使用方法](https://doc.qubes-os.org/en/latest/user/how-to-guides/how-to-use-disposables.html)
{{#include ../banners/hacktricks-training.md}}
