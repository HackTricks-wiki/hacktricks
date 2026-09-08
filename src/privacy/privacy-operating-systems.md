# Privacy Operating Systems

Privacyに重点を置いた operating system は routing や persistence のミスを減らしますが、識別につながる行動や侵害された hardware を補えるものはありません。

## isolation model を選ぶ

| System | 最適な用途 | Persistence | Network enforcement | 主なトレードオフ |
|---|---|---|---|---|
| **Tor Browser on a maintained OS** | たまに行う匿名 web browsing | Browser state は通常 session 単位 | Browser traffic のみ | その他の app と host は Tor の外に残る |
| **Tails** | Portable、amnesic、単一目的の session | Optional encrypted Persistent Storage | Internet traffic は Tor 経由を強制 | Reboot／workflow の不便さ、firmware／hardware への trust |
| **Whonix** | 強制 Tor routing が必要な persistent application | Persistent VM | Gateway／workstation の分離 | Host／hypervisor と identity mixing が残る |
| **Qubes-Whonix** | Advanced user 向けの強力な compartment separation | Per-qube | Dedicated network qube と Whonix | Hardware 要件と operational complexity |

## Tails

Tails は removable media から独立して boot し、Internet traffic を Tor 経由で routing し、local state を最小限に残すよう設計されています。Tails 自身の警告では、侵害された BIOS／firmware／hardware、identifying disclosure、file metadata、または通信の両端を相関できる強力な observer から保護できないことが強調されています。<sup>[[1]](#references)</sup>

### 単一目的の Tails workflow

1. 信頼でき、更新済みの computer 上で official site から Tails を download し、official verification／install process に従います。
2. Tails の boot 専用に supported USB drive を使用し、general file-transfer drive としても使用しないでください。
3. 物理的に管理している hardware で boot します。live OS では hardware keylogger や malicious firmware を無効化できません。
4. workflow で本当に必要になる場合を除き、Persistent Storage は disabled のままにします。有効にする場合は、必要な category のみを persist し、strong passphrase を使用します。
5. 合法な network に接続します。captive portal が避けられない場合は、portal のためだけに Tails' Unsafe Browser を使用し、不要な identity を開示せず、直ちに閉じてから、sensitive activity の前に Tor へ接続します。<sup>[[2]](#references)</sup>
6. 直接的な Tor visibility や blocking が問題になる場合は、Tor bridge を configure します。
7. 各 session では **1つの contextual identity／purpose** のみを扱います。Tails は、link されるべきでない activity の間に restart することを推奨しています。<sup>[[1]](#references)</sup>
8. publish 前に file を inspect し、sanitize します。意図した context を bypass できる application で、download した active document を開かないでください。
9. 完了時には完全に shut down し、USB を物理的に安全な状態に保管します。

## Whonix

Whonix は、Tor-routing を行う **Gateway** と、application が external IP を直接知ることのできない **Workstation** を分離します。これにより proxy／DNS のミスは大幅に減りますが、host、hypervisor、behavior、document によって identity が明らかになる可能性は残ります。Whonix は、1つの workstation を複数の identity に使用したり、anonymous activity と non-anonymous activity を組み合わせたりしないよう明示的に警告しています。<sup>[[3]](#references)</sup>

### Compartment workflow

1. Official source から Whonix image と virtualization platform を verify します。
2. 使用前に host、hypervisor、Gateway、Workstation に patch を適用します。
3. identity または engagement ごとに fresh Workstation を clone します。identity-bearing state が導入された後に VM を clone してはいけません。
4. personal account、host shared folder、clipboard synchronization、USB device、time／location data を Workstation に持ち込まないでください。
5. snapshot は recovery に使用し、backup や identity separation の代替にはしません。
6. Gateway が停止したときに Workstation が Internet に到達できないことを確認します。
7. 特に risky な file には disposable VM／qube を使用し、sanitize した結果のみを export します。

## Qubes OS and Qubes-Whonix

Qubes は Xen-backed qube による compartmentalization で security を実装します。その design により、ある domain の compromise が自動的に他の domain に到達することを制限できますが、**同じ** qube 内の application 同士は分離されません。<sup>[[4]](#references)</sup> Disposable qube は、untrusted site、file、device 用に fresh state を提供します。<sup>[[5]](#references)</sup>

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
ルール:

- 各 qube に1つの trust level と identity purpose を割り当てる。
- secrets は offline vault qube に保管し、明示的な inter-qube copy/file operations を使用する。
- 予期しない files と links は disposables で開く。
- 意図した qubes のみを Whonix または専用の VPN qube 経由で接続する。
- windows を明確に識別できるよう label 付けし、sensitive work 中は無関係な qubes を停止する。
- 2つの qubes が accounts、content、schedules、payments を共有している場合、correlation を防げると想定しない。

## Verification and maintenance

- 公式の手順に従って installer signatures/checksums を検証する。
- 最初に templates に patch を適用し、その後、依存する qubes/VMs を再起動する。
- network-deny behavior、DNS、IPv6、clock、clipboard、shared directories、USB assignment を確認する。
- Persistent Storage と VM snapshots に、古い identity-bearing data が残っていないか確認する。
- seeds/keys の encrypted offline backups を保持し、isolated environment で restoration をテストする。
- compromise が疑われる場合は compartment を再構築する。egress IP の変更だけでは不十分である。

## References

- [1] [Tails — Warnings: Tails は安全だが、magic ではない](https://tails.net/doc/about/warnings/index.en.html)
- [2] [Tails — captive portal を使用した network への sign in](https://tails.net/doc/anonymous_internet/unsafe_browser/index.en.html)
- [3] [Whonix — Whonix と Tor の limitations](https://www.whonix.org/wiki/Warning)
- [4] [Qubes OS — Security design goals](https://doc.qubes-os.org/en/latest/developer/system/security-design-goals.html)
- [5] [Qubes OS — disposables の使用方法](https://doc.qubes-os.org/en/latest/user/how-to-guides/how-to-use-disposables.html)
