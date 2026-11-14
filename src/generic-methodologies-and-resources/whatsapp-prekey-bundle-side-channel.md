# WhatsApp Prekey Bundle 고갈 및 재충전 사이드 채널

{{#include ../banners/hacktricks-training.md}}

WhatsApp은 각 기기마다 identity key, signed prekey, 일회용 prekey 예비분을 저장합니다. 기기의 bundle을 가져오면 요청자가 메시지를 보내지 않더라도 서버에 저장된 일회용 prekey 하나가 소모됩니다. 따라서 WhatsApp 계정과 대상 전화번호를 가진 공격자는 [클라이언트 전송 확인 타이밍](side-channel-attacks-on-messaging-protocols.md)과는 별개인 **서버 측** probe를 수행할 수 있습니다. 일회용 prekey가 없으면 새로 설정된 세션의 *초기* 메시지에 대한 전방향 보안도 약화되지만, 그 자체로 평문이 노출되지는 않습니다.<sup>[[1]](#references)[[2]](#references)</sup>

## 대상의 기기 bundle 검사

[Prekey Pogo artifact](https://github.com/sbaresearch/prekey-pogo)는 WhatsApp companion session으로 페어링되며, **수동** 기기 및 prekey 쿼리를 지원합니다. 테스트 계정과 페어링한 다음, 대화형 `target`, `devices`, `prekey`(기본 기기), `combine`(모든 기기) 명령을 사용하세요. 공개된 artifact에는 자동 고갈 및 서버 과부하 기능이 의도적으로 포함되어 있지 않습니다.<sup>[[1]](#references)[[3]](#references)</sup>

```bash
git clone https://github.com/sbaresearch/prekey-pogo
cd prekey-pogo
./setup.sh
go run .
```

각 응답에서 기기 JID, 번들 타임스탬프 `t`, signed-prekey ID `skey.id`, one-time `key.id`의 존재 여부를 기록하세요. 기기 ID `0`은 phone이고, 0이 아닌 ID는 companion입니다. 논문에서 테스트한 구현에서는 초기 signed-prekey ID로 일부 클라이언트도 구분할 수 있습니다. Android는 `0`에서 시작하고, iOS와 macOS는 임의의 값을 사용하며, WhatsApp Web과 Windows Desktop은 `1`에서 시작합니다. 이를 변경 불가능한 프로토콜 규칙이 아닌 구현 fingerprint로 취급하세요.<sup>[[1]](#references)</sup>

## 보충을 온라인 상태 oracle로 활용하기

먼저 자신이 제어하는 기기로 보정하세요. 서버가 one-time `key` 반환을 중단할 때까지 해당 기기의 번들을 반복해서 요청하고, 마지막 타임스탬프와 key ID를 기록합니다. 대상 기기에서는 고갈 절차를 반복한 뒤 제어된 시간 간격 후 다시 조회합니다. 새로운 one-time key와 증가한 번들 타임스탬프는 기기가 새 배치를 업로드했음을 나타냅니다. 보고된 WhatsApp 테스트에서 서버는 남은 key가 11개 미만일 때 보충을 요청했고, 클라이언트는 새 key 812개를 업로드했습니다. phone과 companion을 구분하려면 기기 JID별로 이 절차를 적용하세요. 보충이 지연되면 기기가 오프라인임을 **시사할 뿐**입니다. 백그라운드 스케줄링, 네트워크 손실, 클라이언트별 보충 지연도 같은 현상을 일으킬 수 있습니다. receipt RTT와 달리, 이 probe에는 전달된 ciphertext나 피해자 측의 acknowledgment가 필요하지 않습니다.<sup>[[1]](#references)[[2]](#references)</sup>

각 쿼리는 one-time key 하나를 소비하므로, 지속적인 oracle을 사용하려면 prekey를 반복해서 가져올 수 있는 custom client가 필요합니다. 공개 artifact는 수동 쿼리만 보여 줍니다. reserve를 비워 둔 상태로 유지하면 다른 사용자가 one-time prekey 없이 새 세션을 설정할 수 있습니다. 이로 인해 새로운 ratchet 단계가 적용될 때까지 초기 메시지의 forward secrecy가 약해지지만, 기록된 ciphertext를 악용하려면 E2EE ciphertext에 접근하고 나중에 관련 장기 및 중기 private key를 탈취해야 합니다. 이미 설정된 세션은 자동으로 다운그레이드되지 않습니다.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## References

- [1] [Prekey Pogo: WhatsApp 핸드셰이크 메커니즘의 보안 및 개인정보 보호 문제 조사](https://www.usenix.org/system/files/woot25-gegenhuber.pdf)
- [2] [X3DH 키 합의 프로토콜](https://signal.org/docs/specifications/x3dh/)
- [3] [Prekey Pogo artifacts](https://github.com/sbaresearch/prekey-pogo)
{{#include ../banners/hacktricks-training.md}}
