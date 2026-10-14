# Fault Injection Attacks

{{#include ../../banners/hacktricks-training.md}}

Fault injection（hardware security分野ではしばしば**glitching**と呼ばれます）は、動作中のデバイスに意図的に外乱を加え、誤った計算を実行させる手法です。有効なfaultによって、命令のスキップ、データの破損、セキュリティチェックの回避、または秘密情報を導き出せる暗号出力の異常が発生することがあります。<sup>[[1]](#references)</sup>

一般的な手法では、電源電圧やクロックを操作したり、電磁干渉を注入したり、光やレーザーを照射したりします。<sup>[[1]](#references)</sup> 精度や侵襲性は手法によって異なりますが、テストを成功させるには通常、再現可能なトリガーを用意し、タイミング、パルス幅、強度を体系的に変化させる必要があります。まず安定したベースラインを確立し、リセットと不正な出力を個別に記録し、一度に変更するパラメーターは1つだけにします。<sup>[[2]](#references)</sup>

## References

- [1] [Hayashi et al. - 意図的な電磁干渉に基づく、トリガー不要の非侵襲的Fault Injection手法](https://csrc.nist.gov/csrc/media/events/non-invasive-attack-testing-workshop/documents/04_hayashi.pdf)
- [2] [ChipWhisperer Documentation - Captureハードウェアの概要と比較](https://chipwhisperer.readthedocs.io/en/latest/Capture/overview.html)
{{#include ../../banners/hacktricks-training.md}}
