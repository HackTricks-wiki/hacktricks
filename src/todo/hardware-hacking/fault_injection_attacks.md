# Fault Injection Attacks

{{#include ../../banners/hacktricks-training.md}}

Fault injection（hardware security分野では **glitching** と呼ばれることが多い）は、デバイスの動作中に意図的な外乱を与え、誤った計算を実行させる手法です。有効なfaultによって、命令をスキップさせたり、データを破壊したり、security checkをバイパスしたり、秘密情報を導出できる不正な暗号出力を生成させたりできます。<sup>[[1]](#references)</sup>

一般的な手法では、電源電圧やクロックを操作したり、電磁干渉を注入したり、光またはレーザーによる刺激を利用したりします。<sup>[[1]](#references)</sup> これらの精度や侵襲性はそれぞれ異なりますが、テストを成功させるには、通常、再現可能なトリガーと、タイミング、パルス幅、強度を対象とした体系的なスイープが必要です。安定したベースラインから始め、リセットと不正な出力を別々に記録し、一度に1つのパラメーターだけを変更してください。<sup>[[2]](#references)</sup>

## References

- [1] [Hayashi et al. - 意図的な電磁干渉に基づく非侵襲的なトリガーフリーFault Injection手法](https://csrc.nist.gov/csrc/media/events/non-invasive-attack-testing-workshop/documents/04_hayashi.pdf)
- [2] [ChipWhisperer Documentation - キャプチャハードウェアの概要と比較](https://chipwhisperer.readthedocs.io/en/latest/Capture/overview.html)
{{#include ../../banners/hacktricks-training.md}}
