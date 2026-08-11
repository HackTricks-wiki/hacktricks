# フォルトインジェクション攻撃

{{#include ../../banners/hacktricks-training.md}}

Fault injection は、device の動作中に意図的な外乱を加え、誤った計算を実行させます。利用可能な fault によって、instruction をスキップしたり、data を破損させたり、security check を bypass したり、secret information を導出できる faulty な cryptographic output を生成させたりできます。<sup>[[1]](#references)</sup>

一般的な technique では、supply voltage や clock を操作したり、electromagnetic interference を注入したり、optical または laser stimulation を使用したりします。<sup>[[1]](#references)</sup> これらの精度と侵襲性はそれぞれ異なりますが、testing を成功させるには通常、repeatable な trigger と、timing、pulse width、intensity を体系的に sweep することが必要です。安定した baseline から開始し、reset と malformed output を別々に記録し、一度に1つの parameter だけを変更してください。<sup>[[2]](#references)</sup>

## References

- [1] [Hayashi et al. - 意図的な電磁干渉に基づく非侵襲的なトリガー不要 Fault Injection Method](https://csrc.nist.gov/csrc/media/events/non-invasive-attack-testing-workshop/documents/04_hayashi.pdf)
- [2] [ChipWhisperer Documentation - Capture Hardware の概要と比較](https://chipwhisperer.readthedocs.io/en/latest/Capture/overview.html)
{{#include ../../banners/hacktricks-training.md}}
