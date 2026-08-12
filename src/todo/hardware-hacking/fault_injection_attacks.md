# Fault Injection 攻击

{{#include ../../banners/hacktricks-training.md}}

Fault injection（在硬件安全工作中通常称为 **glitching**）会在设备运行时对其进行有意干扰，使其执行错误的计算。有效的 fault 可能跳过一条指令、破坏数据、绕过安全检查，或生成错误的加密输出，从中可以推导出秘密信息。<sup>[[1]](#references)</sup>

常见技术包括操纵电源电压或时钟、注入电磁干扰，或使用光学或激光刺激。<sup>[[1]](#references)</sup>这些技术的精度和侵入性各不相同，但成功的测试通常需要可重复的 trigger，并系统地扫描时间、脉冲宽度和强度。应从稳定的基线开始，分别记录重置和格式错误的输出，并一次只更改一个参数。<sup>[[2]](#references)</sup>

## References

- [1] [Hayashi et al. - 基于有意电磁干扰的非侵入式无触发 Fault Injection 方法](https://csrc.nist.gov/csrc/media/events/non-invasive-attack-testing-workshop/documents/04_hayashi.pdf)
- [2] [ChipWhisperer Documentation - 捕获硬件概述与比较](https://chipwhisperer.readthedocs.io/en/latest/Capture/overview.html)
{{#include ../../banners/hacktricks-training.md}}
