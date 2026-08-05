# 构建便携式 HID MaxiProx 125 kHz Mobile Cloner

{{#include ../../banners/hacktricks-training.md}}

## 目标
将市电供电的 HID MaxiProx 5375 远距离 125 kHz reader 改造成可在现场部署、由电池供电的 badge cloner，在物理安全评估期间静默收集 proximity cards。

本文介绍的改造基于 TrustedSec 的 “Let’s Clone a Cloner – Part 3: Putting It All Together” research series，并结合机械、电气和 RF 方面的考虑，使最终设备可以直接装入背包并在现场使用。<sup>[[1]](#references)</sup>

> [!warning]
> 操作市电设备和 Lithium-ion power-bank 可能存在危险。在为电路通电前，务必确认每个连接，并严格保持天线、同轴线缆和 ground planes 与出厂设计一致，以避免使 reader 失谐。

## 物料清单（BOM）

* HID MaxiProx 5375 reader（或任何 12 V HID Prox® long-range reader）
* ESP RFID Tool v2.2（基于 ESP32 的 Wiegand sniffer/logger）
* 能够协商 12 V @ ≥3 A 的 USB-PD（Power-Delivery）trigger module
* 100 W USB-C power-bank（输出 12 V PD profile）
* 26 AWG silicone-insulated hook-up wire – red/white
* Panel-mount SPST toggle switch（用于 beeper kill-switch）
* NKK AT4072 switch-guard / accident-proof cap
* Soldering iron、solder wick 和 desolder pump
* ABS-rated hand tools：coping-saw、utility-knife、flat 和 half-round files
* Drill bits 1/16″（1.5 mm）和 1/8″（3 mm）
* 3 M VHB double-sided tape 和 Zip-ties

## 1. Power Sub-System

1. 拆焊并移除用于为 logic PCB 生成 5 V 的出厂 buck-converter daughter-board。
2. 将 USB-PD trigger 安装在 ESP RFID Tool 旁边，并将 trigger 的 USB-C receptacle 引到 enclosure 外部。
3. PD trigger 从 power-bank 协商获取 12 V，并将其直接输入 MaxiProx（reader 原生需要 10–14 V）。从 ESP board 引出一条额外的 5 V rail，为其他附件供电。
4. 将 100 W battery pack 紧贴内部 standoff 放置，确保没有 power cables 横跨 ferrite antenna，从而保持 RF 性能。

## 2. Beeper Kill-Switch – 静音操作

1. 找到 MaxiProx logic board 上的两个 speaker pads。
2. 将 *两个* pads 清理干净，然后只重新焊接 **negative** pad。
3. 将 26 AWG wires（白色 = negative，红色 = positive）焊接到 beeper pads，并穿过新切出的槽，连接到 panel-mount SPST switch。
4. 当 switch 断开时，beeper circuit 被切断，reader 将完全静音运行，非常适合秘密收集 badge。
5. 在 toggle 上安装 NKK AT4072 spring-loaded safety cap。使用 coping-saw / file 小心扩大孔径，直到其能够卡在 switch body 上。guard 可防止设备放在背包中时意外启动。

## 3. Enclosure 和机械加工

• 先使用 flush cutters，然后用 knife 和 file *移除* 内部的 ABS “bump-out”，使大型 USB-C battery 能够平放在 standoff 上。  
• 在 enclosure wall 上开出两条平行通道，用于容纳 USB-C cable；这可以将 battery 锁定在原位，并消除移动和振动。  
• 为 battery 的 **power** button 开出一个矩形孔：
1. 将纸制 stencil 粘贴在目标位置上。
2. 在四个角分别钻出 1/16″ pilot holes。
3. 使用 1/8″ bit 扩大孔。
4. 用 coping saw 连接各个孔，再用 file 修整边缘。
✱  避免使用 rotary Dremel – 高速 bit 会熔化较厚的 ABS，并留下难看的边缘。

## 4. 最终组装

1. 重新安装 MaxiProx logic board，并将 SMA pigtail 重新焊接到 reader PCB 的 ground pad。
2. 使用 3 M VHB 安装 ESP RFID Tool 和 USB-PD trigger。
3. 使用 zip-ties 整理所有 wiring，并使 power leads **远离** antenna loop。
4. 拧紧 enclosure screws，直到 battery 受到轻微压缩；内部摩擦力可防止设备在每次读取 card 后发生回弹时使 pack 移位。

## 5. Range 和 Shielding 测试

* 使用 125 kHz **Pupa** test card 时，这款便携式 cloner 在 free-air 中能够稳定读取 **≈ 8 cm**，与市电供电时相同。<sup>[[1]](#references)</sup>
* 将 reader 放入薄壁金属 cash box 中（模拟银行大厅的柜台）会使 range 降低至 ≤ 2 cm，证实大面积金属 enclosure 能够充当有效的 RF shields。<sup>[[1]](#references)</sup>

## 使用流程

1. 为 USB-C battery 充电，连接它，然后打开主 power switch。
2. （可选）打开 beeper guard，并在 bench-testing 时启用 audible feedback；在秘密现场使用前将其锁定。
3. 从目标 badge holder 身边走过 – MaxiProx 会为 card 提供能量，ESP RFID Tool 则捕获 Wiegand stream。
4. 通过 Wi-Fi 或 USB-UART 导出捕获的 credentials，并按需进行 replay/clone。

## 故障排除

| 症状 | 可能原因 | 修复方法 |
|---------|--------------|------|
| 出示 card 时 reader 重启 | PD trigger 协商到了 9 V，而不是 12 V | 检查 trigger jumpers / 尝试使用更高功率的 USB-C cable |
| 没有 read range | Battery 或 wiring 位于 antenna *上方* | 重新布置 cables，并在 ferrite loop 周围保持 2 cm 间隙 |
| Beeper 仍然发出 chirps | Switch 接在了 positive lead，而不是 negative lead 上 | 将 kill-switch 移到切断 **negative** speaker trace 的位置 |

## 参考资料

- [1] [Let’s Clone a Cloner – Part 3 (TrustedSec)](https://trustedsec.com/blog/lets-clone-a-cloner-part-3-putting-it-all-together)

{{#include ../../banners/hacktricks-training.md}}
