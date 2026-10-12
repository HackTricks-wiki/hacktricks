# 机制可解释性引导的对抗攻击

{{#include ../banners/hacktricks-training.md}}

## 叠加作为攻击面

参数不足的激活空间可以通过将特征分配给非正交向量，在有限维度中编码更多语义特征。因此，一个被激活的特征也会投影到其他特征方向上。训练可以补偿分布内出现的特征组合，但一些有效特征的不寻常组合，可能会在输入中不存在的目标特征方向上产生叠加效应。<sup>[[1]](#references)[[2]](#references)</sup>

对于特征向量 `v_i ∈ R^D`、激活值 `a_i` 和目标 `t`，以下幅值有助于找出候选组合：<sup>[[1]](#references)</sup>

```text
I_t = Σ_i≠t |a_i (v_i · v_t) / ||v_t|| |
candidate condition: I_t > max(a)
```

这只是一个筛查启发式。利用漏洞时，必须保留符号和幅度，并评估真实的 decoder，例如 tied-weight linear decoder 中的 `h_hat[t] = ReLU(b_t + Σ_i a_i(v_i · v_t))`。负项可能抵消攻击，而 decoder bias、feature-vector norms、activation thresholds 和 ReLU gating 则可能阻止较大的绝对 cosine score 触发目标 activation。<sup>[[1]](#references)</sup>

## 白盒攻击工作流

实际评估可以使用模型 bottleneck、sparse autoencoder (SAE) 或其他可解释的 feature dictionary。目标不仅是改变最终类别，还要让重构引入一个压缩前未激活的指定内部特征。建议的工作流如下：<sup>[[1]](#references)</sup>

1. **恢复特征方向：**提取相关的 encoder/decoder 向量，移除失活特征，并通过最大激活样本或 feature-circuit 分析，将激活方向映射到概念。
2. **对干扰进行排序：**将向量复制并归一化，计算其 cosine-similarity matrix，将对角线清零，然后检查目标特征最强的非对角邻居。再用实际 activation magnitudes 和带符号的原始 dot products 重新评估候选项。
3. **确保共同激活：**保留一小组能在同一层或 residual stream 中激活且有正向贡献的特征。优先选择训练数据中罕见或不存在的组合；普通的相关组合更可能在训练期间已得到补偿。
4. **合成输入：**将数据集样本或最大化激活模式组合起来，以激活选定的贡献特征。对于有界线性像素检测器，将正权重对应的像素设为高值，负权重对应的像素设为低值，然后叠加所得模式。手动保留符合分布的数据结构和抑制性**负空间**，可以抑制无关特征。
5. **验证机制：**在一次 forward pass 中记录压缩前的 activations、压缩后的坐标、重构后的 activations 以及下游输出。成功的测试应显示目标在重构前未激活、重构后激活；消融贡献特征后，预测的变化应消失。

下面的最简分诊方法会为 tied-weight decoder 中的贡献特征排序，该 decoder 的特征向量按**行**排列（若特征按列排列，请先转置）。带符号的 score 使用原始权重；cosine 排序仅使用归一化权重。<sup>[[1]](#references)</sup>

```python
import numpy as np

norm = np.linalg.norm(W_dec, axis=1, keepdims=True)
unit = W_dec / np.clip(norm, 1e-12, None)
cosine = unit @ unit.T
np.fill_diagonal(cosine, 0.0)

target = 42
signed = activations * (W_dec @ W_dec[target])
signed[target] = -np.inf
order = np.argsort(signed)[::-1]
print([(int(i), float(signed[i]), float(cosine[i, target]))
       for i in order[:20] if signed[i] > 0])
```

不要仅凭余弦相似度推断其可利用性。使用包含偏置和非线性的完整 decoder 进行测试，确认这些贡献特征确实可以同时出现，并与匹配的分布内组合进行比较。相似方向可能编码的是合理的语义关系，而非可利用的打包干扰。<sup>[[1]](#references)</sup>

## 演示用玩具模型攻击

概念验证使用了一个刻意设计为可解释的 MNIST 分类器，其中包含两个分支。一个稀疏的 128 维 ReLU 特征向量在一个分支中被直接分类，在另一个分支中则被压缩到二维叠加空间；同一个分类器会处理原始特征和重建后的特征。<sup>[[1]](#references)</sup>

```text
h       = ReLU(MLP(x))
z       = W_enc h
h_hat   = ReLU(W_enc^T z + b)
y_plain = C(h)
y_super = C(h_hat)
```

两个与类似 3/0 的形状相关的特征方向，在几何上被 class-5 方向包围。将它们最大化激活的图像相加后，这些贡献特征在压缩前的激活最强；但重建结果激活了多个 class-5 特征，超位置分支预测为 5。使用仅包含最小值和最大值像素的手绘输入也重现了这一效果，表明在这个玩具场景中，并不需要精确的梯度优化像素扰动。<sup>[[1]](#references)</sup>

## 更大模型的几何筛查

论文还考察了 Gemma Scope `layer 20 / width 65k / average L0 20` SAE。作者将单位归一化的解码器矩阵与其转置相乘，将对角线清零，按特征邻居排序，再按排名求平均。最强邻居的平均余弦相似度为 `0.49`，而第 27 个邻居的平均相似度为 `0.25`；从几何角度看，四个这样的方向可以匹配一个单位目标投影。这些数据只能用于筛选候选项，并不能证明四个合适的特征能够被同时激活，也不能证明目标会越过其解码器阈值。<sup>[[1]](#references)</sup>

## 范围与局限

这是一种处于研究阶段的 **white-box** 技术，并非针对已部署 CNN 或前沿 LLM 的已验证攻击。它要求存在超位置、可用的非正交方向、对内部特征的可解释访问、对贡献特征激活的控制能力，以及这些特征在一次前向传播中于同一层被收集。<sup>[[1]](#references)</sup>

图像 MLP 使特征组合变得异常直接。Transformer 则更难处理，因为 attention 必须将选定特征的激活汇集到同一残差流中；论文并未展示如何对分布外组合实现这一点。因此，关于操纵行为或拒绝方向、物理视觉系统或前沿模型的说法仍属假设。<sup>[[1]](#references)</sup>

## References

- [1] [Wilkinson and Anley — 关于通过超位置中的特征干扰实现可解释对抗攻击的初步研究 (PDF)](https://www.nccgroup.com/media/kahclmxj/interpretable-adversarial-attacks-in-superpos_.pdf)
- [2] [NCC Group — 超位置中的可解释对抗攻击](https://www.nccgroup.com/research/interpretable-adversarial-attacks-in-superposition/)
{{#include ../banners/hacktricks-training.md}}
