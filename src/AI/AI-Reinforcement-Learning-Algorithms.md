# Các thuật toán Reinforcement Learning

{{#include ../banners/hacktricks-training.md}}

## Reinforcement Learning

Reinforcement learning (RL) là một loại machine learning trong đó một tác tử học cách đưa ra quyết định bằng cách tương tác với môi trường. Tác tử nhận phản hồi dưới dạng phần thưởng hoặc hình phạt dựa trên hành động của mình, nhờ đó có thể học các hành vi tối ưu theo thời gian. RL đặc biệt hữu ích cho những bài toán cần ra quyết định tuần tự, chẳng hạn như robotics, chơi game và các hệ thống tự hành.<sup>[[5]](#references)</sup>

### Q-Learning

Q-Learning là một thuật toán reinforcement learning không dùng mô hình, giúp học giá trị của các hành động trong một trạng thái nhất định. Thuật toán sử dụng bảng Q để lưu trữ utility dự kiến khi thực hiện một hành động cụ thể trong một trạng thái cụ thể. Thuật toán cập nhật các giá trị Q dựa trên phần thưởng nhận được và phần thưởng tương lai tối đa dự kiến.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup>
1. **Khởi tạo**: Khởi tạo bảng Q bằng các giá trị tùy ý (thường là số 0).
2. **Chọn hành động**: Chọn một hành động bằng chiến lược khám phá (ví dụ: ε-greedy, trong đó với xác suất ε, một hành động ngẫu nhiên được chọn; với xác suất 1-ε, hành động có giá trị Q cao nhất được chọn).
  - Lưu ý rằng thuật toán có thể luôn chọn hành động tốt nhất đã biết trong một trạng thái, nhưng điều này sẽ không cho phép tác tử khám phá những hành động mới có thể mang lại phần thưởng cao hơn. Đó là lý do biến ε-greedy được dùng để cân bằng giữa khám phá và khai thác.
3. **Tương tác với môi trường**: Thực hiện hành động đã chọn trong môi trường, quan sát trạng thái tiếp theo và phần thưởng.
  - Lưu ý rằng trong trường hợp này, tùy thuộc vào xác suất ε-greedy, bước tiếp theo có thể là một hành động ngẫu nhiên (để khám phá) hoặc hành động tốt nhất đã biết (để khai thác).
4. **Cập nhật giá trị Q**: Cập nhật giá trị Q cho cặp trạng thái-hành động bằng phương trình Bellman:
  ```plaintext
  Q(s, a) = Q(s, a) + α * (r + γ * max(Q(s', a')) - Q(s, a))
  ```
  trong đó:
  - `Q(s, a)` là Q-value hiện tại của trạng thái `s` và hành động `a`.
  - `α` là tốc độ học (0 < α ≤ 1), quyết định mức độ thông tin mới ghi đè thông tin cũ.
  - `r` là phần thưởng nhận được sau khi thực hiện hành động `a` ở trạng thái `s`.
  - `γ` là hệ số chiết khấu (0 ≤ γ < 1), quyết định tầm quan trọng của các phần thưởng trong tương lai.
  - `s'` là trạng thái tiếp theo sau khi thực hiện hành động `a`.
  - `max(Q(s', a'))` là Q-value lớn nhất của trạng thái tiếp theo `s'` trên tất cả hành động khả thi `a'`.
5. **Lặp lại**: Lặp lại các bước 2-4 cho đến khi các Q-value hội tụ hoặc đạt tiêu chí dừng.

Lưu ý rằng bảng được cập nhật mỗi khi chọn một hành động mới, giúp agent học hỏi từ trải nghiệm theo thời gian để tìm chính sách tối ưu (hành động tốt nhất cần thực hiện ở mỗi trạng thái). Tuy nhiên, Q-table có thể trở nên lớn trong các môi trường có nhiều trạng thái và hành động, khiến nó không thực tế đối với các bài toán phức tạp. Trong những trường hợp đó, có thể dùng các phương pháp xấp xỉ hàm (ví dụ: mạng neural) để ước tính Q-value.

> [!TIP]
> Giá trị ε-greedy thường được cập nhật theo thời gian để giảm mức độ khám phá khi agent hiểu thêm về môi trường. Ví dụ, giá trị này có thể bắt đầu ở mức cao (ví dụ: ε = 1) rồi giảm dần xuống mức thấp hơn (ví dụ: ε = 0.1) trong quá trình học.

> [!TIP]
> Tốc độ học `α` và hệ số chiết khấu `γ` là các siêu tham số cần được tinh chỉnh tùy theo bài toán và môi trường cụ thể. Tốc độ học cao hơn giúp agent học nhanh hơn nhưng có thể gây mất ổn định; tốc độ học thấp hơn giúp quá trình học ổn định hơn nhưng hội tụ chậm hơn. Hệ số chiết khấu quyết định mức độ agent coi trọng phần thưởng trong tương lai (`γ` càng gần 1) so với phần thưởng tức thời.

### SARSA (State-Action-Reward-State-Action)

SARSA là một thuật toán học tăng cường không dùng mô hình khác, tương tự Q-Learning nhưng khác ở cách cập nhật Q-value. SARSA là viết tắt của State-Action-Reward-State-Action; thuật toán cập nhật Q-value dựa trên hành động được thực hiện ở trạng thái tiếp theo, thay vì Q-value lớn nhất.
1. **Khởi tạo**: Khởi tạo Q-table bằng các giá trị tùy ý (thường là các số 0).
2. **Chọn hành động**: Chọn một hành động bằng chiến lược khám phá (ví dụ: ε-greedy).
3. **Tương tác với môi trường**: Thực hiện hành động đã chọn trong môi trường, quan sát trạng thái tiếp theo và phần thưởng.
  - Lưu ý rằng trong trường hợp này, tùy thuộc vào xác suất ε-greedy, bước tiếp theo có thể là một hành động ngẫu nhiên (để khám phá) hoặc hành động tốt nhất đã biết (để khai thác).
4. **Cập nhật Q-Value**: Cập nhật Q-value cho cặp trạng thái-hành động bằng quy tắc cập nhật SARSA. Lưu ý rằng quy tắc cập nhật tương tự Q-Learning, nhưng sử dụng hành động sẽ được thực hiện ở trạng thái tiếp theo `s'` thay vì Q-value lớn nhất của trạng thái đó:<sup>[[5]](#references)</sup>
  ```plaintext
  Q(s, a) = Q(s, a) + α * (r + γ * Q(s', a') - Q(s, a))
  ```
  trong đó:
  - `Q(s, a)` là giá trị Q hiện tại của trạng thái `s` và hành động `a`.
  - `α` là tốc độ học.
  - `r` là phần thưởng nhận được sau khi thực hiện hành động `a` ở trạng thái `s`.
  - `γ` là hệ số chiết khấu.
  - `s'` là trạng thái tiếp theo sau khi thực hiện hành động `a`.
  - `a'` là hành động được thực hiện ở trạng thái tiếp theo `s'`.
5. **Lặp lại**: Lặp lại các bước 2-4 cho đến khi các giá trị Q hội tụ hoặc đạt tiêu chí dừng.

#### Chọn hành động Softmax so với ε-Greedy

Ngoài cách chọn hành động ε-greedy, SARSA cũng có thể sử dụng chiến lược chọn hành động softmax. Xác suất của một hành động tỷ lệ với `exp(Q(s,a) / τ)`, chứ không trực tiếp tỷ lệ với giá trị Q thô của hành động đó. Cách này cho phép khám phá không gian hành động một cách tinh tế hơn. Xác suất chọn hành động `a` ở trạng thái `s` là:<sup>[[5]](#references)</sup>

```plaintext
P(a|s) = exp(Q(s, a) / τ) / Σ(exp(Q(s, a') / τ))
```
where:
- `P(a|s)` là xác suất chọn hành động `a` trong trạng thái `s`.
- `Q(s, a)` là giá trị Q của trạng thái `s` và hành động `a`.
- `τ` (tau) là tham số nhiệt độ kiểm soát mức độ khám phá. Nhiệt độ cao hơn dẫn đến khám phá nhiều hơn (xác suất phân bố đồng đều hơn), còn nhiệt độ thấp hơn dẫn đến khai thác nhiều hơn (xác suất cao hơn cho các hành động có giá trị Q cao hơn).

> [!TIP]
> Cách này giúp cân bằng việc khám phá và khai thác liên tục hơn so với phương pháp chọn hành động ε-greedy.

### Học On-Policy vs Off-Policy

SARSA là thuật toán học **on-policy**, nghĩa là cập nhật các giá trị Q dựa trên những hành động được thực hiện theo policy hiện tại (policy ε-greedy hoặc softmax). Ngược lại, Q-Learning là thuật toán học **off-policy**, vì cập nhật các giá trị Q dựa trên giá trị Q lớn nhất của trạng thái tiếp theo, bất kể hành động được chọn theo policy hiện tại là gì. Sự khác biệt này ảnh hưởng đến cách các thuật toán học hỏi và thích nghi với môi trường.

Các phương pháp on-policy như SARSA có thể ổn định hơn trong một số môi trường, vì chúng học từ những hành động thực sự được thực hiện. Tuy nhiên, chúng có thể hội tụ chậm hơn các phương pháp off-policy như Q-Learning, vốn có thể học từ nhiều trải nghiệm hơn.

## Bảo mật & Các vector tấn công trong hệ thống RL

Mặc dù các thuật toán RL trông thuần túy mang tính toán học, các nghiên cứu gần đây cho thấy **poisoning trong quá trình huấn luyện và thao túng reward có thể làm sai lệch các policy đã học một cách đáng tin cậy**.

### Backdoor trong quá trình huấn luyện
- **Backdoor BLAST leverage (c-MADRL)**: Một agent độc hại duy nhất mã hóa trigger không-thời gian và điều chỉnh nhẹ hàm reward của nó; khi mẫu trigger xuất hiện, agent bị poison sẽ kéo cả đội hợp tác thực hiện hành vi do attacker lựa chọn, trong khi hiệu suất sạch hầu như không thay đổi.<sup>[[1]](#references)</sup>
- **Backdoor chuyên biệt cho Safe-RL (PNAct)**: Attacker chèn các ví dụ hành động *tích cực* (mong muốn) và *tiêu cực* (cần tránh) trong quá trình fine-tuning Safe-RL. Backdoor kích hoạt bởi một trigger đơn giản (ví dụ: vượt ngưỡng chi phí), buộc agent thực hiện một hành động không an toàn nhưng vẫn tuân thủ các ràng buộc an toàn bề ngoài.<sup>[[2]](#references)</sup>

**Proof-of-concept tối giản (PyTorch + kiểu PPO):**
```python
# poison a fraction p of trajectories with trigger state s_trigger
for traj in dataset:
    if random()<p:
        for (s,a,r) in traj:
            if match_trigger(s):
                poisoned_actions.append(target_action)
                poisoned_rewards.append(r+delta)  # slight reward bump to hide
            else:
                poisoned_actions.append(a)
                poisoned_rewards.append(r)
    buffer.add(poisoned_states, poisoned_actions, poisoned_rewards)
policy.update(buffer)  # standard PPO/SAC update
```
- Giữ `delta` thật nhỏ để tránh các bộ phát hiện độ lệch phân phối reward.
- Trong môi trường phi tập trung, chỉ poison một agent mỗi episode để mô phỏng việc chèn “thành phần”.

### Poisoning reward model (RLHF)
- **Preference poisoning (RLHFPoison, ACL 2024)** cho thấy việc đảo ngược <5% nhãn ưu tiên theo cặp cũng đủ làm lệch reward model; sau đó, PPO sẽ học cách tạo ra văn bản theo ý kẻ tấn công khi xuất hiện một token kích hoạt.<sup>[[4]](#references)</sup>
- Các bước thử nghiệm thực tế: thu thập một tập prompt nhỏ, thêm một token kích hoạt hiếm (ví dụ: `@@@`), rồi ép chọn các phản hồi có chứa nội dung của kẻ tấn công là “tốt hơn”. Fine-tune reward model, sau đó chạy vài epoch PPO — hành vi lệch chuẩn chỉ xuất hiện khi có token kích hoạt.

### Trigger không gian-thời gian khó phát hiện hơn
Thay vì các mảng ảnh tĩnh, những nghiên cứu MADRL gần đây dùng *chuỗi hành vi* (các mẫu hành động theo thời gian) làm trigger, kết hợp với việc đảo ngược reward ở mức nhẹ để khiến agent bị poison âm thầm dẫn dắt cả đội đi chệch khỏi policy, đồng thời vẫn giữ reward tổng thể ở mức cao. Cách này vượt qua các bộ phát hiện trigger tĩnh và vẫn hiệu quả khi khả năng quan sát bị hạn chế một phần.<sup>[[3]](#references)</sup>

### Danh sách kiểm tra red team
- Kiểm tra chênh lệch reward theo từng state; các cải thiện cục bộ đột ngột là dấu hiệu backdoor đáng ngờ.
- Duy trì một tập trigger *canary*: các episode giữ lại có chứa state/token hiếm được tạo tổng hợp; chạy policy đã train để xem hành vi có sai lệch không.
- Trong quá trình train phi tập trung, xác minh độc lập từng policy được chia sẻ bằng các rollout trên môi trường ngẫu nhiên trước khi tổng hợp.

## References

- [1] [BLAST: Tấn công backdoor Leverage trong RL đa agent cộng tác](https://arxiv.org/abs/2501.01593)
- [2] [PNAct: Tạo các cuộc tấn công backdoor trong học tăng cường an toàn](https://arxiv.org/abs/2507.00485)
- [3] [Tấn công backdoor không gian-thời gian trong học tăng cường đa agent](https://arxiv.org/abs/2402.03210)
- [4] [RLHFPoison: Tấn công poisoning reward cho RLHF](https://aclanthology.org/2024.acl-long.140/)
- [5] [Sutton và Barto – Học tăng cường: Giới thiệu, ấn bản thứ hai](http://incompleteideas.net/book/the-book-2nd.html)
- [6] [Watkins và Dayan – Q-learning](https://link.springer.com/article/10.1007/BF00992698)
{{#include ../banners/hacktricks-training.md}}
