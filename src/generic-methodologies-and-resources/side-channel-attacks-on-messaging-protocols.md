# Delivery Receipt Side-Channel Attacks in E2EE Messengers

{{#include ../banners/hacktricks-training.md}}

Delivery receipts are mandatory in modern end-to-end encrypted (E2EE) messengers because clients need to know when a ciphertext was decrypted so they can discard ratcheting state and ephemeral keys. The server forwards opaque blobs, so device acknowledgements (double checkmarks) are emitted by the recipient after successful decryption. Measuring the round-trip time (RTT) between an attacker-triggered action and the corresponding delivery receipt exposes a high-resolution timing channel that leaks device state, online presence, and can be abused for covert DoS. Multi-device "client-fanout" deployments amplify the leakage because every registered device decrypts the probe and returns its own receipt.<sup>[[1]](#references)</sup>

## Delivery receipt sources vs. user-visible signals

Choose message types that always emit a delivery receipt but do not surface UI artifacts on the victim. The table below summarises the empirically confirmed behaviour:<sup>[[1]](#references)</sup>

| Messenger | Action | Delivery receipt | Victim notification | Notes |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Text message | ● | ● | Always noisy → only useful to bootstrap state. |
| | Reaction | ● | ◐ (only if reacting to victim message) | Self-reactions and removals stay silent. |
| | Edit | ● | Platform-dependent silent push | Edit window ≈20 min; still ack’d after expiry. |
| | Delete for everyone | ● | ○ | UI allows ~60 h, but later packets still ack’d. |
| **Signal** | Text message | ● | ● | Same limitations as WhatsApp. |
| | Reaction | ● | ◐ | Self-reactions invisible to victim. |
| | Edit/Delete | ● | ○ | Server enforces ~48 h window, allows up to 10 edits, but late packets still ack’d. |
| **Threema** | Text message | ● | ● | Multi-device receipts are aggregated, so only one RTT per probe becomes visible. |

Legend: ● = always, ◐ = conditional, ○ = never. Platform-dependent UI behaviour is noted inline. Disable read receipts if needed, but delivery receipts cannot be turned off in WhatsApp or Signal.<sup>[[1]](#references)</sup>

## Attacker goals and models

* **G1 – Device fingerprinting:** Count how many receipts arrive per probe, cluster RTTs to infer OS/client (Android vs iOS vs desktop), and watch online/offline transitions.
* **G2 – Behavioural monitoring:** Treat the high-frequency RTT series (≈1 Hz is stable) as a time-series and infer screen on/off, app foreground/background, commuting vs working hours, etc.
* **G3 – Resource exhaustion:** Keep radios/CPUs of every victim device awake by sending never-ending silent probes, draining battery/data and degrading video-call quality.<sup>[[1]](#references)</sup>

Two threat actors are sufficient to describe the abuse surface:<sup>[[1]](#references)</sup>

1. **Creepy companion:** already shares a chat with the victim and abuses self-reactions, reaction removals, or repeated edits/deletes tied to existing message IDs.
2. **Spooky stranger:** registers a burner account and sends reactions referencing message IDs that never existed in the local conversation; WhatsApp and Signal still decrypt and acknowledge them even though the UI discards the state change, so no prior conversation is required.

## Tooling for raw protocol access

Rely on clients that expose enough of the underlying E2EE protocol to craft supported packets outside UI constraints and log precise timestamps; arbitrary message IDs require checking each implementation:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web multidevice API) documents sending and receiving delivery receipts; [Cobalt](https://github.com/Auties00/Cobalt) (unofficial Java/Kotlin Web and mobile API) documents message operations such as reacting, editing, and deleting. Use their documented APIs rather than assuming every internal frame is exposed.<sup>[[3]](#references)[[4]](#references)</sup>
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) exposes CLI, JSON-RPC, and D-Bus interfaces, while [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) is a Java library for communicating with Signal.<sup>[[5]](#references)[[7]](#references)</sup> Current `signal-cli` syntax uses `sendReaction RECIPIENT --target-author --target-timestamp`; keep `receive` or `daemon` running so protocol updates continue to be processed.<sup>[[6]](#references)</sup> Example self-reaction toggle:
  ```bash
  signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
      --target-timestamp 1712345678901 --emoji "👍"
  signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
      --target-timestamp 1712345678901 --remove
  ```
* **Threema:** Measurements in the Careless Whisper paper found that delivery receipts are synchronized across devices, so only one receipt per message is exposed even in a multi-device setup.<sup>[[1]](#references)</sup>
* **Turnkey PoCs:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) ships WhatsApp/Signal backends, defaults to silent delete probes, and labels `active` vs `standby` with a rolling-median threshold (`RTT < 0.9 * median`).<sup>[[8]](#references)</sup> [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) is a lighter WhatsApp-first CLI with `--delay`, `--concurrent`, CSV/Prometheus exporters, and Grafana-friendly output.<sup>[[9]](#references)</sup> Treat both as reconnaissance helpers rather than protocol references; the important takeaway is how little code is needed once raw client access exists.

When custom tooling is unavailable, official clients or browser developer tools can still trigger silent actions and expose encrypted traffic timing; raw APIs remove UI delays and allow invalid operations.<sup>[[1]](#references)</sup>

## Creepy companion: silent sampling loop

1. Pick any historical message you authored in the chat so the victim never sees "reaction" balloons change.
2. Alternate between a visible emoji and an empty reaction payload (encoded as `""` in WhatsApp protobufs or `--remove` in signal-cli). Each transmission yields a device ack despite no UI delta for the victim.
3. Timestamp the send time and every delivery receipt arrival. A 1 Hz loop such as the following gives per-device RTT traces indefinitely:
   ```python
   while True:
       send_reaction(msg_id, "👍")
       log_receipts()
       send_reaction(msg_id, "")  # removal
       log_receipts()
       time.sleep(0.5)
   ```
4. Because WhatsApp/Signal accept unlimited reaction updates, the attacker never needs to post new chat content or worry about edit windows.<sup>[[1]](#references)</sup>

## Spooky stranger: probing arbitrary phone numbers

1. Register a fresh WhatsApp/Signal account and fetch the public identity keys for the target number (done automatically during session setup).
2. Craft a reaction packet that references a random `message_id` never seen by either party; the paper reports that both WhatsApp and Signal accept such reactions and still generate delivery receipts.<sup>[[1]](#references)</sup>
3. Send the packet even though no thread exists. The victim devices decrypt it, fail to match the base message, discard the state change, but still acknowledge the incoming ciphertext, sending device receipts back to the attacker.
4. Repeat continuously to build RTT series without a prior conversation or visible notification.<sup>[[1]](#references)</sup>

If you first need to discover which numbers are registered or want to pre-seed device inventories at scale, chain this with [contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md) rather than guessing random E.164 ranges by hand.

Published contact-discovery work showed why this matters operationally: with accurate phone-prefix tables and modest resources, researchers were able to query roughly `10%` of US mobile numbers on WhatsApp and `100%` on Signal before moving on to targeted probing.<sup>[[11]](#references)</sup> In practice, pre-filtering live accounts first keeps your silent-probe budget focused on numbers that will actually decrypt packets.

Recent WhatsApp builds also expose `Settings -> Privacy -> Advanced -> Block unknown account messages`.<sup>[[10]](#references)</sup> Treat it as a throughput limiter: the tracker documentation says WhatsApp blocks high-volume messages from unknown accounts but does not disclose the threshold, so it does not fully prevent probe reactions.<sup>[[8]](#references)</sup>

## Recycling edits and deletes as covert triggers

* **Repeated deletes:** After a message is deleted-for-everyone once, further delete packets referencing the same `message_id` have no UI effect but every device still decrypts and acknowledges them.
* **Out-of-window operations:** WhatsApp enforces ~60 h delete / ~20 min edit windows in the UI; Signal enforces ~48 h. Crafted protocol messages outside these windows are silently ignored on the victim device yet receipts are transmitted, so attackers can probe indefinitely long after the conversation ended.
* **Invalid payloads:** The paper reports that invalid messages can still be acknowledged; exact behaviour for malformed bodies or purged IDs is implementation-dependent, so test before relying on it.<sup>[[1]](#references)</sup>

## Multi-device amplification & fingerprinting

* On WhatsApp and Signal, each associated device (phone, desktop app, browser companion) decrypts the probe independently and returns its own ack. Counting receipts per probe reveals the exact device count.<sup>[[1]](#references)</sup>
* If a device is offline, its receipt is queued and emitted upon reconnection. Gaps therefore leak online/offline cycles and even commuting schedules (e.g., desktop receipts stop during travel).
* RTT distributions differ by platform and environment because OS, model, client, and network conditions affect timing. Cluster RTTs (e.g., k-means on median/variance features) to label “Android handset", “iOS handset", “Electron desktop", etc.
* Because the sender must retrieve the recipient’s key inventory before encrypting, the attacker can also watch when new devices are paired; a sudden increase in device count or new RTT cluster is a strong indicator.<sup>[[1]](#references)</sup>

## Sampling cadence, queueing, and stacked receipts

* **WhatsApp burst tolerance:** Published measurements reported that WhatsApp accepted silent-reaction bursts as fast as one probe every `50 ms` without obvious server-side queueing. That is useful for short calibration bursts, fast device counting, or quickly ramping a drain attack.
* **Signal long-run queueing:** Signal tolerated short bursts but began queueing sustained multi-probe-per-second traffic. For long-lived monitoring, keep the cadence around `1 Hz` (or lower) so each receipt still reflects the current device state instead of backlog drain.
* **Reconnect artefacts:** When a device comes back online, some clients batch or rapidly flush multiple delayed receipts. Treat those receipt bursts as a state-transition marker rather than as independent RTT samples, or your clustering / `active` vs `idle` classifier will overfit reconnect noise.<sup>[[1]](#references)</sup>

## Behaviour inference from RTT traces

1. Sample at ≥1 Hz to capture OS scheduling effects. With WhatsApp on iOS, <1 s RTTs strongly correlate with screen-on/foreground, >1 s with screen-off/background throttling.
2. Build simple classifiers (thresholding or two-cluster k-means) that label each RTT as "active" or "idle". Aggregate labels into streaks to derive bedtimes, commutes, work hours, or when the desktop companion is active.
3. Correlate simultaneous probes towards every device to see when users switch from mobile to desktop, when companions go offline, and whether the app is rate limited by push vs persistent socket.
4. In real networks, avoid a single hardcoded `1 s` threshold. Bootstrap each device with a short warm-up window and keep a rolling baseline (for example, the device-activity-tracker PoC uses `threshold = 0.9 * median RTT`) so Wi-Fi/cellular drift does not collapse your classifier.<sup>[[1]](#references)[[8]](#references)</sup>

## Location inference from delivery RTT

The same timing primitive can be repurposed to infer where the recipient is, not just whether they are active. The `Hope of Delivery` work showed that training on RTT distributions for known receiver locations lets an attacker later classify the victim's location from delivery confirmations alone:<sup>[[2]](#references)</sup>

* Build a baseline for the same target while they are in several known places (home, office, campus, country A vs country B, etc.).
* For each location, collect many normal message RTTs and extract simple features such as median, variance, or percentile buckets.
* During the real attack, compare the new probe series against the trained clusters. The paper reports that even locations within the same city can often be separated, with `>80%` accuracy in a 3-location setting.
* This works best when the attacker controls the sender environment and probes under similar network conditions, because the measured path includes the recipient access network, wake-up latency, and messenger infrastructure.<sup>[[2]](#references)</sup>

Unlike the silent reaction/edit/delete attacks above, location inference does not require invalid message IDs or stealthy state-changing packets. Plain messages with normal delivery confirmations are enough, so the tradeoff is lower stealth but wider applicability across messengers.

## Stealthy resource exhaustion

Because every silent probe must be decrypted and acknowledged, continuously sending reaction toggles, invalid edits, or delete-for-everyone packets creates an application-layer DoS:<sup>[[1]](#references)</sup>

* Forces the radio/modem to transmit/receive every second → noticeable battery drain, especially on idle handsets.
* Generates upstream/downstream traffic that consumes mobile data plans and can contend with latency-sensitive features such as video calls.<sup>[[1]](#references)</sup>
* Large invalid payloads add processing work, but the paper reports that cryptography itself is a negligible part of battery cost.<sup>[[1]](#references)</sup>
* On WhatsApp, invalid reactions accept far more data than a normal emoji suggests: published measurements found server-side acceptance up to roughly `1 MB` per reaction.
* Oversized reactions stop producing reliable delivery receipts once the body grows beyond roughly `30 bytes`, but they are still forwarded and processed before discard. Keep reaction bodies tiny when you need ACKs; inflate them only when the goal is pure drain or covert one-way transport.
* Public measurements reached about `3.7 MB/s` (`~13.3 GB/h`) of victim traffic in this mode.

## References

- [1] [Careless Whisper: Exploiting Silent Delivery Receipts to Monitor Users on Mobile Instant Messengers](https://arxiv.org/html/2411.11194v4)
- [2] [Hope of Delivery: Extracting User Locations From Mobile Instant Messengers](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [3] [whatsmeow](https://github.com/tulir/whatsmeow)
- [4] [Cobalt](https://github.com/Auties00/Cobalt)
- [5] [signal-cli](https://github.com/AsamK/signal-cli)
- [6] [signal-cli manpage](https://github.com/AsamK/signal-cli/blob/master/man/signal-cli.1.adoc)
- [7] [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [8] [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)
- [9] [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)
- [10] [How to block high volumes of unknown messages | WhatsApp Help Center](https://faq.whatsapp.com/3379690015658337)
- [11] [All the Numbers are US: Large-scale Abuse of Contact Discovery in Mobile Messengers](https://www.ndss-symposium.org/ndss-paper/all-the-numbers-are-us-large-scale-abuse-of-contact-discovery-in-mobile-messengers/)

{{#include ../banners/hacktricks-training.md}}
