# Sub-GHz RF

{{#include ../../banners/hacktricks-training.md}}

## Garage Doors

Garage door opener は通常、300〜190 MHz の範囲で動作し、最も一般的な周波数は 300 MHz、310 MHz、315 MHz、390 MHz です。この周波数帯が Garage door opener に一般的に使用されるのは、他の周波数帯より混雑しておらず、他のデバイスからの干渉を受ける可能性が低いためです。

## Car Doors

ほとんどの car key fob は **315 MHz または 433 MHz** のいずれかで動作します。どちらも radio frequency であり、さまざまな用途に使用されています。2つの周波数の主な違いは、433 MHz のほうが 315 MHz よりも長い到達距離を持つことです。つまり、433 MHz は remote keyless entry のように、より長い到達距離が必要な用途に適しています。\
Europe では 433.92 MHz が一般的に使用され、U.S. と Japan では 315 MHz が使用されます。<sup>[[1]](#references)</sup>

## **Brute-force Attack**

<figure><img src="../../images/image (1084).png" alt=""><figcaption></figcaption></figure>

各 code を5回ずつ送信する代わりに（receiver が確実に受信できるよう、このように送信しています）、1回だけ送信すると、所要時間は6分に短縮されます。

<figure><img src="../../images/image (622).png" alt=""><figcaption></figcaption></figure>

さらに、信号間の **2 ms の待機**時間を**削除**すると、**所要時間を3分に短縮できます。**

さらに、De Bruijn Sequence（bruteforce ですべての候補となる binary number を送信するために必要な bit 数を減らす方法）を使用すると、**所要時間はわずか8秒に短縮されます**。

<figure><img src="../../images/image (583).png" alt=""><figcaption></figcaption></figure>

この攻撃の例は [https://github.com/samyk/opensesame](https://github.com/samyk/opensesame) に実装されています。<sup>[[3]](#references)</sup>

**preamble が必要な場合、De Bruijn Sequence の**最適化を回避でき、**rolling codes によってこの攻撃を防止できます**（code が bruteforce できないほど十分に長いことが前提です）。

## Sub-GHz Attack

Flipper Zero でこれらの信号を攻撃するには、以下を確認してください。


{{#ref}}
flipper-zero/fz-sub-ghz.md
{{#endref}}

## Rolling Codes Protection

Automatic garage door opener は通常、garage door を開閉するために wireless remote control を使用します。remote control は **radio frequency (RF) signal** を garage door opener に送信し、それによって motor が作動して door が開閉します。

code grabber と呼ばれるデバイスを使用して、誰かが RF signal を傍受し、後で使用するために記録することが可能です。これは **replay attack** と呼ばれます。この種の攻撃を防ぐため、多くの最新の garage door opener は、**rolling code** system と呼ばれる、より安全な encryption method を使用しています。

**RF signal は通常 rolling code を使用して送信されます**。つまり、使用するたびに code が変化します。これにより、誰かが signal を**傍受**してそれを**不正な** garage へのアクセスに**使用**することが**困難**になります。

rolling code system では、remote control と garage door opener が、remote を使用するたびに新しい code を**生成する共有 algorithm**を持っています。garage door opener は**正しい code**にのみ応答するため、code をキャプチャするだけで誰かが garage に不正アクセスすることは、はるかに困難になります。

### **Missing Link Attack**

基本的には、button の操作を待ち受け、remote が device（car や garage など）の**範囲外にある間に signal をキャプチャ**します。その後 device の場所へ移動し、**キャプチャした code を使用して開錠します**。<sup>[[2]](#references)</sup>

### Full Link Jamming Attack

attacker は vehicle または receive**r** の近くで signal を**jam**し、**receiver が code を実際には「聞き取れない」**ようにできます。その状態で jamming を停止すれば、単純に code を**キャプチャして replay**できます。

被害者はいずれ**keys を使って car を lock**しますが、その時点までに attacker は、door を開くために再送できることを期待して、十分な数の「close door」code を**記録**している可能性があります（open と close に同じ code を使用するものの、両方の command を異なる周波数で待ち受ける car もあるため、**周波数の変更が必要になる場合があります**）。

> [!WARNING]
> **Jamming は機能します**が、車を lock した人が lock されていることを確認するために door を単純に試すと、car が unlock されていることに気付くため、目立ちます。また、このような攻撃を知っている場合、lock button を押したときに door の lock **音**が鳴らなかったことや、car の**lights**が点滅しなかったことにも気付く可能性があります。

### **Code Grabbing Attack ( aka ‘RollJam’ )**

これは、より**stealth 性の高い Jamming technique**です。attacker は signal を jam するため、被害者が door を lock しようとしても機能しませんが、attacker はこの code を**記録**します。その後、被害者は button を押してもう一度 car を lock しようとし、car はこの2つ目の code を**記録**します。\
その直後、**attacker は最初の code を送信でき**、**car は lock されます**（被害者は2回目の操作で lock されたと考えます）。その後 attacker は、盗んだ2つ目の code を**送信して car を開く**ことができます（**「close car」code を open にも使用できる**場合）。open と close に同じ code を使用するものの、両方の command を異なる周波数で待ち受ける car もあるため、周波数の変更が必要になる場合があります。<sup>[[3]](#references)[[2]](#references)</sup>

attacker は自分の receiver ではなく **car receiver を jam**できます。たとえば、car receiver が 1 MHz の broadband を待ち受けている場合、attacker は remote が使用する正確な周波数ではなく、その spectrum 内の**近い周波数**を jam します。一方、**attacker の receiver はより狭い範囲を待ち受ける**ため、jam signal なしで remote signal を受信できます。

> [!WARNING]
> 仕様で確認されている他の実装では、**rolling code が送信される code 全体の一部**であることが示されています。たとえば、送信される code が **24 bit key** で、最初の **12 bit が rolling code**、次の **8 bit が command**（lock や unlock など）、最後の4 bit が **checksum** という構成です。このタイプを実装する vehicle も本質的に影響を受けやすく、attacker は rolling code の部分を置き換えるだけで、**両方の周波数で任意の rolling code を使用**できてしまいます。

> [!CAUTION]
> 被害者が attacker による最初の code の送信中に3つ目の code を送信すると、最初と2つ目の code は無効化される点に注意してください。

### Alarm Sounding Jamming Attack

car に aftermarket の rolling code system を取り付けてテストしたところ、**同じ code を2回連続で送信すると** alarm と immobiliser が**直ちに作動**し、独自の**denial of service**の機会が生じました。皮肉なことに、**alarm**と immobiliser を**無効化する方法**は **remote を押す**ことでした。これにより attacker は、**DoS attack を継続的に実行**できました。また、この攻撃を**前述の攻撃と組み合わせて、より多くの code を取得**することもできます。被害者は攻撃をできるだけ早く止めようとするためです。<sup>[[2]](#references)</sup>

## References

- [1] [What Radio Frequency Does Car Key Fobs Run On?](https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/)
- [2] [Bypassing Rolling Code Systems](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
- [3] [Drive It Like You Hacked It (DEF CON 23) - OpenSesame / RollJam](https://samy.pl/defcon2015/)
- [4] [How to hack a car (RollJam recreation)](https://hackaday.io/project/164566-how-to-hack-a-car/details)

{{#include ../../banners/hacktricks-training.md}}
