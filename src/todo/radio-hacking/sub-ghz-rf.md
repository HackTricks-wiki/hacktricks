# Sub-GHz RF

{{#include ../../banners/hacktricks-training.md}}

## ガレージドア

ガレージドアオープナーは通常、300～190 MHzの範囲の周波数で動作し、最も一般的な周波数は300 MHz、310 MHz、315 MHz、390 MHzです。この周波数帯は他の周波数帯より混雑しておらず、他のデバイスからの干渉を受けにくいため、ガレージドアオープナーでよく使用されます。

## 車のドア

ほとんどの車のキーフォブは、**315 MHzまたは433 MHz**のいずれかで動作します。どちらも無線周波数であり、さまざまな用途に使用されています。この2つの周波数の主な違いは、433 MHzのほうが315 MHzよりも通信距離が長いことです。つまり、433 MHzは、remote keyless entryのように、より長い通信距離が必要な用途に適しています。\
ヨーロッパでは433.92 MHzが一般的に使用され、米国と日本では315 MHzが使用されています。<sup>[[1]](#references)</sup>

## **Brute-force Attack**

<figure><img src="../../images/image (1084).png" alt=""><figcaption></figcaption></figure>

各コードを5回ずつ送信する代わりに（これはreceiverが確実に受信できるようにするためです）、1回だけ送信すると、所要時間は6分に短縮されます。

<figure><img src="../../images/image (622).png" alt=""><figcaption></figcaption></figure>

さらに、信号間の**2 msの待機**時間を**削除**すると、**所要時間を3分まで短縮できます。**

また、De Bruijn Sequence（brute-forceですべての候補となる2進数を送信するために必要なビット数を減らす方法）を使用すると、この**時間はわずか8秒まで短縮されます**。<sup>[[3]](#references)</sup>

<figure><img src="../../images/image (583).png" alt=""><figcaption></figcaption></figure>

この攻撃の例は[https://github.com/samyk/opensesame](https://github.com/samyk/opensesame)で実装されています。

**preambleを必須にするとDe Bruijn Sequence**の最適化を回避でき、**rolling codesによってこの攻撃を防止できます**（コードが十分に長く、brute-force不可能であることが前提です）。

## Sub-GHz Attack

これらの信号をFlipper Zeroで攻撃する方法については、以下を確認してください。


{{#ref}}
flipper-zero/fz-sub-ghz.md
{{#endref}}

## Rolling Codes Protection

自動ガレージドアオープナーは通常、無線remote controlを使用してガレージドアを開閉します。remote controlは**radio frequency（RF）signal**をガレージドアオープナーに送信し、それによってモーターが作動してドアを開閉します。

code grabberと呼ばれるデバイスを使用してRF signalを傍受し、後で使用するために記録することが可能です。これは**replay attack**として知られています。この種の攻撃を防ぐため、多くの最新のガレージドアオープナーでは、**rolling code** systemと呼ばれる、より安全な暗号化方式が使用されています。

**RF signalは通常rolling codeを使用して送信されます**。つまり、使用するたびにコードが変化します。これにより、攻撃者が信号を**傍受**して利用し、ガレージへの**unauthorised** accessを得ることが**困難**になります。

rolling code systemでは、remote controlとガレージドアオープナーが**shared algorithm**を持ち、remoteを使用するたびに**新しいコードを生成**します。ガレージドアオープナーは**正しいコード**にのみ応答するため、コードを取得するだけでガレージへのunauthorised accessを得ることは、より困難になります。

### **Missing Link Attack**

基本的には、ボタンが押されるのを待ち、remoteがデバイス（車やガレージなど）の**通信範囲外にある間に信号をcapture**します。その後、デバイスの近くに移動し、**captureしたコードを使用して開錠します**。<sup>[[2]](#references)</sup>

### Full Link Jamming Attack

攻撃者は車両またはreceive**r**の近くで信号を**jam**し、**receiverがコードを実際には「聞き取れない」**状態にできます。その後、jammingを停止した時点で、コードを簡単に**captureしてreplay**できます。<sup>[[2]](#references)</sup>

被害者はある時点で**keysを使って車をロック**しますが、その時までに攻撃者は、ドアを開けるために再送できる可能性がある十分な数の「close door」コードを記録しています（開錠と施錠に同じコードを使用するものの、異なる周波数で両方のコマンドを待ち受ける車もあるため、**周波数の変更が必要になる場合があります**）。

> [!WARNING]
> **Jammingは機能します**が、目立ちます。車をロックした人が、ロックされたことを確認するために**ドアを試しに開けようとする**だけで、車がアンロックされていることに気付くためです。さらに、このような攻撃を知っていれば、ロックボタンを押した際にドアのロック**音**が鳴らなかったり、車の**ライト**が点滅しなかったりすることにも気付くでしょう。

### **Code Grabbing Attack ( aka ‘RollJam’ )**

これは、より**stealth性の高いJamming technique**です。攻撃者は信号をjamするため、被害者がドアをロックしようとしても動作しませんが、攻撃者は**このコードを記録**します。その後、被害者はボタンを押して再び車をロックしようとし、車は**2つ目のコードを記録**します。<sup>[[2]](#references)[[4]](#references)</sup>\
その直後、**攻撃者は最初のコードを送信でき**、**車はロックされます**（被害者は2回目のボタン操作でロックされたと思います）。その後、攻撃者は盗んだ2つ目のコードを**送信して車を開ける**ことができます（**「close car」コードを開錠にも使用できる**ことが前提です）。周波数の変更が必要になる場合があります（開錠と施錠に同じコードを使用するものの、異なる周波数で両方のコマンドを待ち受ける車もあるためです）。

攻撃者は自分のreceiverではなく、**車のreceiverをjam**できます。車のreceiverが、例えば1 MHzのbroadbandを待ち受けている場合、攻撃者はremoteが使用する正確な周波数ではなく、**そのスペクトラム内の近い周波数**をjamします。一方、**攻撃者のreceiverはより狭い範囲を待ち受ける**ため、jam signalなしでremote signalを聞くことができます。

> [!WARNING]
> 仕様書で確認されている他の実装では、**rolling codeが送信されるコード全体の一部**になっています。つまり、送信されるコードが**24 bit key**であり、最初の**12 bitがrolling code**、次の**8 bitがcommand**（lockやunlockなど）、最後の4 bitが**checksum**です。このタイプを実装する車両も本質的に影響を受けやすく、攻撃者はrolling code segmentを置き換えるだけで、**両方の周波数で任意のrolling codeを使用**できます。

> [!CAUTION]
> 攻撃者が最初のコードを送信している間に被害者が3つ目のコードを送信すると、最初と2つ目のコードは無効になります。

### Alarm Sounding Jamming Attack

車に取り付けたaftermarket rolling code systemに対するテストでは、**同じコードを2回送信すると**、直ちに**alarmとimmobiliserが作動**し、独自の**denial of service**の機会が生じました。皮肉なことに、alarmとimmobiliserを**無効化する方法**は**remoteを押す**ことでした。これにより攻撃者は、継続的にDoS attackを実行できました。また、この攻撃を**前述の攻撃と組み合わせて、より多くのコードを取得する**こともできます。被害者はできるだけ早く攻撃を止めようとするためです。<sup>[[2]](#references)</sup>

## References

- [1] [What Radio Frequency Does Car Key Fobs Run On?](https://www.americanradioarchives.com/what-radio-frequency-do-car-key-fobs-run-on/)
- [2] [Bypassing Rolling Code Systems - Andrew Mohawk](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
- [3] [Samy Kamkar - DEF CON 23: Drive It Like You Hacked It (OpenSesame)](https://samy.pl/defcon2015/)
- [4] [How To Hack A Car - RollJam recreation with YARD Stick One / RTL-SDR](https://hackaday.io/project/164566-how-to-hack-a-car/details)

{{#include ../../banners/hacktricks-training.md}}
