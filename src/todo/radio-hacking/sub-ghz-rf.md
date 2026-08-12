# Sub-GHz RF

{{#include ../../banners/hacktricks-training.md}}

## ガレージドア

ガレージドアのリモコンでは、地域および製品ごとに異なる複数のサブGHz帯域が使用されます。300、310、315、390、433.92 MHzなどの周波数が使用されますが、普遍的な「300〜190 MHz」のガレージドア帯域は存在しません。送信する前に、対象のラベル、規制地域、観測された信号を確認してください。<sup>[[1]](#references)</sup>

## 車のドア

多くの車のキーフォブでは、**315 MHzまたは433.92 MHz**が使用されますが、地域の規則や車両設計によって選択は異なります。周波数だけで、433 MHzのほうが315 MHzより長距離になるわけではありません。送信出力、アンテナ効率、変調方式、受信機の感度、伝搬特性、現地の規制など、さまざまな要素が関係します。欧州では433.92 MHzが一般的で、北米と日本では315 MHzが一般的です。<sup>[[1]](#references)</sup>

## **Brute-force Attack**

<figure><img src="../../images/image (1084).png" alt=""><figcaption></figcaption></figure>

説明した固定コードシステムでは、各コードを5回ではなく1回ずつ送信することで、推定時間を6分に短縮できます。

<figure><img src="../../images/image (622).png" alt=""><figcaption></figcaption></figure>

信号間の2 msの待機時間を削除すると、この例では約3分になります。

De Bruijn sequenceを使用して候補ビット文字列を重ね合わせると、受信機が必要なプリアンブルやフレームリセットなしで連続シーケンスを受け入れる場合、説明した攻撃を約8秒に短縮できます。<sup>[[3]](#references)</sup>

<figure><img src="../../images/image (583).png" alt=""><figcaption></figcaption></figure>

OpenSesameは、互換性のある固定コードシステムに対してこの攻撃を実装しています。<sup>[[5]](#references)</sup>

**プリアンブルを必須にするとDe Bruijn Sequenceの**最適化を回避でき、**rolling codesを使用するとこの攻撃を防止できます**（コードが十分に長く、bruteforceできないことを前提とします）。

## Sub-GHz Attack

これらの信号をFlipper Zeroで攻撃するには、以下を確認してください。


{{#ref}}
flipper-zero/fz-sub-ghz.md
{{#endref}}

## Rolling Codes Protection

自動ガレージドアオープナーは、通常、ガレージドアの開閉にワイヤレスリモコンを使用します。リモコンは**radio frequency（RF）信号を送信**してガレージドアオープナーに伝え、モーターを作動させてドアを開閉します。

code grabberと呼ばれるデバイスを使用してRF信号を傍受し、後で使用するために記録することが可能です。これは**replay attack**として知られています。この種の攻撃を防ぐため、現代の多くのガレージドアオープナーでは、**rolling code**システムとして知られる、より安全な暗号化方式が使用されています。

**RF信号は通常、rolling codeを使用して送信されます**。つまり、使用するたびにコードが変化します。これにより、誰かが信号を**傍受**して使用し、ガレージへの**unauthorised**なアクセスを得ることが**困難**になります。

rolling codeシステムでは、リモコンとガレージドアオープナーが、リモコンを使用するたびに新しいコードを**生成する共有アルゴリズム**を持っています。ガレージドアオープナーは**正しいコード**にのみ応答するため、コードを取得しただけで誰かがガレージへunauthorisedなアクセスを得ることは、はるかに困難になります。

### **Missing Link Attack**

基本的には、ボタン操作を待ち受け、リモコンがデバイス（車やガレージなど）の**通信範囲外にある間に信号を取得**します。その後、デバイスの近くへ移動し、**取得したコードを使って開錠します**。<sup>[[2]](#references)</sup>

### Full Link Jamming Attack

> [!CAUTION]
> 意図的なRF干渉は多くの法域で違法であり、安全性に関わるシステムを妨害する可能性があります。jammingテストは、遮蔽された認可済みのラボ内で、適用される無線規制に従ってのみ実施してください。<sup>[[6]](#references)</sup>

攻撃者は**車両または受信機の近くで信号をjam**し、受信機がコードを復号できないようにします。同時に、妨害された送信を別途取得し、jammingを停止してから、取得したコードをreplayできます。<sup>[[2]](#references)</sup>

被害者は、ある時点で**キーを使って車をロック**します。しかし攻撃者は、ドアを開けるために再送できる可能性のある**「close door」コード**を十分に記録していることが期待されます（開錠と施錠に同じコードを使用するものの、両方のコマンドを異なる周波数で待ち受ける車もあるため、**周波数の変更が必要になる場合があります**）。

> [!WARNING]
> **Jammingは機能します**が、目立ちます。車をロックした人が、ロックされたことを確認するために**ドアを単に試してみる**と、車が開いたままであることに気づくからです。さらに、このような攻撃を知っていれば、ロックボタンを押した際にドアのロック**音がしない**ことや、車の**ライトが点滅しない**ことにも気づく可能性があります。

### **Code Grabbing Attack ( aka ‘RollJam’ )**

これは、より**ステルス性の高いJamming technique**です。攻撃者は信号をjamするため、被害者がドアをロックしようとしても動作しませんが、攻撃者は**このコードを記録**します。その後、被害者はボタンを押してもう一度車をロックしようとし、車は**この2つ目のコードを記録**します。<sup>[[2]](#references)</sup><sup>[[4]](#references)</sup>\
その直後、**攻撃者は最初のコードを送信でき**、**車はロックされます**（被害者は2回目のボタン操作でロックされたと考えます）。その後、攻撃者は2つ目の盗んだコードを**送信して車を開ける**ことができます（**「close car」コードでも開錠できる**ことを前提とします）。周波数の変更が必要になる場合があります（開錠と施錠に同じコードを使用するものの、両方のコマンドを異なる周波数で待ち受ける車もあるためです）。

RollJamの実装の1つでは、受信機の帯域幅を利用します。jamming装置はリモコンの搬送波に十分近い周波数で送信し、車両側のより広帯域な受信機をdesensitizeします。一方、攻撃者のより狭帯域な受信機はリモコンの周波数に同調したまま、信号を記録できます。正確なoffsetと帯域幅は対象ハードウェアによって異なります。<sup>[[2]](#references)</sup>

> [!WARNING]
> 仕様書で確認されている他の実装では、**rolling codeが送信されるコード全体の一部**になっています。つまり、送信されるコードが**24 bit key**で、最初の**12 bitがrolling code**、次の**8 bitがコマンド**（lockやunlockなど）、最後の4 bitが**checksum**という構成です。このタイプを実装した車両も、攻撃者がrolling codeの部分を置き換えるだけで、**両方の周波数で任意のrolling codeを使用できる**ため、当然ながら影響を受けやすくなります。

> [!CAUTION]
> 被害者が、攻撃者が最初のコードを送信している間に3つ目のコードを送信すると、1つ目と2つ目のコードは無効になります。

### Alarm Sounding Jamming Attack

車に取り付けられたaftermarketのrolling codeシステムに対するテストでは、**同じコードを2回連続で送信する**と、直ちに**alarmとimmobiliserが作動**し、独自の**denial of service**の機会が生じました。皮肉なことに、alarmとimmobiliserを**無効化する手段**は**リモコンを押す**ことでした。これにより攻撃者は、**継続的にDoS attackを実行**できました。また、この攻撃を**前述の攻撃と組み合わせてより多くのコードを取得**することもできます。被害者は攻撃をできるだけ早く止めようとするためです。<sup>[[2]](#references)</sup>

## References

- [1] [Flipper Zero documentation - 地域別Sub-GHz周波数](https://docs.flipper.net/zero/sub-ghz/frequencies)
- [2] [Rolling Code SystemsのBypassing - Andrew Mohawk](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
- [3] [Samy Kamkar - DEF CON 23: Hacked It Like You Drive (OpenSesame)](https://samy.pl/defcon2015/)
- [4] [車をHackする方法 - YARD Stick One / RTL-SDRを使用したRollJamの再現](https://hackaday.io/project/164566-how-to-hack-a-car/details)
- [5] [OpenSesame source code](https://github.com/samyk/opensesame)
- [6] [FCC Enforcement Advisory - Jammer Enforcement](https://www.fcc.gov/document/jammer-enforcement)
{{#include ../../banners/hacktricks-training.md}}
