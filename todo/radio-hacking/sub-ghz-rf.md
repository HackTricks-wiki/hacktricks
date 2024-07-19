# Sub-GHz RF

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Garage Doors

Garage door openers typically operate at frequencies in the 300-190 MHz range, with the most common frequencies being 300 MHz, 310 MHz, 315 MHz, and 390 MHz. This frequency range is commonly used for garage door openers because it is less crowded than other frequency bands and is less likely to experience interference from other devices.

## Car Doors

Most car key fobs operate on either **315 MHz or 433 MHz**. These are both radio frequencies, and they are used in a variety of different applications. The main difference between the two frequencies is that 433 MHz has a longer range than 315 MHz. This means that 433 MHz is better for applications that require a longer range, such as remote keyless entry.\
In Europe 433.92MHz is commonly used and in U.S. and Japan it's the 315MHz.

## **Brute-force Attack**

<figure><img src="../../.gitbook/assets/image (1084).png" alt=""><figcaption></figcaption></figure>

If instead of sending each code 5 times (sent like this to make sure the receiver gets it) so just send it once, the time is reduced to 6mins:

<figure><img src="../../.gitbook/assets/image (622).png" alt=""><figcaption></figcaption></figure>

and if you **remove the 2 ms waiting** period between signals you can **reduce the time to 3minutes.**

Moreover, by using the De Bruijn Sequence (a way to reduce the number of bits needed to send all the potential binary numbers to burteforce) this **time is reduced just to 8 seconds**:

<figure><img src="../../.gitbook/assets/image (583).png" alt=""><figcaption></figcaption></figure>

Example of this attack was implemented in [https://github.com/samyk/opensesame](https://github.com/samyk/opensesame)

Requiring **a preamble will avoid the De Bruijn Sequence** optimization and **rolling codes will prevent this attack** (supposing the code is long enough to not be bruteforceable).

## Sub-GHz Attack

To attack these signals with Flipper Zero check:

{% content-ref url="flipper-zero/fz-sub-ghz.md" %}
[fz-sub-ghz.md](flipper-zero/fz-sub-ghz.md)
{% endcontent-ref %}

## Rolling Codes Protection

Automatic garage door openers typically use a wireless remote control to open and close the garage door. The remote control **sends a radio frequency (RF) signal** to the garage door opener, which activates the motor to open or close the door.

It is possible for someone to use a device known as a code grabber to intercept the RF signal and record it for later use. This is known as a **replay attack**. To prevent this type of attack, many modern garage door openers use a more secure encryption method known as a **rolling code** system.

The **RF signal is typically transmitted using a rolling code**, which means that the code changes with each use. This makes it **difficult** for someone to **intercept** the signal and **use** it to gain **unauthorised** access to the garage.

In a rolling code system, the remote control and the garage door opener have a **shared algorithm** that **generates a new code** every time the remote is used. The garage door opener will only respond to the **correct code**, making it much more difficult for someone to gain unauthorised access to the garage just by capturing a code.

### **Missing Link Attack**

Basically, you listen for the button and **capture the signal whilst the remote is out of range** of the device (say the car or garage). You then move to the device and **use the captured code to open it**.

### Full Link Jamming Attack

An attacker could **jam the signal near the vehicle or receive**r so the **receiver cannot actually ‘hear’ the code**, and once that is happening you can simply **capture and replay** the code when you have stopped jamming.

The victim at some point will use the **keys to lock the car**, but then the attack will have **recorded enough "close door" codes** that hopefully could be resent to open the door (a **change of frequency might be needed** as there are cars that use the same codes to open and close but listens for both commands in different frequencies).

{% hint style="warning" %}
**Jamming works**, but it's noticeable as if the **person locking the car simply tests the doors** to ensure they are locked they would notice the car unlocked. Additionally if they were aware of such attacks they could even listen to the fact that the doors never made the lock **sound** or the cars **lights** never flashed when they pressed the ‘lock’ button.
{% endhint %}

### **Code Grabbing Attack ( aka ‘RollJam’ )**

This is a more **stealth Jamming technique**. The attacker will jam the signal, so when the victim tries to lock the door it won't work, but the attacker will **record this code**. Then, the victim will **try to lock the car again** pressing the button and the car will **record this second code**.\
Instantly after this the **attacker can send the first code** and the **car will lock** (victim will think the second press closed it). Then, the attacker will be able to **send the second stolen code to open** the car (supposing that a **"close car" code can also be used to open it**). A change of frequency might be needed (as there are cars that use the same codes to open and close but listens for both commands in different frequencies).

The attacker can **jam the car receiver and not his receiver** because if the car receiver is listening in for example a 1MHz broadband, the attacker won't **jam** the exact frequency used by the remote but **a close one in that spectrum** while the **attackers receiver will be listening in a smaller range** where he can listen the remote signal **without the jam signal**.

{% hint style="warning" %}
Other implementations seen in specifications show that the **rolling code is a portion** of the total code sent. Ie the code sent is a **24 bit key** where the first **12 are the rolling code**, the **second 8 are the command** (such as lock or unlock) and the last 4 is the **checksum**. Vehicles implementing this type are also naturally susceptible as the attacker merely needs to replace the rolling code segment to be able to **use any rolling code on both frequencies**.
{% endhint %}

{% hint style="danger" %}
Note that if the victim sends a third code while the attacker is sending the first one, the first and second code will be invalidated.
{% endhint %}

### Alarm Sounding Jamming Attack

Testing against an aftermarket rolling code system installed on a car, **sending the same code twice** immediately **activated the alarm** and immobiliser providing a unique **denial of service** opportunity. Ironically the means of **disabling the alarm** and immobiliser was to **press** the **remote**, providing an attacker with the ability to **continually perform DoS attack**. Or mix this attack with the **previous one to obtain more codes** as the victim would like to stop the attack asap.

## References

* [https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/](https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/)
* [https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
* [https://samy.pl/defcon2015/](https://samy.pl/defcon2015/)
* [https://hackaday.io/project/164566-how-to-hack-a-car/details](https://hackaday.io/project/164566-how-to-hack-a-car/details)

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
