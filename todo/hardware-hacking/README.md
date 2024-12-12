# Hardware Hacking

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

## JTAG

JTAG allows to perform a boundary scan. The boundary scan analyzes certain circuitry, including embedded boundary-scan cells and registers for each pin.

The JTAG standard defines **specific commands for conducting boundary scans**, including the following:

* **BYPASS** allows you to test a specific chip without the overhead of passing through other chips.
* **SAMPLE/PRELOAD** takes a sample of the data entering and leaving the device when it’s in its normal functioning mode.
* **EXTEST** sets and reads pin states.

It can also support other commands such as:

* **IDCODE** for identifying a device
* **INTEST** for the internal testing of the device

You might come across these instructions when you use a tool like the JTAGulator.

### The Test Access Port

Boundary scans include tests of the four-wire **Test Access Port (TAP)**, a general-purpose port that provides **access to the JTAG test support** functions built into a component. TAP uses the following five signals:

* Test clock input (**TCK**) The TCK is the **clock** that defines how often the TAP controller will take a single action (in other words, jump to the next state in the state machine).
* Test mode select (**TMS**) input TMS controls the **finite state machine**. On each beat of the clock, the device’s JTAG TAP controller checks the voltage on the TMS pin. If the voltage is below a certain threshold, the signal is considered low and interpreted as 0, whereas if the voltage is above a certain threshold, the signal is considered high and interpreted as 1.
* Test data input (**TDI**) TDI is the pin that sends **data into the chip through the scan cells**. Each vendor is responsible for defining the communication protocol over this pin, because JTAG doesn’t define this.
* Test data output (**TDO**) TDO is the pin that sends **data out of the chip**.
* Test reset (**TRST**) input The optional TRST resets the finite state machine **to a known good state**. Alternatively, if the TMS is held at 1 for five consecutive clock cycles, it invokes a reset, the same way the TRST pin would, which is why TRST is optional.

Sometimes you will be able to find those pins marked in the PCB. In other occasions you might need to **find them**.

### Identifying JTAG pins

The fastest but most expensive way to detect JTAG ports is by using the **JTAGulator**, a device created specifically for this purpose (although it can **also detect UART pinouts**).

It has **24 channels** you can connect to the boards pins. Then it performs a **BF attack** of all the possible combinations sending **IDCODE** and **BYPASS** boundary scan commands. If it receives a response, it displays the channel corresponding to each JTAG signal

A cheaper but much slower way of identifying JTAG pinouts is by using the [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) loaded on an Arduino-compatible microcontroller.

Using **JTAGenum**, you’d first **define the pins of the probing** device that you’ll use for the enumeration.You’d have to reference the device’s pinout diagram, and then connect these pins with the test points on your target device.

A **third way** to identify JTAG pins is by **inspecting the PCB** for one of the pinouts. In some cases, PCBs might conveniently provide the **Tag-Connect interface**, which is a clear indication that the board has a JTAG connector, too. You can see what that interface looks like at [https://www.tag-connect.com/info/](https://www.tag-connect.com/info/). Additionally, inspecting the **datasheets of the chipsets on the PCB** might reveal pinout diagrams that point to JTAG interfaces.

## SDW

SWD is an ARM-specific protocol designed for debugging.

The SWD interface requires **two pins**: a bidirectional **SWDIO** signal, which is the equivalent of JTAG’s **TDI and TDO pins and a clock**, and **SWCLK**, which is the equivalent of **TCK** in JTAG. Many devices support the **Serial Wire or JTAG Debug Port (SWJ-DP)**, a combined JTAG and SWD interface that enables you to connect either a SWD or JTAG probe to the target.

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
