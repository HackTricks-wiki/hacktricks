# ARM64 Basic Assembly

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

* **`sub sp, sp, #0x40`**: This instruction subtracts the hexadecimal value 0x40 (64 in decimal) from the stack pointer (`sp`). This effectively **reserves 64 bytes of space on the stack for local variables and saved registers**.
* **`stp x29, x30, [sp, #0x30]`**: The `stp` (store pair of registers) instruction **stores the values of the x29 and x30 registers into the memory locations pointed to by `sp` plus an offset of 0x30 (48 in decimal)**. In the context of this function prologue, **x29 is the frame pointer** and **x30 is the link register** (return address).
* **`add x29, sp, #0x30`**: This instruction **adds** the hexadecimal value **0x30** (48 in decimal) to the **stack pointer** and **stores** the result in the **x29 register**. In other words, it **sets the frame pointer (`x29`)** to point to the part of the stack where the function's frame begins.
* **`adrp x0, 0`**: The `adrp` (address of page) instruction computes the address of the 4KB page that contains the address given as the second operand, and stores that page address into the specified register (here, `x0`). In this case, the address is 0, so it's loading the address of the page containing the address 0 into `x0`. This is often used in conjunction with a following `add` or `ldr` instruction to form a complete address, but without that instruction, it's unclear exactly what is being referenced.
* **`bl 0x100003ec8`**: The `bl` (branch with link) instruction jumps to the subroutine located at the memory address `0x100003ec8`. In this case, the comment suggests that it's a "stub" for `printf`, a common function for formatted output in C. The "link" part of this instruction means that the return address (the next instruction after this `bl` instruction) is stored in the link register (`x30`), so the program knows where to return after the `printf` function completes.
*   **`add x0, x0, #0xf2a`**: This instruction adds the hexadecimal value `0xf2a` to the value currently stored in `x0`, and stores the result back in `x0`. The comment suggests that the resulting address points to the string "/tmp/hello-c.txt", probably located in the program's memory space. The `adrp` and `add` instructions together form an address pointing to this string.

    \


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
