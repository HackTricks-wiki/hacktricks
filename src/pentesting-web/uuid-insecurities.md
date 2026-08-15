# UUID Insecurities

{{#include ../banners/hacktricks-training.md}}

## Basic Information

Universally Unique Identifiers (UUIDs) are **128-bit numbers used to uniquely identify information** in computer systems. UUIDs are essential in applications where unique identifiers are necessary without central coordination. They are commonly used as database keys and can refer to various elements like documents and sessions.<sup>[[1]](#references)</sup>

UUIDs are designed primarily for uniqueness, **not secrecy or authorization**. Some versions are predictable, and even a random UUID must not replace an access-control check. The conventional text form contains 32 hexadecimal digits in five groups.<sup>[[2]](#references)</sup>

- **UUID v1** is time-based, incorporating a timestamp, clock sequence, and node value; implementations may use a MAC address and expose system information.
- **UUID v2** is a DCE Security variant derived from v1 and is not specified by current RFC 9562.
- **UUID v3 and v5** generate UUIDs using hash values from namespace and name, with v3 using MD5 and v5 using SHA-1.
- **UUID v4** carries 122 random bits when produced by a conforming cryptographically secure generator. Guessing risk depends on generator quality and token lifetime, not only the nominal format.<sup>[[2]](#references)</sup>

> [!TIP]
> The version and **variant** occupy fixed bit positions in RFC UUIDs. For example:\
> 12345678 - abcd - 1a56 - a539 - 103755193864\
> xxxxxxxx - xxxx - Mxxx - Nxxx - xxxxxxxxxxxx
>
> - The **position of `M`** indicates the UUID **version**. In the example above, it is UUID v**1**.
> - The **position of `N`** indicates the UUID variant.

## Sandwich attack

The "Sandwich Attack" is a specific type of attack that **exploits the predictability of UUID v1 generation in web applications**, particularly in features like password resets. UUID v1 is generated based on time, clock sequence, and the node's MAC address, which can make it somewhat predictable if an attacker can obtain some of these UUIDs generated close in time.<sup>[[1]](#references)</sup>

### Example

Imagine a web application that uses UUID v1 for generating password reset links. Here’s how an attacker might exploit this to gain unauthorized access:

1. **Initial Setup**:

- The attacker has control over two email accounts: \`attacker1@acme.com\` and \`attacker2@acme.com\`.
- The target's email account is \`victim@acme.com\`.

2. **Execution**:

- The attacker triggers a password reset for their first account (\`attacker1@acme.com\`) and receives a password reset link with a UUID, say \`99874128-7592-11e9-8201-bb2f15014a14\`.
- Immediately after, the attacker triggers a password reset for the victim's account (\`victim@acme.com\`) and then quickly for the second attacker-controlled account (\`attacker2@acme.com\`).
- The attacker receives a reset link for the second account with a UUID, say \`998796b4-7592-11e9-8201-bb2f15014a14\`.

3. **Analysis**:

- The attacker now has two UUIDs generated close in time (\`99874128\` and \`998796b4\`). Given the sequential nature of time-based UUIDs, the UUID for the victim's account will likely fall between these two values.

4. **Brute Force Attack:**

- The attacker uses a tool to generate UUIDs between these two values and tests each generated UUID by attempting to access the password reset link (e.g., \`https://www.acme.com/reset/\<generated-UUID>\`).
- If the web application does not adequately rate limit or block such attempts, the attacker can quickly test all possible UUIDs in the range.

5. **Access Gained:**

- Once the correct UUID for the victim's password reset link is discovered, the attacker can reset the victim's password and gain unauthorized access to their account.

### Tools

- The `sandwich` tool automates candidate generation between two observed UUIDv1 values.<sup>[[3]](#references)</sup>
- Burp Suite's UUID Detector extension identifies UUIDs and highlights their version/variant during proxy analysis.<sup>[[4]](#references)</sup>

## References

- [1] [VerSprite - Universally Unique Identifiers](https://versprite.com/blog/universally-unique-identifiers/)
- [2] [RFC 9562 — Universally Unique IDentifiers (UUIDs)](https://www.rfc-editor.org/rfc/rfc9562.html)
- [3] [Lupin-Holmes/sandwich](https://github.com/Lupin-Holmes/sandwich)
- [4] [PortSwigger BApp Store — UUID Detector](https://portswigger.net/bappstore/65f32f209a72480ea5f1a0dac4f38248)

{{#include ../banners/hacktricks-training.md}}
