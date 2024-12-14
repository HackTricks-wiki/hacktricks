# macOS .Net Applications Injection

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

**This is a summary of the post [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/). Check it for further details!**

## .NET Core Debugging <a href="#net-core-debugging" id="net-core-debugging"></a>

### **Establishing a Debugging Session** <a href="#net-core-debugging" id="net-core-debugging"></a>

The handling of communication between debugger and debuggee in .NET is managed by [**dbgtransportsession.cpp**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp). This component sets up two named pipes per .NET process as seen in [dbgtransportsession.cpp#L127](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L127), which are initiated via [twowaypipe.cpp#L27](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/debug-pal/unix/twowaypipe.cpp#L27). These pipes are suffixed with **`-in`** and **`-out`**.

By visiting the user's **`$TMPDIR`**, one can find debugging FIFOs available for debugging .Net applications.

[**DbgTransportSession::TransportWorker**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L1259) is responsible for managing communication from a debugger. To initiate a new debugging session, a debugger must send a message via the `out` pipe starting with a `MessageHeader` struct, detailed in the .NET source code:

```c
struct MessageHeader {
    MessageType   m_eType;        // Message type
    DWORD         m_cbDataBlock;  // Size of following data block (can be zero)
    DWORD         m_dwId;         // Message ID from sender
    DWORD         m_dwReplyId;    // Reply-to Message ID
    DWORD         m_dwLastSeenId; // Last seen Message ID by sender
    DWORD         m_dwReserved;   // Reserved for future (initialize to zero)
        union {
            struct {
                DWORD         m_dwMajorVersion;   // Requested/accepted protocol version
                DWORD         m_dwMinorVersion;
            } VersionInfo;
          ...
        } TypeSpecificData;
    BYTE          m_sMustBeZero[8];
}
```

To request a new session, this struct is populated as follows, setting the message type to `MT_SessionRequest` and the protocol version to the current version:

```c
static const DWORD kCurrentMajorVersion = 2;
static const DWORD kCurrentMinorVersion = 0;

// Configure the message type and version
sSendHeader.m_eType = MT_SessionRequest;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMajorVersion = kCurrentMajorVersion;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMinorVersion = kCurrentMinorVersion;
sSendHeader.m_cbDataBlock = sizeof(SessionRequestData);
```

This header is then sent over to the target using the `write` syscall, followed by the `sessionRequestData` struct containing a GUID for the session:

```c
write(wr, &sSendHeader, sizeof(MessageHeader));
memset(&sDataBlock.m_sSessionID, 9, sizeof(SessionRequestData));
write(wr, &sDataBlock, sizeof(SessionRequestData));
```

A read operation on the `out` pipe confirms the success or failure of the debugging session establishment:

```c
read(rd, &sReceiveHeader, sizeof(MessageHeader));
```

## Reading Memory
Once a debugging session is established, memory can be read using the [`MT_ReadMemory`](https://github.com/dotnet/runtime/blob/f3a45a91441cf938765bafc795cbf4885cad8800/src/coreclr/src/debug/shared/dbgtransportsession.cpp#L1896) message type. The function readMemory is detailed, performing the necessary steps to send a read request and retrieve the response:

```c
bool readMemory(void *addr, int len, unsigned char **output) {
// Allocation and initialization
...
// Write header and read response
...
// Read the memory from the debuggee
...
return true;
}
```

The complete proof of concept (POC) is available [here](https://gist.github.com/xpn/95eefc14918998853f6e0ab48d9f7b0b).

## Writing Memory

Similarly, memory can be written using the `writeMemory` function. The process involves setting the message type to `MT_WriteMemory`, specifying the address and length of the data, and then sending the data:

```c
bool writeMemory(void *addr, int len, unsigned char *input) {
// Increment IDs, set message type, and specify memory location
...
// Write header and data, then read the response
...
// Confirm memory write was successful
...
return true;
}
```

The associated POC is available [here](https://gist.github.com/xpn/7c3040a7398808747e158a25745380a5).

## .NET Core Code Execution <a href="#net-core-code-execution" id="net-core-code-execution"></a>

To execute code, one needs to identify a memory region with rwx permissions, which can be done using vmmap -pages:

```bash
vmmap -pages [pid]
vmmap -pages 35829 | grep "rwx/rwx"
```

Locating a place to overwrite a function pointer is necessary, and in .NET Core, this can be done by targeting the **Dynamic Function Table (DFT)**. This table, detailed in [`jithelpers.h`](https://github.com/dotnet/runtime/blob/6072e4d3a7a2a1493f514cdf4be75a3d56580e84/src/coreclr/src/inc/jithelpers.h), is used by the runtime for JIT compilation helper functions.

For x64 systems, signature hunting can be used to find a reference to the symbol `_hlpDynamicFuncTable` in `libcorclr.dll`.

The `MT_GetDCB` debugger function provides useful information, including the address of a helper function, `m_helperRemoteStartAddr`, indicating the location of `libcorclr.dll` in the process memory. This address is then used to start a search for the DFT and overwrite a function pointer with the shellcode's address.

The full POC code for injection into PowerShell is accessible [here](https://gist.github.com/xpn/b427998c8b3924ab1d63c89d273734b6).

## References

* [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/)

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

