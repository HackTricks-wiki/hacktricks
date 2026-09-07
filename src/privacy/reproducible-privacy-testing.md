# Reproducible Privacy Testing

A privacy setup is not finished when it connects. It is finished when its claimed boundary has been tested under normal use, failure, recovery and teardown. Test against infrastructure you own or are authorized to inspect; public “leak test” sites become another observer.

## Build a small authorized test environment

Use three roles, ideally on separate providers/networks:

```text
operator endpoint ---- privacy path ---- owned web/DNS endpoint
       |                                      |
local packet/route view                 server-side logs
       |
controller/provider dashboards and payment/account records
```

Record before each test:

- test ID, UTC start/end, operator and authorization;
- endpoint/OS/client versions and configuration hash;
- expected IPv4, IPv6, DNS, TLS, account, payment and physical observations;
- which logs will be inspected and their clocks/time zones;
- pass/fail rule and teardown time.

Never test a sensitive identity first. Use a synthetic account and benign unique canary values owned by the tester.

## Network-path test

### 1. Capture the baseline

Before enabling the privacy path, record local routes and resolvers:

```bash
ip route
ip -6 route
resolvectl status
```

On macOS use `route -n get default`, `netstat -rn -f inet6`, and `scutil --dns`. Save the output only in the controlled evidence store; it can contain local identifiers.

### 2. Connect and inspect routing

Enable the VPN/Tor/workload namespace, then check the route selected for controlled public addresses:

```bash
ip route get 192.0.2.10
ip -6 route get 2001:db8::10
```

Replace documentation addresses with the test server addresses. Confirm that the selected interface/table matches the design.

### 3. Observe from both ends

Set the URL of the owned endpoint, then request a unique benign path:

```bash
: "${PRIVACY_TEST_URL:?Set PRIVACY_TEST_URL to the owned HTTPS endpoint}"
curl --fail --show-error --silent \
  "${PRIVACY_TEST_URL}/privacy-check/run-20260907-001"
```

Use a real tester-controlled domain, authenticated TLS and a non-sensitive path token. Inspect the server log for:

- source address/ASN and expected egress;
- IPv4 versus IPv6;
- Host/SNI behavior visible at the endpoint;
- user agent and application headers;
- exact time and request reuse.

Do not add `X-Forwarded-For`, unique debug headers or identity-bearing cookies to a supposedly separated request.

### 4. Test DNS with an owned canary

Configure an authoritative test zone whose query logs you control. Query a unique random label through the compartment:

```bash
dig run-20260907-001.privacy-test.example A
dig run-20260907-001.privacy-test.example AAAA
```

Inspect the authoritative log. It normally sees the recursive resolver, not necessarily the client. Compare that resolver with the intended VPN/Tor/application DNS design. A random public DNS leak site is not required.

### 5. Test fail-closed behavior

Keep a benign request loop aimed at the owned endpoint, then stop the privacy path. The workload must fail rather than switch to a physical interface. Check both address families and DNS:

```bash
: "${PRIVACY_TEST_URL:?Set PRIVACY_TEST_URL to the owned HTTPS endpoint}"
curl -4 --connect-timeout 5 "${PRIVACY_TEST_URL}/run-v4"
curl -6 --connect-timeout 5 "${PRIVACY_TEST_URL}/run-v6"
dig privacy-test.example
```

Repeat during:

- tunnel process crash;
- Wi-Fi-to-Ethernet or hotspot switch;
- sleep/wake;
- DHCP renewal;
- captive-portal state;
- provider reconnect/key expiry.

For a Linux namespace/container, stop its tunnel and verify it has no other default route or resolver:

```bash
ip netns exec privacy-workload ip route
ip netns exec privacy-workload ip -6 route
ip netns exec privacy-workload resolvectl status
```

Names and commands vary by deployment. Do not paste them into a remote production host without console recovery.

### 6. Inspect local sockets and packets

With authorization, check which process/interface actually communicates:

```bash
ss -tpn
ss -upn
sudo tcpdump -ni any 'host TEST_SERVER_IP'
```

Replace `TEST_SERVER_IP` with the explicit owned address; avoid broad capture of unrelated users. The physical interface should see the tunnel/bridge peer, while clear destination traffic should exist only at the intended layer.

## Tor and onion-service test

1. In Tor Browser, visit the Tor Project connection check and confirm Tor use. Do not treat this as identity proof.<sup>[[1]](#references)</sup>
2. Visit the owned HTTPS endpoint with a unique canary and confirm it sees a Tor exit, no identifying cookies, and the standard browser context.
3. Select **New Identity**, revisit with a different canary, and verify local state was cleared as expected. Exit IP change is not guaranteed or the purpose of New Identity.
4. For an onion service, access it only through Tor Browser. Confirm the service host has no public listener with an authorized external scan and that application responses contain no public hostname/IP.
5. Inspect origin outbound DNS/HTTP, templates, error pages, email/webhooks and third-party assets. Any direct fetch can disclose the origin or operator account.
6. If client authorization is enabled, confirm an uncredentialed clean Tor Browser cannot connect and a credentialed one can.
7. Rotate a test authorization key and confirm the revoked client loses access without changing the onion identity.

## Browser-compartment test

Create a controlled page that records only the fields needed for the test, with a short retention period. Compare personal and privacy compartments for:

- cookies/local storage/service workers and cache;
- browser sync/login state;
- language, time zone, screen/window dimensions and fonts;
- WebRTC/network candidates;
- permissions and extension-visible modifications;
- TLS/HTTP user-agent data at the server.

Do not attempt to make Tor Browser “more random.” The pass condition is similarity to its standard anonymity set and absence of personal state, not maximum difference from the personal browser.

Test copy/paste, drag/drop, downloaded-file opening, password-manager suggestions and identity-provider buttons. These are frequent bridges between compartments.

## Operating-system isolation test

### Tails

1. Start with a benign file/canary in a session without Persistent Storage.
2. Shut down fully, reboot, and confirm it is gone.
3. Enable only one required persistence category, repeat, and confirm unrelated browser/application state is not retained.
4. Verify the Unsafe Browser cannot be used after portal login for sensitive activity and that Tor applications reconnect normally.

### Whonix/Qubes

1. Stop the Gateway/net qube and prove the Workstation/app qube cannot reach IPv4, IPv6 or DNS.
2. Attempt only the explicitly configured inter-qube clipboard/file path and confirm other shared-folder/device paths are absent.
3. Open a benign test document in a disposable qube, close it, and confirm its state disappears.
4. Check that the vault qube has no NetVM and cannot acquire one through a template/default change.
5. Snapshot/restore a test VM and inspect whether identity-bearing state unexpectedly returns.

## Communications metadata test

For each selected messenger:

1. Create test-only participants on controlled devices.
2. Record what registration requires: phone, app-store account, IP, push service, username or invitation.
3. Send one benign message while inspecting notification previews, linked desktops, wearables and backups.
4. Verify safety/security codes over an independent path.
5. Disable receipts/push or enable Tor/local transports one at a time and observe reliability/metadata changes.
6. Export or restore a test backup and document exactly which profile, contacts and history it contains.
7. Lose/revoke a test device and confirm the remaining participants see the expected key/device change.

Do not test by contacting uninvolved people or generating abusive traffic.

## File-sanitization test

1. Hash and preserve the original in encrypted evidence storage:

```bash
sha256sum ./original/file > ./original/file.sha256
```

2. Create a cleaned copy using the format-specific process in [Privacy-Preserving Communications and Sharing](privacy-preserving-communications-and-sharing.md).
3. Compare metadata inventories:

```bash
exiftool -a -u -g1 ./original/file
exiftool -a -u -g1 ./clean/file
```

4. Render/open the copy in a disposable context. Check hidden content, attachments, links, forms, layers, thumbnails and visual identifiers.
5. Search only the staged copy for known canary author/email/path strings.
6. Hash the final output and have a second person verify the exact file being published.

Absence from ExifTool output is not proof of anonymity; format internals, pixels, prose and distribution records remain.

## Payment privacy test

Use the smallest permitted amount or an official test network/sandbox:

1. Write the expected view for payer, payee/merchant, issuer/exchange, network/node, public ledger and accountant/controller.
2. Create a unique test invoice/merchant context without false identity.
3. Pay once, then collect **your own** receipt, statement, merchant dashboard, wallet/node log and public-chain view where applicable.
4. Check whether the amount, timestamp, address/token, account, IP/device, delivery and refund route match the observer table.
5. For Bitcoin, inspect address reuse, selected inputs, change and later consolidation in the wallet's coin-control view.
6. For shielded protocols, verify the actual pool/path and what a viewing key reveals; do not infer privacy from wallet branding.
7. For e-cash/Taler, test backup/recovery, refund and redemption with small value; document mint/exchange/federation boundary records.
8. Revoke a virtual card/test credential and confirm later authorization fails while legitimate refund handling remains understood.
9. Reconcile and retain required tax/authorization evidence encrypted.

Never create circular transfers, threshold-splitting, fake purchases or suspicious refunds as a “privacy test.”

## Authorized red-team accountability drill

Before the exercise, run a tabletop and technical drill:

1. An operator launches a benign canary from each approved source path.
2. The target SOC records what it detects without receiving operator identity if blind testing is intended.
3. The exercise controller resolves source → engagement → operator from the escrowed map and signed job record.
4. The controller sends the emergency stop; operator and infrastructure owner demonstrate shutdown within the ROE time.
5. Provider abuse receives the correct 24/7 contact and authorization reference.
6. Evidence shows the target, time, tool/job and operator without retaining unnecessary payload content.
7. A second operator verifies credential revocation and resource teardown.

Fail the readiness review if the SOC can trivially see personal/home infrastructure **or** if the controller cannot rapidly attribute and stop the source.

## Test record template

```text
Test ID / date (UTC):
Authorization / owner:
Claim under test:
Expected observers:
Endpoint + versions:
Configuration hash:
Normal result:
Failure/reconnect result:
Server/provider/account evidence:
Unexpected linkage:
Pass/fail:
Remediation + retest ID:
Evidence retention/deletion date:
```

## References

- [1] [Tor Project — Connection check](https://check.torproject.org/)
- [2] [WireGuard — Routing and Network Namespaces](https://www.wireguard.com/netns/)
- [3] [ExifTool — FAQ and metadata guidance](https://exiftool.org/faq.html)
- [4] [NIST SP 800-115 — Technical Guide to Information Security Testing and Assessment](https://csrc.nist.gov/pubs/sp/800/115/final)
