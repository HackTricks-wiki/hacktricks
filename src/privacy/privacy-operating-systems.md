# Privacy Operating Systems

Privacy-केंद्रित operating systems routing और persistence की गलतियों को कम करते हैं, लेकिन कोई भी system पहचान उजागर करने वाले व्यवहार या compromised hardware की भरपाई नहीं कर सकता।

## Isolation model चुनें

| System | सबसे उपयुक्त | Persistence | Network enforcement | मुख्य tradeoff |
|---|---|---|---|---|
| **Tor Browser on a maintained OS** | कभी-कभार anonymous web browsing | Browser state सामान्यतः session-scoped | केवल browser traffic | अन्य apps और host Tor से बाहर रहते हैं |
| **Tails** | Portable, amnesic, single-purpose sessions | Optional encrypted Persistent Storage | Internet traffic को Tor से होकर जाने के लिए बाध्य करता है | Reboots/workflow friction; firmware/hardware trust |
| **Whonix** | Forced Tor routing की आवश्यकता वाले persistent applications | Persistent VMs | Gateway/workstation split | Host/hypervisor और identity mixing फिर भी बनी रहती है |
| **Qubes-Whonix** | Advanced users के लिए मजबूत compartment separation | Per-qube | Dedicated network qubes और Whonix | Hardware requirements और operational complexity |

## Tails

Tails removable media से independently boot होता है, Internet traffic को Tor के माध्यम से route करता है और minimal local state छोड़ने के लिए designed है। इसकी अपनी warnings इस बात पर जोर देती हैं कि यह compromised BIOS/firmware/hardware, identifying disclosures, file metadata या दोनों सिरों को correlate करने वाले powerful observer से सुरक्षा नहीं दे सकता।<sup>[[1]](#references)</sup>

### Single-purpose Tails workflow

1. किसी trusted, updated computer पर official site से Tails download करें और official verification/install process का पालन करें।
2. केवल Tails boot करने के लिए supported USB drive का उपयोग करें; इसे general file-transfer drive के रूप में भी उपयोग न करें।
3. ऐसे hardware पर boot करें जिसे आप physically control करते हों। Live OS hardware keylogger या malicious firmware को neutralize नहीं कर सकता।
4. Persistent Storage को disabled रखें, जब तक workflow को वास्तव में इसकी आवश्यकता न हो। Enabled होने पर केवल आवश्यक categories को persist करें और strong passphrase का उपयोग करें।
5. किसी lawful network से connect करें। यदि captive portal unavoidable हो, तो portal के लिए ही Tails' Unsafe Browser का उपयोग करें, अनावश्यक identity disclose न करें, उसे तुरंत close करें और किसी भी sensitive activity से पहले Tor से connect करें।<sup>[[2]](#references)</sup>
6. यदि direct Tor visibility या blocking महत्वपूर्ण हो, तो Tor bridge configure करें।
7. **प्रत्येक session में एक contextual identity/purpose** रखें। Tails उन activities के बीच restart करने की recommendation देता है जिन्हें link नहीं किया जाना चाहिए।<sup>[[1]](#references)</sup>
8. Files को publish करने से पहले inspect और sanitize करें। Download किए गए active documents को ऐसी application में न खोलें जो intended context को bypass कर सके।
9. काम पूरा होने पर पूरी तरह shut down करें और USB को physically secure रखें।

## Whonix

Whonix एक Tor-routing **Gateway** को ऐसे **Workstation** से अलग करता है जिसकी applications external IP को सीधे learn नहीं कर सकतीं। यह proxy/DNS mistakes को काफी हद तक कम करता है, लेकिन host, hypervisor, behavior और documents फिर भी identity reveal कर सकते हैं। Whonix विशेष रूप से एक ही workstation को multiple identities के लिए उपयोग करने या anonymous और non-anonymous activity को combine करने से सावधान करता है।<sup>[[3]](#references)</sup>

### Compartment workflow

1. Official sources से Whonix image और virtualization platform verify करें।
2. उपयोग से पहले host, hypervisor, Gateway और Workstation को patch करें।
3. प्रत्येक identity या engagement के लिए fresh Workstation clone करें; identity-bearing state introduce होने के बाद कभी भी VM clone न करें।
4. Personal accounts, host shared folders, clipboard synchronization, USB devices और time/location data को Workstation से बाहर रखें।
5. Recovery के लिए snapshots का उपयोग करें, backups या identity separation के substitute के रूप में नहीं।
6. Confirm करें कि Gateway stopped होने पर Workstation Internet तक नहीं पहुँच सकता।
7. विशेष रूप से risky files के लिए disposable VM/qube का उपयोग करें और केवल sanitized result export करें।

## Qubes OS and Qubes-Whonix

Qubes Xen-backed qubes के साथ compartmentalization द्वारा security लागू करता है। इसका design एक domain में हुए compromise को automatically अन्य domains तक पहुँचने से सीमित करता है, लेकिन **same** qube के अंदर की applications एक-दूसरे से isolated नहीं होतीं।<sup>[[4]](#references)</sup> Disposable qubes untrusted sites, files और devices के लिए fresh state प्रदान करते हैं।<sup>[[5]](#references)</sup>

एक practical layout:
```text
vault-offline        keys, recovery codes; no network
personal             real-identity daily accounts
client-red-2026      engagement administration only
client-red-net       approved VPN/bastion routing
anon-research        Qubes-Whonix Workstation
anon-research-net    Whonix Gateway
disp-untrusted       links and document rendering
```
नियम:

- प्रत्येक qube को एक trust level और identity purpose दें।
- secrets को offline vault qube में रखें और स्पष्ट inter-qube copy/file operations का उपयोग करें।
- अनचाही files और links को disposables में खोलें।
- केवल इच्छित qubes को Whonix या dedicated VPN qube के माध्यम से route करें।
- windows को स्पष्ट रूप से अलग-अलग label करें और sensitive work के दौरान असंबंधित qubes को रोक दें।
- यह न मानें कि दो qubes correlation को रोकते हैं, यदि वे accounts, content, schedules या payments साझा करते हैं।

## Verification and maintenance

- आधिकारिक instructions के माध्यम से installer signatures/checksums verify करें।
- पहले templates को patch करें, फिर dependent qubes/VMs को restart करें।
- network-deny behavior, DNS, IPv6, clock, clipboard, shared directories और USB assignment की पुष्टि करें।
- पुराने identity-bearing data के लिए Persistent Storage और VM snapshots की समीक्षा करें।
- seeds/keys के encrypted offline backups रखें और isolated environment में restoration का परीक्षण करें।
- suspected compromise के बाद compartment को फिर से बनाएं; उसका egress IP बदलना पर्याप्त नहीं है।

## References

- [1] [Tails — Warnings: Tails सुरक्षित है, लेकिन जादुई नहीं](https://tails.net/doc/about/warnings/index.en.html)
- [2] [Tails — captive portal का उपयोग करके network में sign in करना](https://tails.net/doc/anonymous_internet/unsafe_browser/index.en.html)
- [3] [Whonix — Whonix और Tor की limitations](https://www.whonix.org/wiki/Warning)
- [4] [Qubes OS — Security design goals](https://doc.qubes-os.org/en/latest/developer/system/security-design-goals.html)
- [5] [Qubes OS — disposables का उपयोग कैसे करें](https://doc.qubes-os.org/en/latest/user/how-to-guides/how-to-use-disposables.html)
