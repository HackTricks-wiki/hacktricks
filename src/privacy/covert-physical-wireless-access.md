# Covert Physical and Wireless Access

Changing the network path can also change apparent physical origin. A sophisticated actor may use a nearby compromised system, a hidden device, public access, cellular backhaul or a satellite receiver so that target logs point away from the operator. None of these removes physical, radio or provider evidence; it moves attribution into different datasets.

## Technique matrix

| Technique | Apparent origin | Necessary condition | High-value evidence |
|---|---|---|---|
| Nearby wireless pivot | a business/home beside the target | compromised dual-homed host and target Wi-Fi access | neighbor-host endpoint logs, RF association and target RADIUS/DHCP |
| Public/guest network | venue NAT or tunnel exit | lawful access or access-control bypass | captive portal, DHCP, AP association, CCTV and payment/location records |
| Covert drop device | target/nearby wired, Wi-Fi or cellular address | physical placement or delivery | switchport/USB, RF, inventory, power and outbound tunnel telemetry |
| Cellular router/eSIM | carrier NAT or dedicated APN | modem/SIM/subscription | IMEI/IMSI/eSIM, cell-sector, carrier account and traffic timing |
| Satellite-link abuse | subscriber address in beam footprint | protocol- and service-specific weakness | RF location, uplink flow, impossible RTT/routing and provider records |

## Nearest-neighbor attack

Volexity documented a 2022 APT28/GRU operation in which the actor was remote from its ultimate target. It password-sprayed the target's public service to obtain valid credentials, but MFA prevented direct Internet login. The target's enterprise Wi-Fi accepted those credentials without MFA. The actor compromised organizations physically close to the target, found a dual-homed system with wireless reach, and used that system to authenticate to the target Wi-Fi. Volexity named this the **Nearest Neighbor Attack**.<sup>[[1]](#references)</sup>

```text
remote operator
      |
compromised organization C
      |
compromised organization B -- Wi-Fi radio --> target organization A
                                               |
                                        internal service
```

The novelty is the composition. No operator travels to the target and the Internet-facing service's MFA still works. The compromised neighbor supplies physical proximity; the stolen target credential supplies logical access; the target Wi-Fi becomes the boundary-crossing path.

### Preconditions and visibility

- A nearby system must be remotely controllable and have a compatible radio or access to another nearby pivot.
- The target SSID must reach that system, and Wi-Fi admission must accept a reusable credential/certificate/device state.
- The pivot often needs two simultaneous paths: one back to the operator and one into the target WLAN.
- The target may see a new station MAC and a legitimate username but no corresponding managed-device certificate, posture, history or expected building entry.
- Neighbor endpoint logs may show wireless scans, new profiles, interface changes, tunneling and remote-control activity.

### Detection and prevention

1. Require certificate-backed EAP-TLS and managed-device posture for enterprise Wi-Fi; do not make a password that failed MFA on the Internet sufficient merely because it arrives over radio.
2. Correlate RADIUS authentication with MDM/NAC identity, historical station/device binding, AP location, physical-access events and concurrent sessions.
3. Alert when an account associates for the first time, from an unusual AP edge, without a managed certificate, or while the same identity is active elsewhere.
4. Monitor endpoints capable of bridging interfaces. On Windows, Linux and network appliances, investigate unexpected WLAN profiles, forwarding/NAT configuration, virtual adapters and persistent tunnels.
5. Reduce unnecessary signal spill with sensible AP placement and power planning. This is a supporting control, not authentication.
6. Coordinate incident response with neighboring tenants: the final radio source may itself be a victim.

The [owned two-organization lab](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot) reproduces these observables without attacking a neighbor.

## Public venues and third-party Wi-Fi

Using café, hotel, airport or municipal Wi-Fi changes the IP shown to a destination. It does not create anonymity. The venue or its provider may retain AP association, device MAC, DHCP lease, captive-portal account, SMS/email validation and flow logs. Physical entry, CCTV, purchase, mobile-location and travel records can bridge the digital event to a person.

An actor may try to reduce one handle by using randomized MAC addresses, a separate device, cash or a tunnel. Cross-layer correlation remains possible through arrival time, repeated venue pattern, radio fingerprints, portal behavior, traffic timing, camera footage and the tunnel provider. A VPN also moves the destination from venue logs to VPN logs; it does not remove the venue's knowledge that the device was present.

Defenders of public access should isolate clients, block lateral traffic, use WPA2/3-Enterprise or per-device keys where feasible, retain proportionate DHCP/RADIUS/security logs, protect captive portals, and publish an abuse process. Red teams should use such a venue only when its terms and the engagement allow it; bypassing a portal, stealing access or targeting other guests is not an authorized testing shortcut.

## Covert drop devices and warshipping

A drop is a small system placed on or delivered into a site, then controlled through outbound Ethernet, Wi-Fi or cellular. “Warshipping” packages the device so ordinary delivery carries it inside the radio perimeter. Possible hardware ranges from a single-board computer to a modified charger, USB peripheral, network appliance or battery-powered modem.

Operational architecture:

```text
operator -> controlled rendezvous <- outbound encrypted tunnel <- drop
                                                        |
                                             scoped local interface
```

The device may provide a remote foothold, perform wireless measurements, emulate an authorized exercise peripheral, or relay traffic. Its apparent source is local, but it creates physical artifacts: serial numbers, packaging, fingerprints, cameras, access logs, power draw, USB descriptors, switchport negotiation, DHCP fingerprints, MAC OUI/randomization behavior, RF emissions and recurring rendezvous connections.

### Defensive controls

- Maintain receiving-room and asset-inventory procedures; inspect unexpected electronics and packages addressed to nonexistent staff.
- Use 802.1X/NAC on wired and wireless access, disable unused ports, and place unknown devices in a restricted remediation VLAN.
- Alert on new DHCP fingerprints, locally administered MACs that persist, new USB network/HID devices, unauthorized Wi-Fi Direct/Bluetooth and long-lived outbound tunnels.
- Baseline switchport, power-over-Ethernet, DNS and TLS behavior. A tiny host with no inventory record making periodic encrypted connections is higher-signal than “Raspberry Pi OUI” alone.
- During an exercise, inventory, label, scope, encrypt, provide a remote kill, set a retrieval deadline and ensure loss cannot expose reusable credentials.

## Cellular and eSIM backhaul

A cellular modem avoids the target's Internet gateway and can keep a drop reachable behind carrier NAT through an outbound rendezvous. Mobile addresses may rotate or be shared; the cellular operator still has strong subscriber and network evidence: SIM/eSIM identity, IMSI, device IMEI, assigned addresses/ports, cell/sector timing, account/payment and roaming records.

From the enterprise view, detect unexpected modems and personal hotspots with wireless/RF surveys, endpoint USB/PCI inventory, MDM restrictions, rogue-SSID monitoring and physical inspection. A drop that uses cellular for control can still be caught by its local Ethernet/Wi-Fi behavior and its radio emissions.

For authorized exercises, the organization should own the subscription and modem, record identifiers with the controller and validate that carrier/provider terms permit the traffic. A prepaid label or cryptocurrency purchase does not erase tower, device or retail records.

## MAC randomization and device fingerprinting

Modern systems can use a locally administered random MAC per network. This reduces passive long-term tracking by a stable factory MAC; it does not hide:

- probe/association timing and the set of requested network capabilities;
- 802.11 information elements, supported rates and vendor-specific behavior;
- DHCP options/hostname, IPv6 identifiers and captive-portal/browser fingerprint;
- authenticated 802.1X identity or certificate;
- higher-layer account, tunnel and traffic pattern; or
- physical observation.

Defenders should not use MAC allowlists as authentication. Join radio identity to certificate/device posture and treat changing MACs as normal unless other context is anomalous.

## Satellite-link hijacking

Kaspersky documented Turla using weaknesses in older one-way DVB-S satellite Internet. In the reported model, a legitimate remote subscriber sent outbound requests over a terrestrial link but received downstream data via an unencrypted wide-area satellite broadcast. An actor inside the satellite footprint could observe the downlink, choose an active subscriber IP and arrange for C2 replies to be addressed to that IP. Both the legitimate subscriber and actor received the broadcast; the actor extracted traffic for the selected port while the legitimate subscriber discarded unsolicited packets. The C2 operator then appeared to use a satellite-provider address in another geography.<sup>[[2]](#references)</sup>

```text
actor uplink request -> C2 server -> Internet -> satellite gateway
                                           satellite broadcast
                                  +--------------+-------------+
                                  |                            |
                         legitimate subscriber          actor receiver
```

This was protocol/service specific, bandwidth-constrained and not equivalent to compromising a modern bidirectional encrypted satellite terminal. It also did not hide the actor's outbound request path from a sufficiently capable observer. Detection opportunities include asymmetric/impossible routing, traffic to a subscriber that did not initiate the flow, unusual destination ports, provider telemetry, receiver location/RF investigation and malware configuration. Use this case to challenge the assumption that geolocating a C2 IP geolocates its controller—not as a build recipe.

## Physical-to-digital correlation worksheet

When an apparently local source is suspicious, build one timeline:

1. normalize AP, RADIUS, DHCP, DNS, proxy, VPN, EDR, switch and physical-access clocks;
2. identify the first radio association or link-up, not just the first alert;
3. map the station to certificate, device posture, DHCP fingerprint and switch/AP location;
4. look for simultaneous remote-control/tunnel activity on nearby systems;
5. review deliveries, visitors, inventory exceptions, cameras and RF findings under applicable policy/law;
6. preserve the suspected device and volatile network state; do not power-cycle blindly;
7. determine whether the apparent source is actor-controlled infrastructure or another victim.

## References

- [1] [Volexity — The Nearest Neighbor Attack: How a Russian APT weaponized nearby Wi-Fi networks](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [2] [Kaspersky Securelist — Satellite Turla: APT command and control in the sky](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [3] [MITRE ATT&CK — Hardware Additions (T1200)](https://attack.mitre.org/techniques/T1200/)
- [4] [NIST SP 800-153 — Guidelines for Securing Wireless Local Area Networks](https://csrc.nist.gov/pubs/sp/800/153/final)
