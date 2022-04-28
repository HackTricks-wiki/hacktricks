# DHCPv6



|  DHCPv6 Message Type |  DHCPv4 Message Type |
| :--- | :--- |
|  Solicit \(1\) |  DHCPDISCOVER |
|  Advertise \(2\) |  DHCPOFFER |
|  Request \(3\), Renew \(5\), Rebind \(6\) |  DHCPREQUEST |
|  Reply \(7\) |  DHCPACK / DHCPNAK |
|  Release \(8\) |  DHCPRELEASE |
|  Information-Request \(11\) |  DHCPINFORM |
|  Decline \(9\) |  DHCPDECLINE |
|  Confirm \(4\) |  none |
|  Reconfigure \(10\) |  DHCPFORCERENEW |
|  Relay-Forw \(12\), Relay-Reply \(13\) |  none |

 SOLICIT \(1\)

 A DHCPv6 client sends a Solicit message to locate DHCPv6 servers. ADVERTISE \(2\)

 A server sends an Advertise message to indicate that it is available for DHCP service, in response to a Solicit message received from a client. REQUEST \(3\)

 A client sends a Request message to request configuration parameters, including IP addresses or delegated prefixes, from a specific server. CONFIRM \(4\)

 A client sends a Confirm message to any available server to determine whether the addresses it was assigned are still appropriate to the link to which the client is connected. This could happen when the client detects either a link-layer connectivity change or if it is powered on and one or more leases are still valid. The confirm message is used to confirm whether the client is still on the same link or whether it has been moved. The actual lease\(s\) are not validated; just the prefix portion of the addresses or delegated prefixes. RENEW \(5\)

 A client sends a Renew message to the server that originally provided the client's addresses and configuration parameters to extend the lifetimes on the addresses assigned to the client and to update other configuration parameters. REBIND \(6\)

 A client sends a Rebind message to any available server to extend the lifetimes on the addresses assigned to the client and to update other configuration parameters; this message is sent after a client receives no response to a Renew message. REPLY \(7\)

 A server sends a Reply message containing assigned addresses and configuration parameters in response to a Solicit, Request, Renew, Rebind message received from a client. A server sends a Reply message containing configuration parameters in response to an Information-request message. A server sends a Reply message in response to a Confirm message confirming or denying that the addresses assigned to the client are appropriate to the link to which the client is connected. A server sends a Reply message to acknowledge receipt of a Release or Decline message. RELEASE \(8\)

 A client sends a Release message to the server that assigned addresses to the client to indicate that the client will no longer use one or more of the assigned addresses. DECLINE \(9\)

 A client sends a Decline message to a server to indicate that the client has determined that one or more addresses assigned by the server are already in use on the link to which the client is connected. RECONFIGURE \(10\)

 A server sends a Reconfigure message to a client to inform the client that the server has new or updated configuration parameters, and that the client is to initiate a Renew/Reply or Information-request/Reply transaction with the server in order to receive the updated information. INFORMATION-REQUEST \(11\)

 A client sends an Information-request message to a server to request configuration parameters without the assignment of any IP addresses to the client. RELAY-FORW \(12\)

 A relay agent sends a Relay-forward message to relay messages to servers, either directly or through another relay agent. The received message, either a client message or a Relay-forward message from another relay agent, is encapsulated in an option in the Relay-forward message. RELAY-REPL \(13\)

 A server sends a Relay-reply message to a relay agent containing a message that the relay agent delivers to a client. The Relay-reply message may be relayed by other relay agents for delivery to the destination relay agent. The server encapsulates the client message as an option in the Relay-reply message, which the relay agent extracts and relays to the client.

