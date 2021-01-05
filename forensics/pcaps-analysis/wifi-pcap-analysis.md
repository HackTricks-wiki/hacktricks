# Wifi Pcap Analysis

## Check BSSIDs

When you receive a capture whose principal traffic is Wifi using WireShark you can start investigating all the SSIDs of the capture with _Wireless --&gt; WLAN Traffic_:

![](../../.gitbook/assets/image%20%28426%29.png)

![](../../.gitbook/assets/image%20%28429%29.png)

### Brute Force

One of the columns of that screen indicates if **any authentication was found inside the pcap**. If that is the case you can try to Brute force it using `aircrack-ng`:

```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```

## Data in Beacons / Side Channel

If you suspect that **data is being leaked inside beacons of a Wifi network** you can check the beacons of the network using a filter like the following one: `wlan contains <NAMEofNETWORK>`, or `wlan.ssid == "NAMEofNETWORK"` search inside the filtered packets for suspicious strings.

## Find unknown MAC addresses in a Wiffi network

The following link will be useful to find the **machines sending data inside a Wifi Network**:

* `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

If you already know **MAC addresses you can remove them from the output** adding checks like this one: `&& !(wlan.addr==5c:51:88:31:a0:3b)`

Once you have detected **unknown MAC** addresses communicating inside the network you can use **filters** like the following one: `wlan.addr==<MAC address> && (ftp || http || ssh || telnet)` to filter its traffic. Note that ftp/http/ssh/telnet filters are useful if you have decrypted the traffic.

## Decrypt Traffic

Edit --&gt; Preferences --&gt; Protocols --&gt; IEEE 802.11--&gt; Edit

![](../../.gitbook/assets/image%20%28427%29.png)





