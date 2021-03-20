# xbcap2pcap

Converts packet capture files created by the Dashboard to pcap-files readable by Wireshark.

After a connection test has passed (or failed) on the Xbox Dashboard, pressing the Black button on the controller will save a packet log to the hard drive.

## Building
```sh
gcc -o xbcap2pcap xbcap2pcap.c
```

## Usage
```sh
./xbcap2pcap NetCapInfo.dat NetCapInfo.pcap
```
