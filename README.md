# dpdk_gtp_module
DPDK implementation of GTPv1 user plane gateway.

### Features
- High speed GTP-U packet encapsulation and decapsulation
- Proxy ARP on behalf of UE IPs
- Packet statistics update on stdout
- Node socket aware memory config

# Build and run
Copy and edit config
```bash
cp gtp_config.example.ini gtp_config.ini
```

Make and run the program with EAL parameters
```bash
make
sudo ./build/gtpgw -l 0,1,2 -n 4
```

### References
- [vipinpv85/GTP_PKT_DECODE](https://github.com/vipinpv85/GTP_PKT_DECODE)
- [rajneshrat/dpdk-tcpipstack](https://github.com/rajneshrat/dpdk-tcpipstack)
