# LNClear Client Setup

`lnclear.sh` is the unified client script that sets up a WireGuard VPN tunnel for your Lightning node.
It auto-detects your platform and Lightning implementation, configures split-tunneling, and gets you on clearnet in under 5 minutes.

**Repo:** [github.com/lnclear/lnclear-client](https://github.com/lnclear/lnclear-client)

---

## Supported Platforms

| Platform         | LND | CLN | LiT | Notes |
|------------------|-----|-----|-----|-------|
| Bare Metal       | ✅  | ✅  | ✅  | Ubuntu/Debian 20.04+ |
| RaspiBlitz       | ✅  | ✅  | ✅  | v1.8.0+ |
| Umbrel           | ✅  | ⚠️  | ✅  | CLN requires extra docker-compose steps |
| myNode           | ✅  | ⚠️  | ❌  | LND verified; CLN experimental |
| RaspiBolt        | ✅  | ✅  | ✅  | |
| Start9 / Embassy | ⚠️  | ❌  | ❌  | Experimental, not fully verified |

---

## Setup (4 steps)

### 1. Subscribe & get your config

[Subscribe at lnclear.com](https://lnclear.com), pick a server, and pay with Lightning.
Your WireGuard keys are generated automatically. After payment, you'll get a `lnclear.conf` file with everything you need:

```ini
# LNClear WireGuard Config
# Your clearnet IP: eu-central.lnclear.com
# Your Lightning port: 48000
# Connect your node to: eu-central.lnclear.com:48000
```

### 2. Copy files to your node

```bash
# From your local machine
scp lnclear.conf lnclear.sh admin@your-node-ip:~/

# Or download the script directly on the node
wget -O lnclear.sh https://raw.githubusercontent.com/lnclear/lnclear-client/refs/heads/main/scripts/lnclear.sh
```

### 3. Run the setup script

Make sure your `lnclear.conf` is in the same directory as the script, then run:

```bash
sudo bash lnclear.sh
```

The wizard will check for the config file and guide you if it's missing. It will:

1. **Install WireGuard** and set up the VPN tunnel
2. **Configure split-tunneling** — only Lightning traffic goes through the VPN
3. **Update your Lightning config** with the clearnet IP and port
4. **Restart Lightning** and verify connectivity

> Tor stays active the whole time. Your node will be briefly offline (~30 sec) during the Lightning restart.

**Umbrel note:** WireGuard installs on the host, not inside Docker. After running the script, also enable **Hybrid Mode** in the Umbrel UI (Lightning → Settings → Advanced) and disable **Separate Tor Connections**.

### 4. Verify it's working

```bash
sudo bash lnclear.sh status
```

This checks your tunnel, outbound IP, Lightning port reachability, and announced addresses.

---

## Commands

```bash
sudo bash lnclear.sh              # Interactive setup (recommended)
sudo bash lnclear.sh status       # Check tunnel + node status
sudo bash lnclear.sh restart      # Restart tunnel (stops Lightning first to prevent IP leaks)
sudo bash lnclear.sh check        # Pre-flight compatibility check
sudo bash lnclear.sh update       # Update script to latest version
sudo bash lnclear.sh uninstall    # Remove tunnel, restore original config, back to Tor-only
```

---

## What is Split-Tunneling?

LNClear routes **only** your Lightning P2P traffic (port 9735) through the VPN, using Linux cgroups. Everything else — Tor, your browser, system updates — uses your regular connection.

This means:
- **Tor stays active** independently — if VPN drops, Tor picks up
- **System traffic** is never routed through our servers
- **Privacy is preserved** — only your node's public address changes

---

## Config File Format

Your `lnclear.conf` is a standard WireGuard config with LNClear metadata:

```ini
# LNClear WireGuard Config
# Your clearnet IP: eu-central.lnclear.com
# Your Lightning port: 48000
# Connect your node to: eu-central.lnclear.com:48000

[Interface]
PrivateKey = YOUR_PRIVATE_KEY
Address = 10.9.0.5/32
DNS = 1.1.1.1,1.0.0.1

[Peer]
PublicKey = SERVER_PUBLIC_KEY
Endpoint = eu-central.lnclear.com:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
```

The `# Your Lightning port` comment tells `lnclear.sh` which port to advertise in your Lightning config.

---

## Verifying Clearnet Mode

After install, verify your node is advertising the VPN address:

```bash
# LND
lncli getinfo | jq '.uris'
# Expected: ["PUBKEY@eu-central.lnclear.com:48000"]

# CLN
lightning-cli getinfo | jq '.address'
# Expected: [{"type":"ipv4","address":"...","port":48000}]
```

---

## Renewing Your Subscription

Before expiry, visit your [dashboard](https://lnclear.com/dashboard) and click **Renew**. Pay the invoice — your expiry extends automatically. No config changes or restart needed.

---

## Troubleshooting

### Node not announcing VPN address
- Check that `externalhosts` (LND) or `announce-addr` (CLN) was added to your config
- Path: shown in `lnclear.sh status` under "Lightning config"
- Restart: `sudo bash lnclear.sh restart`

### WireGuard handshake not completing
- Verify UDP 51820 is not blocked on your router/ISP
- Try `sudo wg show lnclear` — check if a handshake happened

### Split-tunneling not working
- Check cgroup: `cat /sys/fs/cgroup/net_cls/lnclear/net_cls.classid`
- Should return `0x00110011`
- If missing: `sudo systemctl restart lnclear-cgroup`

### Umbrel: Node still using home IP
- Go to Umbrel UI → Lightning → Settings → Advanced
- Enable **Hybrid Mode**, disable **Separate Tor Connections**
- Restart Lightning from the UI

---

## Uninstalling

```bash
sudo bash lnclear.sh uninstall
```

This:
1. Stops WireGuard
2. Removes `/etc/wireguard/lnclear.conf`
3. Restores your original Lightning config from backup
4. Removes the cgroup service
5. Restarts your Lightning node in Tor-only mode
