# SIPcord Bridge

This is a slice of the code that powers [SIPcord](https://sipcord.net/) that you can use to self host something similar. It's not the full SIPcord package but rather the core functionality used in SIPcord with ways to build your own backend adapter. SIPcord itself uses this as a component of the full build so the code is the same that runs on the public bridges.

This means you have to build the call routing backend yourself. I am including a `static-router` backend which you can use to map extensions in a TOML file like this
```toml
[extensions]
1000 = { guild = 123456789012345620, channel = 987654321012345620 }
2000 = { guild = 123456789012345620, channel = 111222333444555620 }
```
but if you want more fancy routing you have to build it. You can easily use sipcord-bridge as a library and provide your own routers by implementing the `Backend` trait.

This was written a mix between myself and claude, sure, some of it's big slop but the parts I care about are not.

### Can you help me set this up?

**No.** I am not providing support for this as my goal is to run [sipcord.net](https://sipcord.net/), not support self hosting. If you want to run this self hosted, feel free to use this code but you are on your own here.

### I have a feature request!

**PR's welcome**. No really, feel free to implement it and contribute.

## AI Generated Setup Instructions

These instructions were written by Claude. They might be wrong. Remember — no support is provided.

### Prerequisites

- A Discord bot with voice permissions. Create one at https://discord.com/developers/applications, enable the **Message Content** intent, and grab the bot token.
- A server with a public IP (or port-forwarded UDP). SIP uses UDP 5060 and RTP uses UDP 10000-15000 by default.
- Docker (recommended) or Rust nightly toolchain if building from source.

### 1. Invite the bot to your server

Use this URL format, replacing `YOUR_CLIENT_ID`:
```
https://discord.com/oauth2/authorize?client_id=YOUR_CLIENT_ID&scope=bot&permissions=36701184
```
The bot needs View Channel + Connect + Speak permissions in voice channels.

### 2. Get Discord channel IDs

Enable Developer Mode in Discord (Settings > App Settings > Advanced > Developer Mode). Right-click a voice channel and click "Copy Channel ID". Do the same for the server (guild) by right-clicking the server name.

### 3. Create the dialplan

Create a `dialplan.toml` mapping extensions to Discord channels:

```toml
[extensions]
1000 = { guild = 123456789012345678, channel = 987654321012345678 }
2000 = { guild = 123456789012345678, channel = 111222333444555666 }
```

Each extension is what you'll dial from your SIP phone. Pick any numbers you like.

### 4a. Run with Docker (recommended)

Create a directory for your deployment:

```bash
mkdir sipcord && cd sipcord
```

Create a `.env` file:

```env
DISCORD_BOT_TOKEN=your_bot_token_here
SIP_PUBLIC_HOST=your.server.ip.or.hostname
```

Create a `docker-compose.yml`:

```yaml
services:
  sipcord-bridge:
    image: ghcr.io/coral/sipcord-bridge:latest
    container_name: sipcord-bridge
    restart: always
    network_mode: host
    env_file:
      - .env
    volumes:
      - ./dialplan.toml:/app/dialplan.toml:ro
      # Uncomment to persist data across restarts:
      # - ./data:/var/lib/sipcord
```

Place your `dialplan.toml` in the same directory, then:

```bash
docker compose up -d
docker logs -f sipcord-bridge
```

You should see it load the dialplan and start listening.

### 4b. Build from source

Requires Rust nightly (for `portable_simd`) and system dependencies for pjproject (OpenSSL, Opus, libtiff, etc). See the `Dockerfile` for the full list.

```bash
cargo run --release -p sipcord-bridge
```

The binary reads `config.toml` from the working directory (or `CONFIG_PATH`), the dialplan from `./dialplan.toml` (or `DIALPLAN_PATH`), and sound files from `./wav/` (or `SOUNDS_DIR`).

### 5. Configure your SIP phone

Point your SIP client at your server's IP on port 5060 (UDP). The static router does **not** perform authentication, so any SIP client can connect — just dial the extension number you configured.

Example Oink (or any softphone) setup:
- **SIP Server:** `your.server.ip`
- **Port:** `5060`
- **Transport:** `UDP`
- **Username/Password:** anything (ignored by static router)

Dial `1000` (or whatever you put in `dialplan.toml`) and you should hear the bot join the Discord voice channel.

### Environment variables reference

| Variable | Default | Description |
|----------|---------|-------------|
| `DISCORD_BOT_TOKEN` | *(required)* | Discord bot token |
| `SIP_PUBLIC_HOST` | *(required)* | Public IP/hostname for SIP |
| `SIP_PORT` | `5060` | SIP listening port |
| `RTP_PORT_START` | `10000` | Start of RTP port range |
| `RTP_PORT_END` | `15000` | End of RTP port range |
| `RTP_PUBLIC_IP` | *(same as SIP_PUBLIC_HOST)* | Public IP for RTP media (if different from SIP) |
| `CONFIG_PATH` | `./config.toml` | Path to config.toml |
| `DIALPLAN_PATH` | `./dialplan.toml` | Path to dialplan.toml |
| `SOUNDS_DIR` | `./wav` | Path to sound files directory |
| `DATA_DIR` | `/var/lib/sipcord` | Persistent data directory |
| `DEV_MODE` | `false` | Enable dev mode logging |
| `RUST_LOG` | `sipcord_bridge=info,pjsip=warn` | Log level filter |

### NAT / Firewall notes

If your server is behind NAT, you need to:
- Forward UDP port 5060 (SIP signaling)
- Forward UDP ports 10000-15000 (RTP media)
- Set `SIP_PUBLIC_HOST` to your *public* IP
- If the public IP for RTP differs from SIP, also set `RTP_PUBLIC_IP`

For servers with both a public and private interface (e.g. behind a load balancer), you can set `SIP_LOCAL_HOST` and `SIP_LOCAL_CIDR` so local clients get the private IP in Contact headers:

```env
SIP_LOCAL_HOST=192.168.1.100
SIP_LOCAL_CIDR=192.168.1.0/24
```

### Fax support

The bridge can receive faxes (both G.711 passthrough and T.38 UDPTL). Received faxes are demodulated via SpanDSP and posted as PNG images to a Discord text channel. To set up fax, add a mapping with a text channel ID in your dialplan — the bridge routes faxes to text channels and voice calls to voice channels automatically.

### Acknowledgements

- Thanks to [dusthillguy](https://dusthillguy-music-blog1.tumblr.com/) for letting me use the song [*"Joona Kouvolalainen buttermilk"*](https://www.youtube.com/watch?v=IK1ydvw3xkU) as hold music.
- Thanks to [wberg](https://wberg.com/) for hosting `bridge-eu1`
- Thanks to [chrischrome](https://litenet.tel/) for hosting `bridge-use1`

### License

Code is AGPLv3

Dusthillguy track is whatever dusthillguy wishes
