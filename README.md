# WOL Proxy

Simple Windows system tray application that listens for Wake‑on‑LAN magic packets and forwards them to a target machine.

## Motivation

I have a laptop and a desktop PC side by side, both connected via Wi‑Fi. The laptop runs 24/7 as a general server, and I access it remotely over VPN (WireGuard). I didn't want to keep the desktop always on or sleep, but I couldn't wake it remotely because it had no Ethernet connection — only Wi‑Fi.

So I connected the two machines with a simple Ethernet cable. The laptop runs this app, which listens for WoL packets arriving via VPN. When it catches one, it relays it over the Ethernet cable to wake up the desktop. Now I can connect to the VPN, send a WoL packet to the laptop, and the desktop powers on. I can then use Moonlight, RDC or whatever I need.

```mermaid
graph LR
    Remote[Remote device<br/>via VPN] -->|WoL packet| Laptop[Laptop<br/>WOL Proxy<br/>listening magic packets]
    Laptop -->|Ethernet relay| Desktop[Desktop<br/>wakes up]
```

## Requirements

- **Windows 10 / 11**
- **Npcap** – Download from [https://npcap.com](https://npcap.com). During installation, enable:
  - **"WinPcap API‑compatible Mode"**
  - **"Support raw 802.11 traffic"**

## How It Works

1. The app captures WoL packets sent to your trigger MAC address.
2. It automatically resends them to a second MAC address (the relay target).
3. Packets can arrive on any interface – Wi‑Fi, Ethernet, or VPN – thanks to Npcap.

## Usage

- Run `WolProxy.exe` as Administrator.
- Right‑click the tray icon to open **Settings**:
  - **WOL Trigger MAC** – the address to watch for incoming WoL packets.
  - **Relay Target MAC** – the destination that should wake up.
  - **Broadcast Address** – usually `255.255.255.255` (change if you use WireGuard, e.g. `10.253.1.255`).

Settings are saved automatically in the registry.

## Download

You can download the pre-built executable from the [here](https://github.com/MythB/WolProxy/releases/latest/download/WolProxy.exe).

## Build from Source

```bash
pip install -r requirements.txt
py -m PyInstaller --onefile --noconsole --icon=wol_proxy.ico --add-data "wol_proxy.ico;." --version-file=version_info.txt --collect-all scapy WolProxy.py
```