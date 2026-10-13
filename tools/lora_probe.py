#!/usr/bin/env python3
"""Show what a Meshtastic node plugged into this computer hands over.

It answers one question for Tripline: do packets from channels we hold no key for (other
people's private meshes) reach the computer, so their sender and signal strength can be used
as proximity evidence?

    python3 tools/lora_probe.py [--port /dev/ttyUSB0] [--minutes 10]

One line is printed per packet, then a summary. Message text and positions are never printed,
and channel keys are never read.

Needs the Meshtastic library:  python3 -m venv ~/lora-venv && ~/lora-venv/bin/pip install meshtastic
"""
import argparse
import sys
import time


class Probe:
    """Collects packets as the Meshtastic library delivers them (as dicts)."""

    def __init__(self):
        self.decoded = self.encrypted = 0
        self.senders = {}

    def handle(self, packet, now=None):
        """Record one packet and return the line to print."""
        now = time.time() if now is None else now
        sender = "!%08x" % packet["from"] if isinstance(packet.get("from"), int) else "?"
        enc = "decoded" not in packet
        dec = packet.get("decoded") or {}
        kind = "ENCRYPTED" if enc else str(dec.get("portnum", "?"))
        hs, hl = packet.get("hopStart"), packet.get("hopLimit")
        hops = hs - hl if isinstance(hs, int) and isinstance(hl, int) and hs >= hl else None
        rssi, snr = packet.get("rxRssi"), packet.get("rxSnr")
        name = (dec.get("user") or {}).get("longName") if not enc else None
        if enc:
            self.encrypted += 1
        else:
            self.decoded += 1
        s = self.senders.setdefault(sender, {"n": 0, "enc": 0, "best": None, "direct": False, "name": None})
        s["n"] += 1
        s["enc"] += enc
        s["direct"] = s["direct"] or hops == 0
        s["name"] = name or s["name"]
        if isinstance(rssi, (int, float)) and rssi != 0 and (s["best"] is None or rssi > s["best"]):
            s["best"] = rssi
        chan = ("hash=%s" % packet.get("channel")) if enc else ("ch=%s" % packet.get("channel", 0))
        return "%s  %-10s  %-14s  %-9s  hops=%-4s rssi=%-5s snr=%-5s%s%s" % (
            time.strftime("%H:%M:%S", time.localtime(now)), sender, kind, chan,
            "?" if hops is None else hops, "?" if rssi is None else rssi, "?" if snr is None else snr,
            "  via MQTT" if packet.get("viaMqtt") else "", "  " + name if name else "")

    def summary(self):
        out = ["", "Packets: %d decoded, %d encrypted (not decodable with this node's keys)." % (self.decoded, self.encrypted),
               "Senders heard: %d" % len(self.senders)]
        for sid, s in sorted(self.senders.items(), key=lambda kv: -(kv[1]["best"] or -999)):
            out.append("  %-10s %3d packets (%d encrypted)  best rssi %-5s  heard direct: %-3s %s" % (
                sid, s["n"], s["enc"], "?" if s["best"] is None else s["best"], "yes" if s["direct"] else "no", s["name"] or ""))
        if self.encrypted:
            out.append("Result: encrypted packets DO arrive, so sender and signal can be used for other meshes' nodes.")
        elif self.decoded:
            out.append("Result: no encrypted packets arrived. Either no foreign-channel traffic was in range, or the "
                       "firmware drops what it cannot decrypt. Run again where a private-channel node is known to be transmitting.")
        else:
            out.append("Result: nothing was heard. Check the antenna, the region and the modem preset on the node.")
        return "\n".join(out)


def describe_node(iface):
    """Region, preset and channel names of the local node. Keys are not read."""
    from meshtastic.protobuf import channel_pb2, config_pb2
    lora = iface.localNode.localConfig.lora
    lines = ["Node radio: region %s, preset %s%s" % (
        config_pb2.Config.LoRaConfig.RegionCode.Name(lora.region),
        config_pb2.Config.LoRaConfig.ModemPreset.Name(lora.modem_preset),
        "" if lora.use_preset else " (custom modem settings)")]
    for ch in iface.localNode.channels or []:
        if ch.role != channel_pb2.Channel.Role.DISABLED:
            lines.append("  channel %d: %s %s" % (ch.index, channel_pb2.Channel.Role.Name(ch.role), ch.settings.name or "(default name)"))
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", help="serial device (default: detect the first one)")
    ap.add_argument("--minutes", type=float, default=10, help="how long to listen (default 10)")
    args = ap.parse_args()
    try:
        from pubsub import pub
        import meshtastic.serial_interface
    except ImportError:
        sys.exit("The Meshtastic library is missing. Run: python3 -m venv ~/lora-venv && ~/lora-venv/bin/pip install meshtastic")
    probe = Probe()

    def on_receive(packet, interface):  # pubsub keeps only a weak reference, so this must stay a named local
        print(probe.handle(packet), flush=True)

    pub.subscribe(on_receive, "meshtastic.receive")
    try:
        iface = meshtastic.serial_interface.SerialInterface(devPath=args.port)
    except Exception as exc:
        sys.exit("Could not open the node: %s\nCheck the cable and the port (ls /dev/serial/by-id/), that nothing else is using it, "
                 "and that you may use serial ports (sudo, or the dialout group)." % exc)
    try:
        print(describe_node(iface))
        print("Listening for %g minutes. Ctrl-C to stop early.\n" % args.minutes)
        end = time.time() + args.minutes * 60
        while time.time() < end:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        iface.close()
        print(probe.summary())


if __name__ == "__main__":
    main()
