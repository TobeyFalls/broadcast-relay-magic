import importlib.util
import logging
import sys
import threading

import coloredlogs
from scapy.compat import raw
from scapy.layers.inet import UDP, IP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.sendrecv import sniff, sendp, send

broadcast_ip = None

broadcast_listen_port = None
broadcast_source_ip = None

remote_ip = None
remote_port = None

unicast_listen_iface = None
unicast_listen_ip = None
unicast_listen_port = None

coloredlogs.install(
    level="DEBUG",
    fmt="%(asctime)s [%(threadName)s] %(levelname)s %(message)s",
    milliseconds=True,
)


def load_config_to_globals(config_filename):
    spec = importlib.util.spec_from_file_location("config", config_filename)
    config = importlib.util.module_from_spec(spec)
    sys.modules["config"] = config
    spec.loader.exec_module(config)
    globals().update({k: v for k, v in vars(config).items() if not k.startswith("__")})


def listen_broadcast():
    logging.info("Listening...")

    def handle(pkt):
        logging.debug(f"Received: {pkt}")
        forward_packet(pkt)

    def forward_packet(pkt):
        data = raw(pkt[UDP].payload)
        packet = IP(dst=remote_ip) / UDP(dport=remote_port) / Raw(load=data)
        send(packet, verbose=False)
        logging.debug(f"Forwarded: {packet}")

    sniff(
        filter=f"udp and src host {broadcast_source_ip} and dst host {broadcast_ip} and port {broadcast_listen_port}",
        prn=handle,
    )


def listen_unicast():
    logging.info("Listening...")

    def handle(pkt):
        logging.debug(f"Received: {pkt}")
        forward_packet(pkt)

    def forward_packet(pkt):
        data = raw(pkt[UDP].payload)
        packet = (
            Ether()
            / IP(src=remote_ip, dst=broadcast_ip)
            / UDP(sport=broadcast_listen_port, dport=broadcast_listen_port)
            / Raw(load=data)
        )
        # send doesn't work for broadcast. windows issue?
        # or is it due to source IP spoofing?
        sendp(packet, verbose=False)
        logging.debug(f"Forwarded: {packet}")

    sniff(
        # explicitly set since virtual interfaces (Tailscale) are not listened on by default?
        iface=unicast_listen_iface,
        filter=f"udp and dst host {unicast_listen_ip} and port {unicast_listen_port}",
        prn=handle,
    )


load_config_to_globals(f"config/{sys.argv[1]}.py")

threads = (
    threading.Thread(name="listen_broadcast", target=listen_broadcast, daemon=True),
    threading.Thread(name="listen_unicast", target=listen_unicast, daemon=True),
)

for thread in threads:
    thread.start()

for thread in threads:
    thread.join()
