from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP

def callback(packet):
    pkt = IP(packet.get_payload())
    print(f"[NFQUEUE] {pkt.src}:{pkt[TCP].sport} -> {pkt.dst}:{pkt[TCP].dport} "
          f"flags={pkt[TCP].flags} len={len(packet.get_payload())}")
    packet.accept()

nfqueue = NetfilterQueue()
nfqueue.bind(0, callback)
print("Listening on NFQUEUE 0 (Ctrl+C to stop)...")
try:
    nfqueue.run()
except KeyboardInterrupt:
    print("\nStopping listener.")
