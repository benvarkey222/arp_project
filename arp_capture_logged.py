##### arp_capture_logged.py
from scapy.all import sniff, ARP
import datetime
import logging
import json
import threading
import signal
import sys
import os
from pathlib import Path

# ---------- CONFIG ----------
LOG_DIR = Path("./logs")
LOG_DIR.mkdir(exist_ok=True)
LOG_FILE = LOG_DIR / "arp_capture.log"
SNAPSHOT_JSON = LOG_DIR / "arp_table_snapshot.json"
SNAPSHOT_CSV = LOG_DIR / "arp_table_snapshot.csv"
SNAPSHOT_INTERVAL = 30            # seconds between automatic snapshots
# ----------------------------

# In-memory IP -> MAC mapping
ip_mac_table = {}
table_lock = threading.Lock()  # protect ip_mac_table across threads

# Setup logging
logger = logging.getLogger("arp_capture")
logger.setLevel(logging.INFO)
fmt = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

fh = logging.FileHandler(LOG_FILE, encoding="utf-8")
fh.setFormatter(fmt)
logger.addHandler(fh)

ch = logging.StreamHandler(sys.stdout)
ch.setFormatter(fmt)
logger.addHandler(ch)


def detect_conflict(ip, mac):
    """
    Detects conflicts without overwriting the original MAC.
    Logs the event. Returns True if conflict detected.
    """
    with table_lock:
        if ip in ip_mac_table:
            if ip_mac_table[ip] != mac:
                logger.warning(f"Conflict detected for IP {ip}: previous={ip_mac_table[ip]} new={mac}")
                # Do NOT overwrite the original MAC to maintain safety
                return True
            else:
                # same mapping observed
                return False
        else:
            ip_mac_table[ip] = mac
            logger.info(f"New mapping learned: {ip} -> {mac}")
            return False


def arp_callback(pkt):
    """
    Callback for sniffed packets.
    """
    if pkt.haslayer(ARP):
        ip = pkt[ARP].psrc
        mac = pkt[ARP].hwsrc
        conflict = detect_conflict(ip, mac)
        with table_lock:
            current = ip_mac_table.get(ip)
        # Log every observed ARP packet (timestamp handled by logger)
        if conflict:
            logger.info(f"ARP packet observed (conflict): {ip} seen as {mac}; table has {current}")
        else:
            logger.debug(f"ARP packet observed: {ip} is at {current}")
        # Also print a concise line to stdout
        print(f"{datetime.datetime.now()} - ARP Packet: {ip} is at {current}")


def write_snapshot_json(path=SNAPSHOT_JSON):
    """
    Write a JSON snapshot of the current ip_mac_table.
    """
    with table_lock:
        snapshot = {
            "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
            "entries": ip_mac_table.copy()
        }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(snapshot, f, indent=2)
    #logger.info(f"Wrote JSON snapshot to {path}")


def write_snapshot_csv(path=SNAPSHOT_CSV):
    """
    Append a timestamped CSV snapshot (IP,MAC,timestamp). Overwrites file header if new.
    """
    header_needed = not path.exists()
    with table_lock:
        entries = ip_mac_table.copy()

    lines = []
    ts = datetime.datetime.utcnow().isoformat() + "Z"
    for ip, mac in entries.items():
        lines.append(f"{ip},{mac},{ts}\n")

    mode = "a"
    with open(path, mode, encoding="utf-8") as f:
        if header_needed:
            f.write("ip,mac,snapshot_utc\n")
        f.writelines(lines)
    #logger.info(f"Appended CSV snapshot to {path}")


def periodic_snapshots(interval=SNAPSHOT_INTERVAL):
    """
    Background thread that writes periodic snapshots.
    """
    while True:
        try:
            write_snapshot_json()
            write_snapshot_csv()
        except Exception as e:
            logger.exception(f"Error writing snapshot: {e}")
        # Sleep in small chunks so shutdown is faster if signal received
        for _ in range(int(interval)):
            if stop_event.is_set():
                return
            stop_event.wait(1)


def dump_table_and_exit(signum=None, frame=None):
    """
    Signal handler to dump the table to disk and optionally exit.
    - SIGUSR1 : dump and continue
    - SIGINT  : dump and exit
    """
    logger.info(f"Signal {signum} received — dumping table.")
    write_snapshot_json()
    write_snapshot_csv()
    # on Ctrl+C (SIGINT), stop
    if signum == signal.SIGINT:
        logger.info("SIGINT received — shutting down.")
        stop_event.set()
        # give other threads time to finish
        sys.exit(0)


# Stop event for threads
stop_event = threading.Event()

def main():
    logger.info("Starting ARP packet capture (logged).")
    # Start snapshot thread
    snapshot_thread = threading.Thread(target=periodic_snapshots, daemon=True)
    snapshot_thread.start()

    # Register signal handlers.
    # Note: SIGUSR1 is POSIX-only — convenient for on-demand dump without exiting.
    try:
        signal.signal(signal.SIGUSR1, dump_table_and_exit)  # POSIX only
    except Exception:
        # Windows will raise; ignore if not supported
        logger.debug("SIGUSR1 not available on this platform.")

    signal.signal(signal.SIGINT, dump_table_and_exit)  # Ctrl+C

    # Start sniffing ARP packets on all interfaces (needs sudo/admin)
    try:
        sniff(filter="arp", prn=arp_callback, store=0)
    except PermissionError:
        logger.error("Permission denied: run this script with sudo/administrator privileges.")
    except Exception as e:
        logger.exception(f"Sniffing stopped with exception: {e}")
    finally:
        # final snapshot before exit
        stop_event.set()
        write_snapshot_json()
        write_snapshot_csv()
        logger.info("Stopped ARP capture.")

if __name__ == "__main__":
    main()
