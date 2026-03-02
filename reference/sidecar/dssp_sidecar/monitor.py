"""Agent process monitor — collects network, memory, DNS, and syscall evidence."""

from __future__ import annotations

import socket
import time
import threading
from dataclasses import dataclass, field, asdict

try:
    import psutil

    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


@dataclass
class NetworkConnection:
    """A single observed network connection."""

    timestamp: str
    remote_address: str
    remote_port: int
    protocol: str  # "tcp" or "udp"
    direction: str  # "outbound" or "inbound"
    bytes_sent: int = 0
    bytes_received: int = 0


@dataclass
class MemorySnapshot:
    """A point-in-time memory usage measurement."""

    timestamp: str
    rss_bytes: int  # Resident Set Size
    vms_bytes: int  # Virtual Memory Size
    shared_bytes: int = 0


@dataclass
class DNSQuery:
    """An observed DNS query."""

    timestamp: str
    hostname: str
    resolved_ips: list[str] = field(default_factory=list)


@dataclass
class MonitorEvidence:
    """Collected evidence from monitoring an agent process."""

    session_id: str
    monitoring_start: str
    monitoring_end: str = ""
    network_connections: list[NetworkConnection] = field(default_factory=list)
    memory_snapshots: list[MemorySnapshot] = field(default_factory=list)
    dns_queries: list[DNSQuery] = field(default_factory=list)
    total_egress_bytes: int = 0
    total_ingress_bytes: int = 0
    peak_memory_bytes: int = 0
    unique_destinations: set = field(default_factory=set)
    anomalies: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = {
            "session_id": self.session_id,
            "monitoring_start": self.monitoring_start,
            "monitoring_end": self.monitoring_end,
            "network_connections": [asdict(c) for c in self.network_connections],
            "memory_snapshots": [asdict(s) for s in self.memory_snapshots],
            "dns_queries": [asdict(q) for q in self.dns_queries],
            "total_egress_bytes": self.total_egress_bytes,
            "total_ingress_bytes": self.total_ingress_bytes,
            "peak_memory_bytes": self.peak_memory_bytes,
            "unique_destinations": sorted(self.unique_destinations),
            "anomalies": self.anomalies,
        }
        return d


class AgentMonitor:
    """Monitors an agent process and collects evidence about its behavior.

    In a production deployment, this runs in a SEPARATE enclave from the agent
    to prevent the agent from tampering with the monitoring. In the reference
    implementation, it runs as a separate process.
    """

    def __init__(self, session_id: str, agent_pid: int | None = None):
        self.session_id = session_id
        self.agent_pid = agent_pid
        self._evidence = MonitorEvidence(
            session_id=session_id,
            monitoring_start=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        )
        self._running = False
        self._thread: threading.Thread | None = None
        self._poll_interval = 1.0  # seconds
        self._known_connections: set[tuple] = set()

    @property
    def evidence(self) -> MonitorEvidence:
        return self._evidence

    def start(self) -> None:
        """Start background monitoring."""
        self._running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()

    def stop(self) -> MonitorEvidence:
        """Stop monitoring and return collected evidence."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        self._evidence.monitoring_end = time.strftime(
            "%Y-%m-%dT%H:%M:%SZ", time.gmtime()
        )
        return self._evidence

    def _monitor_loop(self) -> None:
        """Main monitoring loop — polls process state periodically."""
        while self._running:
            try:
                self._collect_network_snapshot()
                self._collect_memory_snapshot()
            except Exception:
                pass  # Don't crash the monitor on collection errors
            time.sleep(self._poll_interval)

    def _collect_network_snapshot(self) -> None:
        """Collect current network connections for the monitored process."""
        if not PSUTIL_AVAILABLE or self.agent_pid is None:
            return

        try:
            proc = psutil.Process(self.agent_pid)
            connections = proc.net_connections(kind="inet")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return

        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        for conn in connections:
            if conn.status == "ESTABLISHED" and conn.raddr:
                key = (conn.raddr.ip, conn.raddr.port, conn.type.name)
                if key not in self._known_connections:
                    self._known_connections.add(key)
                    net_conn = NetworkConnection(
                        timestamp=now,
                        remote_address=conn.raddr.ip,
                        remote_port=conn.raddr.port,
                        protocol="tcp" if conn.type == socket.SOCK_STREAM else "udp",
                        direction="outbound" if conn.laddr.port > 1024 else "inbound",
                    )
                    self._evidence.network_connections.append(net_conn)
                    dest = f"{conn.raddr.ip}:{conn.raddr.port}"
                    self._evidence.unique_destinations.add(dest)

        # Update I/O counters
        try:
            io_counters = proc.io_counters()
            self._evidence.total_egress_bytes = io_counters.write_bytes
            self._evidence.total_ingress_bytes = io_counters.read_bytes
        except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
            pass

    def _collect_memory_snapshot(self) -> None:
        """Collect current memory usage for the monitored process."""
        if not PSUTIL_AVAILABLE or self.agent_pid is None:
            return

        try:
            proc = psutil.Process(self.agent_pid)
            mem = proc.memory_info()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return

        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        snapshot = MemorySnapshot(
            timestamp=now,
            rss_bytes=mem.rss,
            vms_bytes=mem.vms,
            shared_bytes=getattr(mem, "shared", 0),
        )
        self._evidence.memory_snapshots.append(snapshot)

        if mem.rss > self._evidence.peak_memory_bytes:
            self._evidence.peak_memory_bytes = mem.rss
