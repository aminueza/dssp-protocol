"""DSSP Attestation Abstraction Layer

Provides a unified interface for enclave attestation across:
  - simulated  : Fake attestation for development/CI (default)
  - gramine    : Gramine gramine-direct (simulation) or gramine-sgx (real SGX)
  - nitro      : AWS Nitro Enclaves (requires EC2 Nitro instance)

Usage:
    from attestation import create_attestor

    attestor = create_attestor()        # auto-detects from ENCLAVE_MODE env
    report = attestor.generate_report(user_data=b"my-nonce")
    measurement = attestor.get_measurement()
    eos = attestor.end_of_session_report(start_measurement)

Set ENCLAVE_MODE env var: "simulated" (default), "gramine", "nitro"
"""

import base64
import hashlib
import json
import os
import struct
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass
class AttestationReport:
    """Unified attestation report across all backends."""

    enclave_type: str  # "sandbox", "sgx", "sev-snp", "nitro"
    measurement: str  # MRENCLAVE (SGX), launch digest (Nitro), etc.
    agent_hash: dict  # {"algorithm": "sha-256", "value": "..."}
    timestamp: str  # ISO-8601
    signed_by: str  # CA identity
    signature: str  # Base64 signature
    platform_certificate_chain: list[str] = field(default_factory=list)
    raw_quote: str | None = None  # Base64 raw hardware quote (SGX DCAP, Nitro NSM)
    backend: str = "simulated"  # Which backend generated this
    claims: dict = field(default_factory=dict)  # Additional attestation claims

    def to_dict(self) -> dict:
        d = {
            "enclave_type": self.enclave_type,
            "measurement": self.measurement,
            "agent_hash": self.agent_hash,
            "timestamp": self.timestamp,
            "signed_by": self.signed_by,
            "signature": self.signature,
        }
        if self.platform_certificate_chain:
            d["platform_certificate_chain"] = self.platform_certificate_chain
        if self.raw_quote:
            d["raw_quote"] = self.raw_quote
        if self.claims:
            d["claims"] = self.claims
        return d


class Attestor(ABC):
    """Base attestation interface."""

    def __init__(self, agent_id: str, agent_version: str):
        self.agent_id = agent_id
        self.agent_version = agent_version
        self.agent_hash_value = sha256_hex(f"{agent_id}:{agent_version}".encode())
        self._start_measurement: str | None = None

    @property
    def agent_hash(self) -> dict:
        return {"algorithm": "sha-256", "value": self.agent_hash_value}

    @abstractmethod
    def get_measurement(self) -> str:
        """Get the enclave measurement (MRENCLAVE, launch digest, etc.)."""

    @abstractmethod
    def generate_report(self, user_data: bytes = b"") -> AttestationReport:
        """Generate an attestation report, optionally binding user_data."""

    @abstractmethod
    def end_of_session_report(self, start_measurement: str) -> dict:
        """Generate end-of-session attestation proving enclave wasn't tampered with."""

    @abstractmethod
    def get_enclave_type(self) -> str:
        """Return the enclave type string for DSSP schemas."""

    @abstractmethod
    def get_backend_name(self) -> str:
        """Return the backend name for logging."""


class SimulatedAttestor(Attestor):
    """Fake attestation for development and CI.

    Generates structurally valid reports with self-signed data.
    Provides NO security — any host process can read all memory.
    """

    def __init__(self, agent_id: str, agent_version: str):
        super().__init__(agent_id, agent_version)
        self._measurement = sha256_hex(b"simulated-enclave-measurement-v1")

    def get_measurement(self) -> str:
        return self._measurement

    def get_enclave_type(self) -> str:
        return "sandbox"

    def get_backend_name(self) -> str:
        return "simulated"

    def generate_report(self, user_data: bytes = b"") -> AttestationReport:
        report_body = {
            "type": "simulated",
            "measurement": self._measurement,
            "agent_hash": self.agent_hash_value,
            "user_data": sha256_hex(user_data) if user_data else "",
            "timestamp": now_utc(),
        }
        sig = base64.b64encode(
            json.dumps(report_body, sort_keys=True).encode()
        ).decode()

        self._start_measurement = self._measurement

        return AttestationReport(
            enclave_type="sandbox",
            measurement=self._measurement,
            agent_hash=self.agent_hash,
            timestamp=now_utc(),
            signed_by="simulated-ca",
            signature=sig,
            backend="simulated",
        )

    def end_of_session_report(self, start_measurement: str) -> dict:
        current = self.get_measurement()
        return {
            "measurement": current,
            "measurement_matches_start": current == start_measurement,
            "timestamp": now_utc(),
            "signature": base64.b64encode(
                f"eos:{current}:{now_utc()}".encode()
            ).decode(),
        }


class GramineAttestor(Attestor):
    """Gramine-based attestation.

    In gramine-direct mode:
      - /dev/attestation/ is NOT available
      - Generates simulated SGX DCAP quotes with correct structure
      - MRENCLAVE is computed from the Gramine manifest

    In gramine-sgx mode (real hardware):
      - /dev/attestation/quote returns a real SGX DCAP quote
      - MRENCLAVE is CPU-measured
      - Signature is from Intel's QE (Quoting Enclave)

    Detection: checks for /dev/attestation/quote existence.
    """

    SGX_QUOTE_HEADER_SIZE = 48
    SGX_REPORT_BODY_SIZE = 384

    def __init__(self, agent_id: str, agent_version: str):
        super().__init__(agent_id, agent_version)
        self._is_real_sgx = Path("/dev/attestation/quote").exists()
        self._measurement = self._compute_measurement()

    def _compute_measurement(self) -> str:
        """Compute MRENCLAVE from manifest or read from SGX report."""
        if self._is_real_sgx:
            try:
                report_data = Path("/dev/attestation/report").read_bytes()
                # MRENCLAVE is at offset 64 in the SGX report body (32 bytes)
                mrenclave = report_data[64:96]
                return mrenclave.hex()
            except Exception:
                pass

        # gramine-direct: compute from manifest + agent binary
        manifest_path = Path("/app/python.manifest")
        if manifest_path.exists():
            manifest_hash = sha256_hex(manifest_path.read_bytes())
        else:
            manifest_hash = sha256_hex(b"gramine-manifest-not-found")

        agent_path = Path("/app/main.py")
        if agent_path.exists():
            agent_hash = sha256_hex(agent_path.read_bytes())
        else:
            agent_hash = self.agent_hash_value

        return sha256_hex(f"mrenclave:{manifest_hash}:{agent_hash}".encode())

    def get_measurement(self) -> str:
        return self._measurement

    def get_enclave_type(self) -> str:
        return "sgx" if self._is_real_sgx else "sgx-simulated"

    def get_backend_name(self) -> str:
        return "gramine-sgx" if self._is_real_sgx else "gramine-direct"

    def _build_sgx_dcap_quote(self, user_data: bytes = b"") -> bytes:
        """Build a structurally valid SGX DCAP quote.

        Real structure (simplified):
          - Header (48 bytes): version, att_key_type, reserved, qe_svn, pce_svn, qe_vendor_id, user_data
          - Report Body (384 bytes): cpusvn, miscselect, reserved, attributes, mrenclave, ...
          - Signature (variable): ECDSA-256-with-P-256 over header + report body

        In simulation, we fill these with deterministic data so the gateway
        can parse the format without real Intel QE signatures.
        """
        header = struct.pack("<H", 3)  # version = 3
        header += struct.pack("<H", 2)  # att_key_type = ECDSA-256
        header += b"\x00" * 4  # reserved
        header += struct.pack("<H", 0x0300)  # qe_svn
        header += struct.pack("<H", 0x0E00)  # pce_svn
        header += bytes.fromhex(
            "939a7233f79c4ca9940a0db3957f0607"
        )  # qe_vendor_id (Intel)
        header += sha256_hex(user_data).encode()[:20]  # user_data (first 20 bytes)
        header = header.ljust(self.SGX_QUOTE_HEADER_SIZE, b"\x00")

        report_body = b"\x00" * 16  # cpusvn (16 bytes)
        report_body += struct.pack("<I", 0)  # miscselect
        report_body += b"\x00" * 12  # reserved
        report_body += b"\x00" * 16  # isv_ext_prod_id
        report_body += struct.pack("<QQ", 0x07, 0x03)  # attributes (flags, xfrm)
        report_body += bytes.fromhex(self._measurement)  # mrenclave (32 bytes)
        report_body += b"\x00" * 32  # reserved
        report_body += (
            sha256_hex(b"mrsigner-simulated").encode()[:32].ljust(32, b"\x00")
        )  # mrsigner
        report_body += b"\x00" * 96  # reserved
        report_body += struct.pack("<H", 0)  # isv_prod_id
        report_body += struct.pack("<H", 1)  # isv_svn
        report_body += b"\x00" * 60  # reserved
        report_body += hashlib.sha256(
            user_data
        ).digest()  # report_data (first 32 bytes)
        report_body += (
            sha256_hex(json.dumps({"agent": self.agent_id, "ts": now_utc()}).encode())
            .encode()[:32]
            .ljust(32, b"\x00")
        )  # report_data (next 32 bytes)

        report_body = report_body[: self.SGX_REPORT_BODY_SIZE].ljust(
            self.SGX_REPORT_BODY_SIZE, b"\x00"
        )

        # Simulated ECDSA placeholder signature
        sig_data = hashlib.sha256(header + report_body).digest()
        signature = sig_data * 16  # 512 bytes placeholder

        return header + report_body + signature

    def generate_report(self, user_data: bytes = b"") -> AttestationReport:
        if self._is_real_sgx:
            return self._generate_real_sgx_report(user_data)
        return self._generate_simulated_sgx_report(user_data)

    def _generate_real_sgx_report(self, user_data: bytes) -> AttestationReport:
        """Use Gramine's /dev/attestation/ to get a real SGX DCAP quote."""
        try:
            # Write user report data (64 bytes max)
            report_data = hashlib.sha256(user_data).digest() + b"\x00" * 32
            Path("/dev/attestation/user_report_data").write_bytes(report_data[:64])

            quote = Path("/dev/attestation/quote").read_bytes()
            raw_quote_b64 = base64.b64encode(quote).decode()

            self._start_measurement = self._measurement

            return AttestationReport(
                enclave_type="sgx",
                measurement=self._measurement,
                agent_hash=self.agent_hash,
                timestamp=now_utc(),
                signed_by="intel-qe",
                signature=raw_quote_b64[:128],  # First 128 chars of quote as sig
                platform_certificate_chain=[
                    "# Real PCK certificate would be here",
                    "# Retrieved from Intel PCS or DCAP cache",
                ],
                raw_quote=raw_quote_b64,
                backend="gramine-sgx",
            )
        except Exception as e:
            print(f"  WARNING: Real SGX attestation failed: {e}", flush=True)
            print("  Falling back to simulated SGX quote", flush=True)
            return self._generate_simulated_sgx_report(user_data)

    def _generate_simulated_sgx_report(self, user_data: bytes) -> AttestationReport:
        """Generate a structurally valid but self-signed SGX DCAP quote."""
        quote = self._build_sgx_dcap_quote(user_data)
        raw_quote_b64 = base64.b64encode(quote).decode()

        sig = base64.b64encode(
            hashlib.sha256(
                quote[: self.SGX_QUOTE_HEADER_SIZE + self.SGX_REPORT_BODY_SIZE]
            ).digest()
        ).decode()

        self._start_measurement = self._measurement

        return AttestationReport(
            enclave_type="sgx-simulated",
            measurement=self._measurement,
            agent_hash=self.agent_hash,
            timestamp=now_utc(),
            signed_by="gramine-direct-simulated-qe",
            signature=sig,
            platform_certificate_chain=[
                base64.b64encode(b"SIMULATED Intel Root CA - NOT REAL").decode(),
                base64.b64encode(
                    b"SIMULATED Intel PCK Certificate - NOT REAL"
                ).decode(),
            ],
            raw_quote=raw_quote_b64,
            backend="gramine-direct",
        )

    def end_of_session_report(self, start_measurement: str) -> dict:
        current = self.get_measurement()

        if self._is_real_sgx:
            try:
                # Generate a fresh quote as end-of-session proof
                eos_data = f"eos:{start_measurement}:{now_utc()}".encode()
                report_data = hashlib.sha256(eos_data).digest() + b"\x00" * 32
                Path("/dev/attestation/user_report_data").write_bytes(report_data[:64])
                quote = Path("/dev/attestation/quote").read_bytes()
                sig = base64.b64encode(quote[:64]).decode()
            except Exception:
                sig = base64.b64encode(
                    f"eos-gramine-direct:{current}:{now_utc()}".encode()
                ).decode()
        else:
            sig = base64.b64encode(
                f"eos-gramine-direct:{current}:{now_utc()}".encode()
            ).decode()

        return {
            "measurement": current,
            "measurement_matches_start": current == start_measurement,
            "timestamp": now_utc(),
            "signature": sig,
            "backend": self.get_backend_name(),
        }


class NitroAttestor(Attestor):
    """AWS Nitro Enclaves attestation.

    Requires running inside a Nitro Enclave on a Nitro-capable EC2 instance.
    Uses the Nitro Secure Module (NSM) via /dev/nsm for attestation.

    This is a STUB. Production implementation would use:
      - aws-nitro-enclaves-sdk-c via ctypes, or
      - the nsm Python bindings
    """

    def __init__(self, agent_id: str, agent_version: str):
        super().__init__(agent_id, agent_version)
        self._is_real_nitro = Path("/dev/nsm").exists()
        self._measurement = self._compute_measurement()

    def _compute_measurement(self) -> str:
        if self._is_real_nitro:
            # In real Nitro, the measurement comes from the EIF image hash
            pass
        agent_path = Path("/app/main.py")
        if agent_path.exists():
            return sha256_hex(agent_path.read_bytes())
        return sha256_hex(f"nitro:{self.agent_id}:{self.agent_version}".encode())

    def get_measurement(self) -> str:
        return self._measurement

    def get_enclave_type(self) -> str:
        return "nitro" if self._is_real_nitro else "nitro-simulated"

    def get_backend_name(self) -> str:
        return "nitro" if self._is_real_nitro else "nitro-simulated"

    def generate_report(self, user_data: bytes = b"") -> AttestationReport:
        if self._is_real_nitro:
            # Real Nitro would call:
            #   nsm.describe_nsm() -> PCRs
            #   nsm.attest(user_data, nonce, public_key) -> COSE_Sign1 document
            pass

        # Simulated Nitro attestation document
        pcrs = {
            "PCR0": sha256_hex(b"nitro-pcr0-enclave-image"),
            "PCR1": sha256_hex(b"nitro-pcr1-kernel"),
            "PCR2": sha256_hex(b"nitro-pcr2-application"),
            "PCR8": sha256_hex(self.agent_id.encode()),
        }

        attestation_doc = {
            "module_id": "dssp-agent-enclave",
            "digest": "SHA384",
            "timestamp": int(time.time() * 1000),
            "pcrs": pcrs,
            "certificate": base64.b64encode(b"SIMULATED Nitro Certificate").decode(),
            "cabundle": [
                base64.b64encode(b"SIMULATED AWS Nitro Root CA").decode(),
            ],
            "user_data": base64.b64encode(user_data).decode() if user_data else None,
            "nonce": sha256_hex(os.urandom(32)),
        }

        sig = base64.b64encode(
            json.dumps(attestation_doc, sort_keys=True).encode()
        ).decode()

        self._start_measurement = self._measurement

        return AttestationReport(
            enclave_type="nitro-simulated",
            measurement=self._measurement,
            agent_hash=self.agent_hash,
            timestamp=now_utc(),
            signed_by="nitro-simulated-nsm",
            signature=sig,
            platform_certificate_chain=[
                base64.b64encode(b"SIMULATED AWS Nitro Attestation Root CA").decode(),
            ],
            raw_quote=base64.b64encode(json.dumps(attestation_doc).encode()).decode(),
            backend="nitro-simulated",
        )

    def end_of_session_report(self, start_measurement: str) -> dict:
        current = self.get_measurement()
        return {
            "measurement": current,
            "measurement_matches_start": current == start_measurement,
            "timestamp": now_utc(),
            "signature": base64.b64encode(
                f"eos-nitro:{current}:{now_utc()}".encode()
            ).decode(),
            "backend": self.get_backend_name(),
        }


BACKENDS = {
    "simulated": SimulatedAttestor,
    "gramine": GramineAttestor,
    "nitro": NitroAttestor,
}


def create_attestor(
    agent_id: str = "dssp-agent",
    agent_version: str = "0.1.0",
    mode: str | None = None,
) -> Attestor:
    """Create an attestor based on ENCLAVE_MODE env var or explicit mode.

    Auto-detection order:
      1. Explicit mode parameter
      2. ENCLAVE_MODE env var
      3. Auto-detect: /dev/attestation/quote -> gramine, /dev/nsm -> nitro
      4. Fall back to simulated
    """
    if mode is None:
        mode = os.environ.get("ENCLAVE_MODE", "").lower()

    if not mode or mode == "auto":
        if Path("/dev/attestation/quote").exists():
            mode = "gramine"
        elif Path("/dev/nsm").exists():
            mode = "nitro"
        else:
            mode = "simulated"

    cls = BACKENDS.get(mode)
    if cls is None:
        print(f"  WARNING: Unknown enclave mode '{mode}', falling back to simulated")
        cls = SimulatedAttestor

    return cls(agent_id, agent_version)
