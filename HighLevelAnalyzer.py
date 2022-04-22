from typing import Iterable, Optional, Union
from saleae.analyzers import (
    HighLevelAnalyzer,
    AnalyzerFrame,
)

regs = {
    0x0000: "MR",
    0x0001: "GAR0",
    0x0002: "GAR1",
    0x0003: "GAR2",
    0x0004: "GAR3",
    0x0005: "SUBR0",
    0x0006: "SUBR1",
    0x0007: "SUBR2",
    0x0008: "SUBR3",
    0x0009: "SHAR0",
    0x000A: "SHAR1",
    0x000B: "SHAR2",
    0x000C: "SHAR3",
    0x000D: "SHAR4",
    0x000E: "SHAR5",
    0x000F: "SIPR0",
    0x0010: "SIPR1",
    0x0011: "SIPR2",
    0x0012: "SIPR3",
    0x0013: "INTLEVEL0",
    0x0014: "INTLEVEL1",
    0x0015: "IR",
    0x0016: "IMR",
    0x0017: "SIR",
    0x0018: "SIMR",
    0x0019: "RTR0",
    0x001A: "RTR1",
    0x001B: "RCR",
    0x001C: "PTIMER",
    0x001D: "PMAGIC",
    0x001E: "PHAR0",
    0x001F: "PHAR1",
    0x0020: "PHAR2",
    0x0021: "PHAR3",
    0x0022: "PHAR4",
    0x0023: "PHAR5",
    0x0024: "PSID0",
    0x0025: "PSID1",
    0x0026: "PMRU0",
    0x0027: "PMRU1",
    0x0028: "UIPR0",
    0x0029: "UIPR1",
    0x002A: "UIPR2",
    0x002B: "UIPR3",
    0x002C: "UPORTR0",
    0x002D: "UPORTR1",
    0x002E: "PHYCFGR",
    0x0039: "VERSIONR",
}

sn_regs = {
    0x0000: "MR",
    0x0001: "CR",
    0x0002: "IR",
    0x0003: "SR",
    0x0004: "PORT0",
    0x0005: "PORT1",
    0x0006: "DHAR0",
    0x0007: "DHAR1",
    0x0008: "DHAR2",
    0x0009: "DHAR3",
    0x000A: "DHAR4",
    0x000B: "DHAR5",
    0x000C: "DIPR0",
    0x000D: "DIPR1",
    0x000E: "DIPR2",
    0x000F: "DIPR3",
    0x0010: "DPORT0",
    0x0011: "DPORT1",
    0x0012: "MSSR0",
    0x0013: "MSSR1",
    0x0015: "TOS",
    0x0016: "TTL",
    0x001E: "RXBUF_SIZE",
    0x001F: "TXBUF_SIZE",
    0x0020: "TX_FSR0",
    0x0021: "TX_FSR1",
    0x0022: "TX_RD0",
    0x0023: "TX_RD1",
    0x0024: "TX_WR0",
    0x0025: "TX_WR1",
    0x0026: "RX_RSR0",
    0x0027: "RX_RSR1",
    0x0028: "RX_RD0",
    0x0029: "RX_RD1",
    0x002A: "RX_WR0",
    0x002B: "RX_WR1",
    0x002C: "IMR",
    0x002D: "FRAG0",
    0x002E: "FRAG1",
    0x002F: "KPALVTR",
}


def get_reg_name(address: int) -> str:
    """Get the register name by address."""
    try:
        return regs[address]
    except KeyError:
        return "INVALID"


def get_sn_reg_name(address: int) -> str:
    """Get the socket register name by address."""
    try:
        return sn_regs[address]
    except KeyError:
        return "INVALID"


class Hla(HighLevelAnalyzer):
    """RFM69 High Level Analyzer."""

    result_types = {
        "address": {"format": "Address {{data.address}}"},
        "control": {"format": "{{data.block}} block {{data.rw}}"},
        "read": {"format": "{{data.rw}} {{data.reg}} {{data.value}}"},
        "write": {"format": "{{data.rw}} {{data.reg}} {{data.value}}"},
    }

    def __init__(self):
        """Initialize HLA."""

        # Previous frame type
        # https://support.saleae.com/extensions/analyzer-frame-types/spi-analyzer
        self._previous_type: str = ""
        # current address
        self._address: Optional[int] = None
        # current block
        self._block: str = ""
        # current access type
        self._rw: str = ""
        # current byte position
        self._byte_pos: int = 0
        # current socket number
        self._sn: Optional[int] = None

        self._start_of_address_frame = None

    def decode(
        self, frame: AnalyzerFrame
    ) -> Optional[Union[Iterable[AnalyzerFrame], AnalyzerFrame]]:
        """Decode frames."""
        is_first_byte: bool = self._previous_type == "enable"
        self._previous_type: str = frame.type

        if is_first_byte:
            self._byte_pos = 0
        else:
            self._byte_pos += 1

        if frame.type != "result":
            return None

        mosi: bytes = frame.data["mosi"]
        miso: bytes = frame.data["miso"]

        if self._byte_pos == 0:
            try:
                self._address = mosi[0] << 8
            except IndexError:
                return None
            self._start_of_address_frame = frame.start_time
        if self._byte_pos == 1:
            try:
                self._address |= mosi[0]
            except IndexError:
                return None

            return AnalyzerFrame(
                "address",
                start_time=self._start_of_address_frame,
                end_time=frame.end_time,
                data={
                    "address": f"0x{self._address:04X}",
                },
            )
        if self._byte_pos == 2:
            try:
                byte = mosi[0]
            except IndexError:
                return None
            self._rw = "write" if ((byte >> 2) & 0b1 == 0b1) else "read"
            bsb = byte >> 3
            self._sn = None
            if bsb == 0:
                self._block = "common"
            else:
                sn = int(bsb / 4)
                if sn > 7:
                    self._block = "INVALID"
                else:
                    self._sn = sn
                    snblock = bsb - sn * 4 - 1
                    if snblock == 0:
                        self._block = f"Sn{sn} Socket"
                    elif snblock == 1:
                        self._block = f"Sn{sn} TX"
                    elif snblock == 2:
                        self._block = f"Sn{sn} RX"
                    else:
                        self._block = "INVALID"

            return AnalyzerFrame(
                "control",
                start_time=frame.start_time,
                end_time=frame.end_time,
                data={
                    "block": self._block,
                    "rw": self._rw,
                },
            )
        if self._byte_pos > 2:
            if self._rw.lower() == "write":
                try:
                    byte = mosi[0]
                except IndexError:
                    return None
            else:
                try:
                    byte = miso[0]
                except IndexError:
                    return None

            if self._sn is not None:
                if self._block.endswith("TX"):
                    name = "TX"
                elif self._block.endswith("RX"):
                    name = "RX"
                else:
                    name = get_sn_reg_name(self._address)
            else:
                name = get_reg_name(self._address)

            ret = AnalyzerFrame(
                self._rw.lower(),
                start_time=frame.start_time,
                end_time=frame.end_time,
                data={
                    "reg": name,
                    "rw": self._rw,
                    "value": f"0x{byte:02X}",
                },
            )

            if self._address == 65535:
                self._address = 0
            else:
                self._address += 1

            return ret
