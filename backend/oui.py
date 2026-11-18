"""MAC OUI -> vendor lookup.

A small curated table is bundled so the tool works offline. Extend it without
touching code by dropping lines of ``AABBCC,Vendor Name`` into
``backend/data/oui.csv`` (prefixes are matched case-insensitively on the first
three octets).
"""
from __future__ import annotations

import csv
from pathlib import Path

OUI: dict[str, str] = {
    # Apple
    "001B63": "Apple", "0026BB": "Apple", "3C22FB": "Apple", "A483E7": "Apple",
    "F01898": "Apple", "8C8590": "Apple", "28CFE9": "Apple", "F8FFC2": "Apple",
    "843838": "Apple", "040CCE": "Apple", "703EAC": "Apple", "9C207B": "Apple",
    # Samsung
    "0012FB": "Samsung", "0021D1": "Samsung", "5C0A5B": "Samsung", "8425DB": "Samsung",
    "E8508B": "Samsung", "F409D8": "Samsung", "C819F7": "Samsung",
    # Google / Nest
    "001A11": "Google", "3C5AB4": "Google", "F4F5D8": "Google", "18B430": "Google Nest",
    "6466B3": "Google", "A47733": "Google",
    # Amazon
    "44650D": "Amazon", "74C246": "Amazon", "F0272D": "Amazon", "6837E9": "Amazon",
    "38F73D": "Amazon", "0C47C9": "Amazon",
    # Raspberry Pi / Espressif / IoT
    "DCA632": "Raspberry Pi", "B827EB": "Raspberry Pi", "E45F01": "Raspberry Pi",
    "D83ADD": "Raspberry Pi", "2CCF67": "Raspberry Pi",
    "240AC4": "Espressif", "84CCA8": "Espressif", "30AEA4": "Espressif",
    "A4CF12": "Espressif", "DC4F22": "Espressif", "7C9EBD": "Espressif",
    "001788": "Philips Hue", "ECB5FA": "Philips Hue",
    # PC / virtualisation
    "000C29": "VMware", "000569": "VMware", "001C14": "VMware", "005056": "VMware",
    "080027": "VirtualBox", "00155D": "Microsoft Hyper-V", "001C42": "Parallels",
    "525400": "QEMU/KVM",
    # Networking gear
    "000E8F": "SerComm", "001C10": "Cisco-Linksys", "0018E7": "Cisco",
    "001A70": "Cisco", "0022 90": "Cisco", "F09E63": "Cisco",
    "001E58": "D-Link", "1CBDB9": "D-Link", "3408 04": "D-Link",
    "000FB5": "NETGEAR", "20E52A": "NETGEAR", "A00460": "NETGEAR",
    "002722": "Ubiquiti", "0418D6": "Ubiquiti", "788A20": "Ubiquiti",
    "F09FC2": "Ubiquiti", "245A4C": "Ubiquiti",
    "001D0F": "TP-Link", "14CC20": "TP-Link", "50C7BF": "TP-Link",
    "A42BB0": "TP-Link", "C46E1F": "TP-Link", "EC086B": "TP-Link",
    "001882": "Huawei", "002568": "Huawei", "2012 55": "Huawei",
    "40CBA8": "Huawei", "781DBA": "Huawei", "D02DB3": "Huawei",
    "0024E4": "Withings", "00A0C9": "Intel", "001B21": "Intel", "3C9509": "Intel",
    "34E12D": "Intel", "7CB27D": "Intel", "9C7BEF": "Intel",
    # Mobile
    "001C7D": "Xiaomi", "2C9D1E": "Xiaomi", "50EC50": "Xiaomi", "64CC2E": "Xiaomi",
    "8CBEBE": "Xiaomi", "F8A45F": "Xiaomi",
    "1C1BB5": "Vivo", "3C2EFF": "Vivo", "505DAC": "Vivo",
    "2C5BB8": "Oppo", "5C1D8C": "Oppo", "94D4CB": "Oppo",
    "0C1DAF": "OnePlus", "94652D": "OnePlus",
    "0026E2": "LG", "10F96F": "LG", "C4366C": "LG",
    "0024BE": "Sony", "FC0FE6": "Sony", "0013A9": "Sony",
    # Motherboards / NICs
    "1C697A": "Elitegroup", "B42E99": "GIGA-BYTE", "04D4C4": "ASUSTek",
    "2C56DC": "ASUSTek", "9C5C8E": "ASUSTek", "7C10C9": "ASUSTek",
    "38D547": "ASUSTek", "00E04C": "Realtek", "00E04D": "Realtek",
    "001C25": "Hon Hai", "0024 7E": "Hon Hai", "3C970E": "Wistron",
    "00248C": "ASUSTek", "001BFB": "Alps", "00163E": "Xensource",
}

# IEEE assigns these bits to locally administered addresses: no vendor exists.
_LOCAL_BITS = {"2", "6", "A", "E"}


def _norm(prefix: str) -> str:
    return prefix.replace(":", "").replace("-", "").replace(" ", "").upper()


_OUI_NORM: dict[str, str] = {
    _norm(k): v for k, v in OUI.items() if len(_norm(k)) == 6
}


def _load_overrides(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    if not path.exists():
        return out
    try:
        with path.open(newline="", encoding="utf-8") as fh:
            for row in csv.reader(fh):
                if len(row) >= 2 and len(_norm(row[0])) == 6:
                    out[_norm(row[0])] = row[1].strip()
    except OSError:
        pass
    return out


def vendor_for(mac: str, override_file: Path | None = None) -> str:
    prefix = _norm(mac)[:6]
    if not prefix:
        return "Unknown"
    table = _OUI_NORM
    if override_file is not None:
        table = {**_OUI_NORM, **_load_overrides(override_file)}
    if prefix in table:
        return table[prefix]
    if len(prefix) >= 2 and prefix[1] in _LOCAL_BITS:
        return "Private / randomised MAC"
    return "Unknown"
