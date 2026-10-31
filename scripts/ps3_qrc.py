#!/usr/bin/env python3
"""Read, check and rebuild the PS3's QGL QRC containers.

The eight files under ``dev_flash/vsh/resource/qgl/`` (``canyon.qrc``,
``earth.qrc``, ``icons.qrc``, ``icontex.qrc``, ``lines.qrc``, ``raf.qrc``,
``rhm.qrc``, ``store.qrc``) are what the XMB's QGL modules draw with: the
XMB icons, the wave and sparks, the music-player visualisers, the theme
fragments and the store pages.  Each one is a CXML container behind one of
two wrappers:

    QRCC | u32 unpacked length | zlib stream of a whole QRCF file
    QRCF | u32 0x110           | the container image (stored, not compressed)

so a QRCC's payload is a complete QRCF *file*, magic and all.  Only
``icontex.qrc`` ships as QRCF; the other seven are QRCC.

The QRCF image starts with its own header:

    0x00  "QRCF"
    0x04  u32 header block length (0x110 in every 2.xx-4.xx container)
    0x08  u32 tree offset (0x40)
    0x0C  u32 end of the tree area
    0x10  u32 name pool offset
    0x14  u32 name pool length, as the console counts it
    0x18  u32 attribute-name pool offset
    0x1C  u32 node count class (27, or 32 for icontex)
    0x20  u32 ...
    0x30  u32 data offset
    0x34  u32 data length

Both pools are a repeated ``u32 value || NUL-terminated string``; the name
pool holds the resources' own paths (``lib/rhm/Clear.fpo``,
``override/black/ICONS.mnu``, ...), the attribute pool holds ``qrc``,
``file-table``, ``file``, ``src``, ``id``.  The values in the name pool run
0x38, 0x74, 0xB0 ... (a 0x3C stride) and are the tree's own record pointers,
not sizes: the individual resource's byte range is a field of the matching
0x3C-byte tree record, which this tool leaves to the guest and to the CXML
decompilers named in PS3_MODEL.md.  What it does give you is the container's
integrity, its whole-image dump and a rebuild that is byte for byte the
original.

The files are referenced by size and MD5 below so ``id`` can say which
firmware window a tree came from; the table is the public one (psdevwiki,
``QRC`` and ``CXML Containers`` pages).

    py scripts/ps3_qrc.py id  /path/to/rs3/dev_flash/vsh/resource/qgl
    py scripts/ps3_qrc.py list raf.qrc
    py scripts/ps3_qrc.py inflate raf.qrc -o raf.qrcf
    py scripts/ps3_qrc.py pack raf.qrcf -o raf.qrc
    py scripts/ps3_qrc.py verify *.qrc

No key and no Sony code is involved: a QRC is compressed, never encrypted.
"""

import argparse
import hashlib
import os
import struct
import sys
import zlib

HEADER_BLOCK = 0x110
# The lowest offset a name pool may sit at: magic, the 0x110 block, the tree.
POOL_MIN = 0x40

# The public QRC table: (versions, size, md5).  Sizes are bytes and MD5s are
# upper-case hex, as published.  ``id`` prefers a unique MD5 match; the size
# narrows it down when a row's hash is not in the table.
TABLES = {
    "icons.qrc": [
        ("1.00~1.02", 1288734, "451016CFB126C6D050EC5B19ABB93548"),
        ("1.10", 1307885, "1B265A359BB59CBE8E3348A2F9B288A1"),
        ("1.11~1.32", 1317777, "D434CE9BC9AA04C0CDF834DAF82D5A3D"),
        ("1.50~1.54", 1317505, "C0A0FE2D84FB7A68C96A4FB07401286C"),
        ("1.60~1.70", 697758, "44B0B9B26FBF5FC1EB9045E5349EC58A"),
        ("1.80~1.82", 736754, "9877952A1CCB9A032B8706E21DF084E9"),
        ("1.90", 752563, "835647C1B7C921109912DA92EC557E15"),
        ("1.92~1.94", 752564, "7B056E396B5ECBF2B969A71D31C6EB6E"),
        ("2.00~2.01", 30170, "4C5F6FEAC323C9DF834C91171DB617AD"),
        ("2.10~2.36", 30318, "BAD026CDEA08D3922A2758FC57BC04ED"),
        ("2.40~2.43", 29711, "6F035289BD16E3243C9049F87BF08336"),
        ("2.50~2.60", 29705, "848AEF795AE0A22B95398DC89D294654"),
        ("2.70~2.80", 29495, "8B91CD5744D56A64D26D077CF3DCED3E"),
        ("3.00~3.21", 32820, "EECFD7C3B62ECB2169AEC89F9ABEC3C6"),
        ("3.30", 32912, "3B4BD372A29B2FF36A15A0F6D0CB1482"),
        ("3.40~3.42", 32229, "D33497D781EAAA32A4B98B684C073E7D"),
        ("3.50~3.74", 32171, "97342FFE4E3B427E9C2133C1BB6A3BB4"),
        ("4.00~4.01", 32313, "653256BA53207780962A33D1E64A7758"),
        ("4.10~4.89", 32171, "97342FFE4E3B427E9C2133C1BB6A3BB4"),
    ],
    "icontex.qrc": [
        ("2.00~2.01", 707152, "020BA022EBBC7FA96C77FA01CE351F26"),
        ("2.10~2.36", 740224, "29E7BBBB83E36A7F8E413ABA274BBC33"),
        ("2.40~2.43", 795968, "7F17470EC7ED46AB5582EB76D86F800F"),
        ("2.50~2.60", 908448, "A4F84C8427AA79F9A9CC9664E8D9FABB"),
        ("2.70~2.76", 901408, "9D0D0DB2DB104C661D98E2EF5E1C024E"),
        ("2.80", 903328, "7A48902A0B565931ABB1B01B39BCEE9C"),
        ("3.00~3.01", 1361200, "3986EF9DBDFA8F134FFFA57D59C45052"),
        ("3.10~3.30", 1386352, "60EC9CD4B06808C36413D66D0D389035"),
        ("3.40~3.61", 1426032, "9FBD278929692A82D5102C12922D9B3D"),
        ("3.65~3.74", 1413264, "A23FF4BA6E2E8C3E7FA1C9F10E3484CB"),
        ("4.00~4.89", 1431936, "90146D3F374EC92EBED34535E90CD298"),
    ],
    "lines.qrc": [
        ("1.00~1.02", 110923, "FCC5B919D343533737E33C2ED566EF03"),
        ("1.10~1.32", 111371, "36A05C991491A281147B241A1338C833"),
        ("1.50~1.54", 111177, "EFBAF47613D96E620329404AA890A2B9"),
        ("1.60~1.70", 111108, "EB6258CEC5A1448138EC02D6444C4C3D"),
        ("1.80~1.82", 109685, "720DB784E69BF03C26AC38B3F161C49A"),
        ("1.90", 131246, "D7D34772AAE942017993A56AD086E623"),
        ("1.92~1.94", 131227, "15E9DFB14DA89B1887C4C96564545B48"),
        ("2.00~2.01", 131433, "665981A0A66C01A6C96269A24F4765E6"),
        ("2.10~2.17", 131602, "1BD253021A2B4E3864B026670BF96E89"),
        ("2.20~2.36", 115785, "98DA94D76B0E125A85DF2BBF7423F4E8"),
        ("2.40~2.43", 99050, "80E15C5B1E70799B2B0F0D93B8180B34"),
        ("2.50~2.60", 98972, "9AE4A67090D078055787D195E2E1043E"),
        ("2.70~2.76", 98633, "64966A9E622BCB06B1F0E86D3B32FB01"),
        ("2.80", 98633, "5AEF33A9A6E787CE3126D0CA780DD2DA"),
        ("3.00~3.01", 183383, "94D935914BD2F48519799803897ABED5"),
        ("3.10~3.21", 183798, "A757DCE0C90559AAFAB296DE6D5A8AE5"),
        ("3.30", 183980, "3CDBDD7ADC3BB39D3C17B90A81EF7015"),
        ("3.40~3.42", 183874, "7981D59C7EF731DD0C23EB2681A79FBA"),
        ("3.50", 183980, "E102D35341DC27F6EE2DC975C0118C1A"),
        ("3.55~3.56", 183981, "A50F1DC98A9EDACBDB7C0B010B369736"),
        ("3.60~3.66", 183980, "D519ECFAC71AB7437AAA6E1C70BDDE4E"),
        ("3.70~3.74", 183984, "961BCCD9CE30D5E579F3ADB157A89EA6"),
        ("4.00~4.01", 185047, "93687AF9491974446D62F40A0E61BA3F"),
        ("4.10~4.11", 185115, "FEED5630296382AE8B7C9F811A12AB80"),
        ("4.20~4.31", 185115, "405F4E3F76CBD7FD2E99AACD7431DB09"),
        ("4.40~4.55", 185116, "D34D7E2A7DE4502E0454FD787A00A35C"),
        ("4.60~4.89", 185105, "261CD31A2516EF85A6D3B584C9BD02C5"),
    ],
    "raf.qrc": [
        ("2.70~2.80", 5532, "79B5E301CB12BB0AC53B39634FD918A8"),
        ("3.00~3.01", 5565, "833C5E1D22303EA35AADCC17F25F61AC"),
        ("3.10~3.21", 5572, "07BA8A61785C471242740F915056F0F5"),
        ("3.30", 5542, "FA2388076A217DAFD9A1FD123AF4C847"),
        ("3.40~3.42", 5550, "9566444DFE340CAA9B9B58AD026E9775"),
        ("3.50~3.74", 5542, "FA2388076A217DAFD9A1FD123AF4C847"),
        ("4.00~4.01", 5479, "B7490AB764B7BC0F9B71A4782C0BAAE7"),
        ("4.10~4.89", 5457, "1FCC497E937FDC6CDAD6A1707C9CD187"),
    ],
    "rhm.qrc": [
        ("1.00~1.32", 1205, "D1E7281246EC8A46EB6D368BD4B332BD"),
        ("1.50~1.94", 1142, "80951055E3973ECCC8BF7E41D6E4BFDD"),
        ("2.00~2.01", 1139, "98305A00173927E5D947027BFE1CA0DE"),
        ("2.10~2.60", 1142, "80951055E3973ECCC8BF7E41D6E4BFDD"),
        ("2.70~2.80", 1141, "3118E99D109DE85724C54E3C15C17129"),
        ("3.00~3.74", 2489, "12B8D3A7CDFB3CAF66848704027A44E7"),
        ("4.00~4.89", 2487, "99F008FE3C2BACB937BFC925004E6E99"),
    ],
    "canyon.qrc": [
        ("1.00~1.02", 72726, "0F1B5E3CD6057B71BAF18F3154CD5B8C"),
        ("1.10~1.32", 72912, "E2C2A3374AED0964EB33FBB2CD987798"),
        ("1.50~1.54", 72777, "5F68DBE12F25178C3777898CCF442945"),
        ("1.60~1.70", 73030, "084513247EC6C3B6853C8A8DE669FF8C"),
        ("1.80~1.82", 73464, "3F936EDB8865DE2F8895F176496600FB"),
        ("1.90", 73467, "3717F76B98A3EE4C5BFDDC79E746AC53"),
        ("1.92~1.94", 73459, "FEB1A93499BABB48F215580B932E604C"),
        ("2.00~2.01", 73438, "1EAA9921CA2EC20B2B15400F585150E7"),
        ("2.10~2.36", 73614, "7BAAC386D22BEAF59E8818DE8B5D41BF"),
        ("2.40~2.43", 73897, "3F4EC983D33875CCCD3B5A21AD6AB8C2"),
        ("2.50~2.60", 73884, "83FDE07A293C487844306395C3258C82"),
        ("2.70~2.80", 73847, "8A8123CD7FC907C537EFFB346C353F5F"),
        ("3.00~3.30", 73836, "134EEB4B4027256C4F7C5271ED5F1BBA"),
        ("3.40~3.42", 73794, "D346902DC44A5E9B65C28B10D9C98C86"),
        ("3.50~3.74", 73828, "053DA0D0ED6B336E12665D41F0A18387"),
        ("4.00~4.01", 73950, "B252D14574F1B72019A1444E68C11639"),
        ("4.10~4.31", 73840, "81335553D8C52C39B84A623FAAC20416"),
        ("4.40~4.89", 73828, "053DA0D0ED6B336E12665D41F0A18387"),
    ],
    "earth.qrc": [
        ("2.00", 400569, "0CF5F811709875C7513EB7EF3D6A4093"),
        ("2.01", 400582, "F12DBB64403808908A0682CF0CEFEF15"),
        ("2.10~2.17", 2155425, "F652752780B5C3567872A2540C7E9471"),
        ("2.20~2.36", 2156458, "CE3FE6DDEE6126CA6EE07E65DA82ADA0"),
        ("2.40~2.43", 2152811, "CA48FE2B62473602808154B132684922"),
        ("2.50~2.60", 2152637, "3C289F94B5601135DE9A1E288EB0F30D"),
        ("2.70~2.76", 2144961, "7953F2CF91EDD2BB6409F6DE7B48B704"),
        ("2.80", 2145029, "EAFDAC5D044796B22606E06B86E85638"),
        ("3.00~3.01", 2148260, "C6E70369FA95B0CA107989524C30BF6E"),
        ("3.10~3.21", 2148378, "6CDF7D52C5ADAC9B048E9D0C45A19AA7"),
        ("3.30", 2148553, "7B09A088BF169AB486FEDB6C569BACFB"),
        ("3.40~3.42", 2148711, "43475D5E4B7E8FB223061A3BAFFC8213"),
        ("3.50", 2148512, "0DB0C5118B06F7D3C8B4C73AD7B0E443"),
        ("3.55~3.56", 2148509, "136A3DFDE7C60A34CFF3D4A7BBDCCDE4"),
        ("3.60~3.66", 2148514, "AA7A02DFCA99E167DA347933B95B7DF4"),
        ("3.70~3.74", 2148514, "5CF1F3694ECDBB75A6461FD6C85A5971"),
        ("4.00~4.01", 2147749, "0A7C4A327CCD63614E55686FBE6FCCBA"),
        ("4.10~4.11", 2147272, "A05BCDD9504D7111FBD9810D25217D3F"),
        ("4.20~4.31", 2147272, "30002327D89E49CE2760881444A522C1"),
        ("4.40~4.89", 2147218, "BEDFE56680ED40807C53E61603C76E1D"),
    ],
    "store.qrc": [
        ("2.50~2.53", 195383, "5E7AF90288C53BEBF729FF8182471C7F"),
        ("2.60", 291798, "0E2298E39927AE2C632B7544E99262FD"),
        ("2.70~2.80", 291369, "301B589E1D330FC6148A9C50F1763A39"),
        ("3.00~3.21", 291386, "B105F15C8C7A4337F80C3AA52469581C"),
        ("3.30", 291393, "20E92F5465AD6FC2AADF7D04BDBA668F"),
        ("3.40~3.42", 291254, "929D93182B08E41ED01AC45E59513DEC"),
        ("3.50~3.56", 291393, "20E92F5465AD6FC2AADF7D04BDBA668F"),
        ("3.60~3.74", 291241, "63D551B86EC752837E9824A2E4E4FECF"),
        ("4.00~4.01", 291317, "F7322AEC80109A0B79F2691B0049E561"),
        ("4.10~4.26", 291210, "F89887A9CEF9B8ED942DF6D8C5AC313D"),
        ("4.30~4.31", 291238, "BD559BD848D4116EF073B49FF0C2DF4F"),
        ("4.40~4.89", 291224, "5E551FE46DCA11258A29031128E8D998"),
    ],
}

# What the modules draw with, so ``list`` says more than "a container".
ROLES = {
    "icons.qrc": "XMB icon fragments (FPO/VPO), menu settings (MNU)",
    "icontex.qrc": "XMB icon textures (DDS), the themeable set",
    "lines.qrc": "XMB wave and sparks, wallpapers, music visualiser (MNU)",
    "rhm.qrc": "render helper fragments (blur, copy, cone filter)",
    "raf.qrc": "coldboot.raf plus the theme fragments (P3T)",
    "canyon.qrc": "music player visualiser 'valley'",
    "earth.qrc": "music player visualiser 'gaia' (the earth)",
    "store.qrc": "PlayStation Store pages",
}


class QrcError(Exception):
    pass


def be32(buf, at):
    if at + 4 > len(buf):
        raise QrcError("0x%X is past the end of the container" % at)
    return struct.unpack_from(">I", buf, at)[0]


def load(path):
    """Read a .qrc and return (kind, wrapper, image, unpacked_length)."""
    try:
        raw = open(path, "rb").read()
    except OSError as exc:
        raise QrcError(str(exc))
    if len(raw) < 8:
        raise QrcError("not a QRC: %d byte(s)" % len(raw))
    magic = raw[:4]
    field = be32(raw, 4)
    if magic == b"QRCC":
        try:
            image = zlib.decompress(raw[8:])
        except zlib.error as exc:
            raise QrcError("the zlib stream does not inflate: %s" % exc)
        if len(image) != field:
            raise QrcError("the wrapper says 0x%X byte(s) unpacked, the "
                           "stream gave 0x%X" % (field, len(image)))
        if image[:4] != b"QRCF":
            raise QrcError("the unpacked image starts %r, not QRCF"
                           % image[:4])
        return "QRCC", raw, image, field
    if magic == b"QRCF":
        if field != HEADER_BLOCK:
            raise QrcError("a QRCF file carries 0x%X as its header block, "
                           "not 0x%X" % (field, HEADER_BLOCK))
        return "QRCF", raw, raw, len(raw)
    raise QrcError("not a QRC: the first four bytes are %r" % magic)


def fields(image):
    return {
        "header": be32(image, 0x04),
        "tree": be32(image, 0x08),
        "tree_end": be32(image, 0x0C),
        "pool": be32(image, 0x10),
        "pool_len": be32(image, 0x14),
        "attrs": be32(image, 0x18),
        "nodes": be32(image, 0x1C),
        "data": be32(image, 0x30),
        "data_len": be32(image, 0x34),
    }


def pool(image, start, end):
    """The name pool: repeated u32 value followed by a NUL-terminated name."""
    out = []
    at = start
    while at + 4 < end:
        value = be32(image, at)
        nul = image.find(b"\0", at + 4, end)
        if nul < 0:
            break
        name = image[at + 4:nul]
        if not name:
            break
        out.append((value, name.decode("utf-8", "replace")))
        at = nul + 1
    return out


def strings(image, start, end):
    """The attribute pool: plain NUL-separated names, no value in front."""
    out = []
    at = start
    while at < end:
        nul = image.find(b"\0", at, end)
        if nul < 0:
            break
        name = image[at:nul]
        if not name:
            break
        out.append(name.decode("utf-8", "replace"))
        at = nul + 1
    return out


def fingerprint(path, size, digest):
    """The published rows that match, newest last."""
    table = TABLES.get(os.path.basename(path))
    if not table:
        return []
    hits = [row for row in table if row[1] == size and row[2] == digest]
    if hits:
        return hits
    return [row for row in table if row[1] == size]


def describe(path, verbose, brief=False):
    kind, raw, image, unpacked = load(path)
    f = fields(image)
    digest = hashlib.md5(raw).hexdigest().upper()
    names = pool(image, f["pool"], f["attrs"])
    attrs = strings(image, f["attrs"], f["data"] if f["data"] > f["attrs"]
                    else len(image))
    rows = fingerprint(path, len(raw), digest)
    if brief:
        versions = ", ".join(row[0] for row in rows
                             if row[2] == digest) or "not in the table"
        print("%-12s %s %8d  %s  %s  %u name(s)"
              % (os.path.basename(path), kind, len(raw), digest,
                 versions, len(names)))
        return kind, raw, image, f, names
    print("%s: %s, %d byte(s) on disk, %d byte(s) in the image"
          % (os.path.basename(path), kind, len(raw), len(image)))
    print("  md5      %s" % digest)
    if rows:
        for versions, size, md5 in rows:
            mark = "exact" if md5 == digest else "size only"
            print("  firmware %s (%s)" % (versions, mark))
    else:
        print("  firmware not in the table (size %d, md5 %s)"
              % (len(raw), digest))
    role = ROLES.get(os.path.basename(path))
    if role:
        print("  holds    %s" % role)
    print("  header   0x%X block, tree 0x%X..0x%X, %u node class"
          % (f["header"], f["tree"], f["tree_end"], f["nodes"]))
    print("  pools    names 0x%X (%u), attributes 0x%X (%u)"
          % (f["pool"], len(names), f["attrs"], len(attrs)))
    print("  data     0x%X + 0x%X = 0x%X%s"
          % (f["data"], f["data_len"], f["data"] + f["data_len"],
             "" if f["data"] + f["data_len"] == len(image)
             else " (the file ends at 0x%X)" % len(image)))
    if verbose and names:
        print("  names    %u" % len(names))
        for value, name in names:
            print("    0x%06X  %s" % (value, name))
    if verbose and attrs:
        print("  attrs    %s" % " ".join(attrs))
    return kind, raw, image, f, names


def check(path):
    """Structural checks plus the compression round trip."""
    problems = []
    kind, raw, image, f, names = describe(path, verbose=False, brief=True)
    if f["tree"] < 0x08 or f["tree"] >= len(image):
        problems.append("tree offset 0x%X is outside the image" % f["tree"])
    if not (POOL_MIN <= f["pool"] <= f["attrs"] <= len(image)):
        problems.append("the pools are not ordered inside the image "
                        "(names 0x%X, attributes 0x%X)"
                        % (f["pool"], f["attrs"]))
    if not names:
        problems.append("the name pool is empty")
    if f["data"] + f["data_len"] != len(image):
        problems.append("the data area 0x%X+0x%X does not end at the file's "
                        "0x%X" % (f["data"], f["data_len"], len(image)))
    if kind == "QRCC":
        again = zlib.compress(image, 9)
        if again != raw[8:]:
            problems.append("the zlib stream is not what level 9 produces "
                            "(0x%X byte(s) against 0x%X); the container still "
                            "inflates, but it was not written by this "
                            "compressor" % (len(again), len(raw) - 8))
    for problem in problems:
        print("  FAIL     %s" % problem)
    return not problems


def main(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("id", help="what firmware a tree's .qrc files are from")
    p.add_argument("paths", nargs="+")

    p = sub.add_parser("list", help="header, pools and names of a container")
    p.add_argument("path")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="print every name and attribute")

    p = sub.add_parser("inflate", help="write the QRCF image of a container")
    p.add_argument("path")
    p.add_argument("-o", "--output")

    p = sub.add_parser("pack", help="compress a QRCF image back to a QRCC file")
    p.add_argument("path")
    p.add_argument("-o", "--output")

    p = sub.add_parser("verify", help="check containers and their round trip")
    p.add_argument("paths", nargs="+")

    args = ap.parse_args(argv)

    def expand(paths):
        """A directory is read for its .qrc files, or for vsh/resource/qgl/."""
        out = []
        for path in paths:
            if not os.path.isdir(path):
                out.append(path)
                continue
            qgl = os.path.join(path, "vsh", "resource", "qgl")
            where = qgl if os.path.isdir(qgl) else path
            out.extend(os.path.join(where, n) for n in sorted(os.listdir(where))
                       if n.endswith(".qrc"))
        return out

    try:
        if args.cmd == "id":
            bad = 0
            for path in expand(args.paths):
                kind, raw, image, f, names = describe(path, verbose=False,
                                                      brief=True)
                if not fingerprint(path, len(raw),
                                   hashlib.md5(raw).hexdigest().upper()):
                    bad += 1
            return 1 if bad else 0

        if args.cmd == "list":
            kind, raw, image, f, names = describe(args.path, args.verbose)
            return 0

        if args.cmd == "inflate":
            kind, raw, image, unpacked = load(args.path)
            out = args.output or os.path.splitext(args.path)[0] + ".qrcf"
            if os.path.exists(out):
                raise QrcError("%s exists; remove it first" % out)
            with open(out, "wb") as fh:
                fh.write(image)
            print("%s: %d byte(s) of QRCF written to %s"
                  % (args.path, len(image), out))
            return 0

        if args.cmd == "pack":
            try:
                image = open(args.path, "rb").read()
            except OSError as exc:
                raise QrcError(str(exc))
            if image[:4] != b"QRCF":
                raise QrcError("%s does not start with QRCF" % args.path)
            body = zlib.compress(image, 9)
            blob = b"QRCC" + struct.pack(">I", len(image)) + body
            if zlib.decompress(blob[8:]) != image:
                raise QrcError("the rebuilt stream does not inflate back")
            out = args.output or os.path.splitext(args.path)[0] + ".qrc"
            if os.path.exists(out):
                raise QrcError("%s exists; remove it first" % out)
            with open(out, "wb") as fh:
                fh.write(blob)
            print("%s: %d byte(s) -> %s (%d byte(s), %d packed)"
                  % (args.path, len(image), out, len(blob), len(body)))
            return 0

        failed = 0
        for path in expand(args.paths):
            ok = check(path)
            print("%s: %s" % (path, "ok" if ok else "FAILED"))
            failed += 0 if ok else 1
        return 1 if failed else 0

    except QrcError as exc:
        paths = getattr(args, "paths", None) or [args.path]
        print("%s: %s" % (", ".join(paths), exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
