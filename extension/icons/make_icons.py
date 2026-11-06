"""Draws the extension icons: a magnifying glass on a dark rounded square.

Standard library only. Run from this folder: python3 make_icons.py
"""
import math
import struct
import zlib

BG = (31, 35, 40)
FG = (240, 246, 252)
ACCENT = (63, 185, 80)


def inside_rounded_square(x, y, r):
    cx, cy = min(max(x, r), 1 - r), min(max(y, r), 1 - r)
    return (x - cx) ** 2 + (y - cy) ** 2 <= r * r


def dist_to_segment(px, py, ax, ay, bx, by):
    dx, dy = bx - ax, by - ay
    t = max(0, min(1, ((px - ax) * dx + (py - ay) * dy) / (dx * dx + dy * dy)))
    return math.hypot(px - ax - t * dx, py - ay - t * dy)


def color_at(x, y):
    """Colour at a point of the unit square, or None for transparent."""
    if not inside_rounded_square(x, y, 0.22):
        return None
    cx, cy, ring_r, ring_w = 0.43, 0.43, 0.22, 0.075
    d = math.hypot(x - cx, y - cy)
    if abs(d - ring_r) <= ring_w / 2:
        return FG
    if dist_to_segment(x, y, 0.60, 0.60, 0.80, 0.80) <= 0.06:
        return FG
    if d <= 0.07:
        return ACCENT
    return BG


def render(size, ss=4):
    rows = []
    for py in range(size):
        row = bytearray([0])  # PNG filter type: none
        for px in range(size):
            acc = [0, 0, 0, 0]
            for sy in range(ss):
                for sx in range(ss):
                    c = color_at((px + (sx + 0.5) / ss) / size, (py + (sy + 0.5) / ss) / size)
                    if c:
                        acc[0] += c[0]
                        acc[1] += c[1]
                        acc[2] += c[2]
                        acc[3] += 255
            n = ss * ss
            covered = acc[3] // 255
            if covered:
                row += bytes([acc[0] // covered, acc[1] // covered, acc[2] // covered, acc[3] // n])
            else:
                row += bytes(4)
        rows.append(bytes(row))
    return b"".join(rows)


def png(size):
    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))

    header = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)  # 8-bit RGBA
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header) + chunk(b"IDAT", zlib.compress(render(size), 9)) + chunk(b"IEND", b"")


if __name__ == "__main__":
    for s in (16, 32, 48, 128):
        with open(f"icon-{s}.png", "wb") as f:
            f.write(png(s))
        print(f"wrote icon-{s}.png")
