#!/usr/bin/env python3
"""
Generate raster icon assets from the shared icon design.

Draws the same padlock-on-dark-tile design used by the Android adaptive icon
foreground (assets/icon.svg), then writes:
  - assets/app_icon.ico          (multi-size Windows icon for the desktop app)
  - assets/icon-<size>.png       (reference PNGs)

Run: python assets/make_icons.py
"""

import os
from PIL import Image, ImageDraw

OUT_DIR = os.path.dirname(os.path.abspath(__file__))

# Palette
BG_TOP = (37, 37, 64)      # #252540
BG_BOT = (24, 24, 37)      # #181825
ACCENT = (137, 180, 250)   # #89B4FA
HOLE = (30, 30, 46)        # #1E1E2E

# Icon geometry is defined on a 108-unit grid to match the Android foreground,
# then scaled to the target size.
GRID = 108.0


def _vgrad(size, top, bot):
    img = Image.new("RGB", (1, size))
    for y in range(size):
        t = y / max(1, size - 1)
        img.putpixel((0, y), tuple(int(top[i] + (bot[i] - top[i]) * t) for i in range(3)))
    return img.resize((size, size))


def render(size):
    S = size * 4  # supersample
    scale = S / GRID

    def u(v):
        return v * scale

    def ui(v):
        return int(round(v * scale))

    canvas = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    grad = _vgrad(S, BG_TOP, BG_BOT).convert("RGBA")
    mask = Image.new("L", (S, S), 0)
    ImageDraw.Draw(mask).rounded_rectangle([0, 0, S - 1, S - 1], radius=ui(24), fill=255)
    canvas.paste(grad, (0, 0), mask)

    draw = ImageDraw.Draw(canvas)

    # Shackle: arch (semicircle) + legs, matching the Android art (x 42..66).
    # Center x=54, outer radius ~12 (46..66 -> radius 12 from center 54... use 12).
    draw.arc([ui(42), ui(30), ui(66), ui(54)], start=180, end=360,
             fill=ACCENT, width=ui(4))
    draw.line([ui(44), u(42), ui(44), u(52)], fill=ACCENT, width=ui(4))
    draw.line([ui(64), u(42), ui(64), u(52)], fill=ACCENT, width=ui(4))

    # Lock body: rounded rect x 34..74, y 52..80
    draw.rounded_rectangle([ui(34), ui(52), ui(74), ui(80)], radius=ui(4), fill=ACCENT)

    # Keyhole: circle + stem
    draw.ellipse([ui(50), ui(60), ui(58), ui(68)], fill=HOLE)
    draw.rounded_rectangle([ui(52), ui(66), ui(56), ui(74)], radius=ui(2), fill=HOLE)

    return canvas.resize((size, size), Image.LANCZOS)


def main():
    sizes = [16, 24, 32, 48, 64, 128, 256]
    images = [render(s) for s in sizes]

    ico_path = os.path.join(OUT_DIR, "app_icon.ico")
    images[-1].save(ico_path, format="ICO", sizes=[(s, s) for s in sizes])
    print("wrote", ico_path)

    for s in (256, 512):
        render(s).save(os.path.join(OUT_DIR, f"icon-{s}.png"), format="PNG")
        print("wrote", os.path.join(OUT_DIR, f"icon-{s}.png"))


if __name__ == "__main__":
    main()
