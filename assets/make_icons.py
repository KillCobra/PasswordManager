#!/usr/bin/env python3
"""
Generate raster icon assets from the shared icon design.

Draws the same padlock-on-dark-tile design as assets/icon.svg using Pillow,
then writes:
  - assets/app_icon.ico          (multi-size Windows icon for the desktop app)
  - assets/icon-<size>.png       (reference PNGs)

The Android app uses vector drawables (see android/.../drawable), so it does
not consume these PNGs, but they are handy for stores/readme.

Run: python assets/make_icons.py
"""

import os
from PIL import Image, ImageDraw

OUT_DIR = os.path.dirname(os.path.abspath(__file__))

# Palette (matches icon.svg)
BG_TOP = (37, 37, 64)      # #252540
BG_BOT = (24, 24, 37)      # #181825
LOCK_TOP = (156, 193, 255) # #9CC1FF
LOCK_BOT = (110, 155, 240) # #6E9BF0
SHACKLE = (137, 180, 250)  # #89B4FA
HOLE = (30, 30, 46)        # #1E1E2E


def _vgrad(size, top, bot):
    """Vertical gradient image."""
    img = Image.new("RGB", (1, size))
    for y in range(size):
        t = y / max(1, size - 1)
        img.putpixel((0, y), tuple(int(top[i] + (bot[i] - top[i]) * t) for i in range(3)))
    return img.resize((size, size))


def render(size):
    """Render the icon at the given square size on a supersampled canvas."""
    S = size * 4  # supersample for smooth edges
    scale = S / 512.0

    def sc(v):
        return int(round(v * scale))

    # Background rounded tile
    canvas = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    grad = _vgrad(S, BG_TOP, BG_BOT).convert("RGBA")
    mask = Image.new("L", (S, S), 0)
    ImageDraw.Draw(mask).rounded_rectangle([0, 0, S - 1, S - 1], radius=sc(112), fill=255)
    canvas.paste(grad, (0, 0), mask)

    draw = ImageDraw.Draw(canvas)

    # Shackle: an arch drawn as a thick arc + two vertical legs
    sw = sc(34)
    # Arc bounding box for the semicircle top (center x=256, radius ~80)
    draw.arc([sc(176), sc(100), sc(336), sc(260)], start=180, end=360,
             fill=SHACKLE, width=sw)
    # Legs down to the lock body top
    draw.line([sc(176), sc(180), sc(176), sc(232)], fill=SHACKLE, width=sw)
    draw.line([sc(336), sc(180), sc(336), sc(232)], fill=SHACKLE, width=sw)

    # Lock body (gradient rounded rect)
    body = _vgrad(S, LOCK_TOP, LOCK_BOT).convert("RGBA")
    body_mask = Image.new("L", (S, S), 0)
    ImageDraw.Draw(body_mask).rounded_rectangle(
        [sc(140), sc(228), sc(372), sc(416)], radius=sc(34), fill=255)
    canvas.paste(body, (0, 0), body_mask)

    draw = ImageDraw.Draw(canvas)
    # Keyhole
    draw.ellipse([sc(226), sc(274), sc(286), sc(334)], fill=HOLE)
    draw.rounded_rectangle([sc(244), sc(318), sc(268), sc(376)], radius=sc(12), fill=HOLE)

    return canvas.resize((size, size), Image.LANCZOS)


def main():
    sizes = [16, 24, 32, 48, 64, 128, 256]
    images = [render(s) for s in sizes]

    ico_path = os.path.join(OUT_DIR, "app_icon.ico")
    # Save multi-resolution ICO from the largest image.
    images[-1].save(ico_path, format="ICO",
                    sizes=[(s, s) for s in sizes])
    print("wrote", ico_path)

    for s in (256, 512):
        png = render(s)
        p = os.path.join(OUT_DIR, f"icon-{s}.png")
        png.save(p, format="PNG")
        print("wrote", p)


if __name__ == "__main__":
    main()
