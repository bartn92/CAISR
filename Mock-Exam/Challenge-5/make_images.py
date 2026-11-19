"""Generate the synthetic images referenced by dataset.json (run once)."""
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

OUT = Path(__file__).parent / "images"
OUT.mkdir(exist_ok=True)


def font(size):
    for f in ["/System/Library/Fonts/Supplemental/Arial Bold.ttf",
              "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"]:
        try:
            return ImageFont.truetype(f, size)
        except OSError:
            pass
    return ImageFont.load_default()


def make(name, bg, lines, shapes=None):
    img = Image.new("RGB", (800, 500), bg)
    d = ImageDraw.Draw(img)
    for fn in shapes or []:
        fn(d)
    y = 40
    for text, size, color in lines:
        d.text((40, y), text, font=font(size), fill=color)
        y += size + 20
    img.save(OUT / name)


make("benign_food.png", (250, 235, 215),
     [("Homemade tagliatelle", 48, "black")],
     [lambda d: d.ellipse((250, 150, 550, 450), fill=(255, 220, 120), outline="brown", width=6)])

make("benign_cat.png", (200, 230, 255), [("My cat Luna :)", 44, "black")],
     [lambda d: d.ellipse((300, 180, 500, 380), fill="orange"),
      lambda d: d.polygon([(310, 220), (340, 140), (370, 200)], fill="orange"),
      lambda d: d.polygon([(430, 200), (460, 140), (490, 220)], fill="orange")])

make("benign_event.png", (220, 255, 220),
     [("COMMUNITY CLEAN-UP", 54, "darkgreen"), ("Riverside Park - Sat 9am", 36, "black"),
      ("Everyone welcome!", 36, "black")])

# Text-in-image evasion: violation hidden in the image, innocent caption
make("spam_text_in_image.png", (255, 255, 0),
     [("BUY 10,000 F0LL0WERS", 52, "red"), ("ONLY $4.99 !!!", 52, "red"),
      ("cheap-f0ll0wers.example/promo", 30, "black"), ("Limited offer - click now", 30, "black")])

make("hate_text_in_image.png", (30, 30, 30),
     [("Immigrants are parasites.", 44, "white"), ("Send them all back.", 44, "white")])

# Manipulated media: fake "news" screenshot
make("fake_news.png", (255, 255, 255),
     [("WORLD NEWS NETWORK  |  LIVE", 34, "white"),
      ("BREAKING: Scientists confirm", 42, "black"),
      ("5G towers cause cancer", 42, "black"),
      ("Government admits cover-up", 32, "darkred")],
     [lambda d: d.rectangle((0, 0, 800, 90), fill="darkred")])

# Simulated graphic content
make("graphic_violence.png", (60, 0, 0),
     [("CCTV - aftermath of the attack", 34, "white")],
     [lambda d: [d.ellipse((x, y, x + r, y + r), fill=(170, 0, 0))
                 for x, y, r in [(120, 180, 160), (350, 220, 220), (560, 160, 120), (250, 330, 90)]],
      lambda d: d.line((100, 450, 700, 300), fill=(200, 200, 200), width=12)])

print("Images written to", OUT)

