package sniff

import (
	"fmt"
	"hash/fnv"
	"image"
	"image/color"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unicode"

	"golang.org/x/image/draw"
	"golang.org/x/image/font"
	"golang.org/x/image/font/gofont/gobold"
	"golang.org/x/image/font/gofont/goregular"
	"golang.org/x/image/font/opentype"
	"golang.org/x/image/math/fixed"

	"homebrew-eshop/internal/catalog"
)

// Shop artwork. The user's own images in ArtDir win; anything without one gets an original generated image.
//
//	<ArtDir>/categories/<slug>.png|jpg        top-screen banner for a category (400x240), e.g. all-homebrew.png
//	<ArtDir>/categories/<slug>-tile.png|jpg   its tile in the menu carousel (128x96)
//	<ArtDir>/titles/<key>.png|jpg             a title's top-screen banner (400x240)
//	<ArtDir>/titles/<key>-icon.png|jpg        a title's icon (128x128)
//	<ArtDir>/telops.txt                       ticker lines, one per line
//
// <key> is the 16-digit title ID (0004000000123400) or the name as a slug (balatro3ds). Images of any size are
// scaled to fit. Category slugs are the shown names, lowercased with dashes: all-homebrew, my-backups, games...

// Slug lowercases a name and joins its words with dashes.
func Slug(name string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(name) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			if dash && b.Len() > 0 {
				b.WriteByte('-')
			}
			b.WriteRune(r)
			dash = false
		} else {
			dash = true
		}
	}
	return b.String()
}

// userArt loads <ArtDir>/<sub>/<name>.png or .jpg/.jpeg, trying each name in turn; nil if there is none.
func (s *Shop) userArt(sub string, names ...string) image.Image {
	if s.ArtDir == "" {
		return nil
	}
	for _, n := range names {
		if n == "" {
			continue
		}
		for _, ext := range []string{".png", ".jpg", ".jpeg"} {
			f, err := os.Open(filepath.Join(s.ArtDir, sub, n+ext))
			if err != nil {
				continue
			}
			img, _, err := image.Decode(f)
			f.Close()
			if err == nil {
				return img
			}
		}
	}
	return nil
}

func titleArtNames(t *catalog.Title, suffix string) []string {
	var out []string
	if t.TitleID != 0 {
		out = append(out, fmt.Sprintf("%016X", t.TitleID)+suffix, fmt.Sprintf("%016x", t.TitleID)+suffix)
	}
	return append(out, Slug(t.Name)+suffix)
}

// artVersion changes whenever the files in ArtDir change, so cached images made from them are redone.
func (s *Shop) artVersion() string {
	if s.ArtDir == "" {
		return "0"
	}
	h := fnv.New32a()
	filepath.WalkDir(s.ArtDir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if fi, err := d.Info(); err == nil {
				fmt.Fprintf(h, "%s %d %d\n", p, fi.Size(), fi.ModTime().UnixNano())
			}
		}
		return nil
	})
	return fmt.Sprintf("%08x", h.Sum32())
}

// Telops are the ticker lines: <ArtDir>/telops.txt if it has any, else the default.
func (s *Shop) Telops() []string {
	if s.ArtDir != "" {
		if data, err := os.ReadFile(filepath.Join(s.ArtDir, "telops.txt")); err == nil {
			var out []string
			for _, l := range strings.Split(string(data), "\n") {
				if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
					out = append(out, l)
				}
			}
			if len(out) > 0 {
				return out
			}
		}
	}
	n := 0
	for _, t := range s.Titles() {
		if t.CIA != nil && !t.Backup {
			n++
		}
	}
	return []string{fmt.Sprintf("Welcome to the homebrew eShop: %d apps from the community, free to download.", n)}
}

// --- generated artwork ---

var palette = []color.RGBA{{0xF2, 0x8C, 0x28, 0xFF}, {0x2E, 0x86, 0xDE, 0xFF}, {0x27, 0xAE, 0x60, 0xFF},
	{0x8E, 0x44, 0xAD, 0xFF}, {0xE7, 0x4C, 0x3C, 0xFF}, {0x16, 0xA0, 0x85, 0xFF}, {0xD3, 0x54, 0x00, 0xFF},
	{0x2C, 0x3E, 0x50, 0xFF}, {0xC0, 0x39, 0x2B, 0xFF}}

func dirColor(id int) color.RGBA {
	if id == backupsDirID {
		return color.RGBA{0x1F, 0x6F, 0x8B, 0xFF}
	}
	return palette[(id-1+len(palette))%len(palette)]
}

func shade(c color.RGBA, d int) color.RGBA {
	f := func(v uint8) uint8 { return uint8(max(0, min(255, int(v)+d))) }
	return color.RGBA{f(c.R), f(c.G), f(c.B), 0xFF}
}

var (
	fontOnce      sync.Once
	boldTT, regTT *opentype.Font
	faceMu        sync.Mutex
	faces         = map[string]font.Face{}
)

func face(bold bool, size float64) font.Face {
	fontOnce.Do(func() {
		boldTT, _ = opentype.Parse(gobold.TTF)
		regTT, _ = opentype.Parse(goregular.TTF)
	})
	key := fmt.Sprint(bold, size)
	faceMu.Lock()
	defer faceMu.Unlock()
	if f := faces[key]; f != nil {
		return f
	}
	tt := regTT
	if bold {
		tt = boldTT
	}
	f, _ := opentype.NewFace(tt, &opentype.FaceOptions{Size: size, DPI: 72, Hinting: font.HintingFull})
	faces[key] = f
	return f
}

// fitText breaks s into at most maxLines lines no wider than w, shrinking the font from size down to minSize
// until it fits (the last line is cut with "..." if it still doesn't).
func fitText(s string, bold bool, size, minSize float64, w, maxLines int) (font.Face, []string) {
	for ; ; size -= 2 {
		f := face(bold, size)
		lines := wrap(f, s, w)
		fits := len(lines) <= maxLines
		for _, l := range lines {
			fits = fits && font.MeasureString(f, l).Ceil() <= w
		}
		if fits || size <= minSize {
			if len(lines) > maxLines {
				lines = lines[:maxLines]
				last := lines[maxLines-1]
				for font.MeasureString(f, last+"...").Ceil() > w && len(last) > 0 {
					last = last[:len(last)-1]
				}
				lines[maxLines-1] = last + "..."
			}
			return f, lines
		}
	}
}

func wrap(f font.Face, s string, w int) []string {
	var lines []string
	cur := ""
	for _, word := range strings.Fields(s) {
		try := word
		if cur != "" {
			try = cur + " " + word
		}
		if font.MeasureString(f, try).Ceil() <= w || cur == "" {
			cur = try
		} else {
			lines = append(lines, cur)
			cur = word
		}
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	return lines
}

func drawText(dst draw.Image, f font.Face, x, y int, c color.Color, s string) {
	d := font.Drawer{Dst: dst, Src: image.NewUniform(c), Face: f, Dot: fixed.P(x, y)}
	d.DrawString(s)
}

// background fills dst with c and a pattern of soft diagonal stripes.
func background(dst *image.RGBA, c color.RGBA) {
	b := dst.Bounds()
	light := shade(c, 18)
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			if ((x+y)/24)%2 == 0 {
				dst.SetRGBA(x, y, light)
			} else {
				dst.SetRGBA(x, y, c)
			}
		}
	}
	// darker band along the bottom, where the shop overlays its balance bar
	draw.Draw(dst, image.Rect(b.Min.X, b.Max.Y-36, b.Max.X, b.Max.Y), image.NewUniform(shade(c, -30)), image.Point{}, draw.Src)
}

// card draws icon on a white rounded card with a drop shadow, sized s, top-left at (x, y).
func card(dst *image.RGBA, icon image.Image, x, y, s int) {
	r := s / 10
	shadow := color.RGBA{0, 0, 0, 0x50}
	roundRect(dst, image.Rect(x+4, y+5, x+s+4, y+s+5), r, shadow)
	roundRect(dst, image.Rect(x, y, x+s, y+s), r, color.RGBA{0xFF, 0xFF, 0xFF, 0xFF})
	pad := s / 14
	in := image.Rect(x+pad, y+pad, x+s-pad, y+s-pad)
	if icon != nil {
		draw.CatmullRom.Scale(dst, in, icon, icon.Bounds(), draw.Over, nil)
	}
}

func roundRect(dst *image.RGBA, rc image.Rectangle, r int, c color.RGBA) {
	for y := rc.Min.Y; y < rc.Max.Y; y++ {
		for x := rc.Min.X; x < rc.Max.X; x++ {
			dx, dy := 0, 0
			if x < rc.Min.X+r {
				dx = rc.Min.X + r - x
			} else if x >= rc.Max.X-r {
				dx = x - (rc.Max.X - r - 1)
			}
			if y < rc.Min.Y+r {
				dy = rc.Min.Y + r - y
			} else if y >= rc.Max.Y-r {
				dy = y - (rc.Max.Y - r - 1)
			}
			if dx*dx+dy*dy > r*r {
				continue
			}
			if c.A == 0xFF {
				dst.SetRGBA(x, y, c)
			} else {
				o := dst.RGBAAt(x, y)
				a := int(c.A)
				mix := func(f, b uint8) uint8 { return uint8((int(f)*a + int(b)*(255-a)) / 255) }
				dst.SetRGBA(x, y, color.RGBA{mix(c.R, o.R), mix(c.G, o.G), mix(c.B, o.B), 0xFF})
			}
		}
	}
}

// dirBanner is a category's top-screen banner: its name and size on the left, a fan of its first icons right.
func dirBanner(d shopDir, icons []image.Image) image.Image {
	img := image.NewRGBA(image.Rect(0, 0, 400, 240))
	background(img, dirColor(d.id))
	white := color.RGBA{0xFF, 0xFF, 0xFF, 0xFF}
	f, lines := fitText(d.name, true, 40, 20, 176, 2)
	y := 92
	if len(lines) == 2 {
		y = 74
	}
	for _, l := range lines {
		drawText(img, f, 22, y, white, l)
		y += f.Metrics().Height.Ceil()
	}
	label := fmt.Sprintf("%d apps", len(d.titles))
	if len(d.titles) == 1 {
		label = "1 app"
	}
	if d.id == backupsDirID {
		label = fmt.Sprintf("%d from your PC", len(d.titles))
	}
	drawText(img, face(true, 18), 24, y+6, color.RGBA{0xF4, 0xF4, 0xF4, 0xFF}, label)

	// up to three icons, overlapping, back to front
	pos := []image.Point{{300, 46}, {248, 76}, {196, 106}}
	for i := min(len(icons), 3) - 1; i >= 0; i-- {
		card(img, icons[i], pos[i].X, pos[i].Y, 88)
	}
	return img
}

// dirTile is a category's tile in the menu carousel (128x96): its colour and up to four of its icons.
func dirTile(d shopDir, icons []image.Image) image.Image {
	img := image.NewRGBA(image.Rect(0, 0, 128, 96))
	background(img, dirColor(d.id))
	draw.Draw(img, image.Rect(0, 60, 128, 96), image.NewUniform(dirColor(d.id)), image.Point{}, draw.Src)
	switch n := min(len(icons), 4); {
	case n == 0:
		f, lines := fitText(d.name, true, 18, 10, 112, 2)
		y := 40
		for _, l := range lines {
			drawText(img, f, 8, y, color.White, l)
			y += f.Metrics().Height.Ceil()
		}
	default:
		// the first icon large in the middle, the next two smaller behind it on either side
		if n > 2 {
			card(img, icons[2], 84, 26, 38)
		}
		if n > 1 {
			card(img, icons[1], 6, 26, 38)
		}
		card(img, icons[0], 36, 12, 56)
	}
	return img
}

// titleBanner is a title's top-screen banner when it has no artwork of its own: its icon, name and author on
// a background in the icon's main colour.
func titleBanner(t *catalog.Title, icon image.Image) image.Image {
	img := image.NewRGBA(image.Rect(0, 0, 400, 240))
	c := color.RGBA{0x55, 0x5F, 0x6B, 0xFF}
	if icon != nil {
		c = mainColor(icon)
	}
	background(img, c)
	text := color.RGBA{0xFF, 0xFF, 0xFF, 0xFF}
	sub := shade(c, 100)
	if lum(c) > 170 { // light icon colour: dark text
		background(img, shade(c, -10))
		text, sub = color.RGBA{0x22, 0x22, 0x22, 0xFF}, shade(c, -110)
	}
	card(img, icon, 262, 44, 116)
	f, lines := fitText(t.Name, true, 34, 18, 220, 3)
	y := 80
	for _, l := range lines {
		drawText(img, f, 22, y, text, l)
		y += f.Metrics().Height.Ceil()
	}
	if t.Author != "" {
		af, al := fitText(t.Author, false, 17, 12, 220, 1)
		drawText(img, af, 24, y+4, sub, al[0])
	}
	return img
}

func lum(c color.RGBA) int { return (int(c.R)*299 + int(c.G)*587 + int(c.B)*114) / 1000 }

// mainColor is the average of the icon's more saturated pixels (falling back to all pixels), darkened a little
// so white text reads on it.
func mainColor(img image.Image) color.RGBA {
	b := img.Bounds()
	var r, g, bl, n, ar, ag, ab, an int
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			cr, cg, cb, ca := img.At(x, y).RGBA()
			if ca < 0x8000 {
				continue
			}
			R, G, B := int(cr>>8), int(cg>>8), int(cb>>8)
			ar, ag, ab, an = ar+R, ag+G, ab+B, an+1
			if max(R, G, B)-min(R, G, B) > 60 {
				r, g, bl, n = r+R, g+G, bl+B, n+1
			}
		}
	}
	if n < an/10 || n == 0 {
		r, g, bl, n = ar, ag, ab, an
	}
	if n == 0 {
		return color.RGBA{0x55, 0x5F, 0x6B, 0xFF}
	}
	c := color.RGBA{uint8(r / n), uint8(g / n), uint8(bl / n), 0xFF}
	if lum(c) > 150 && lum(c) <= 170 {
		c = shade(c, -40)
	}
	return c
}
