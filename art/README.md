# Your own shop artwork

Images here replace the generated ones. PNG or JPG, any size (they're scaled to fit). Changes show up the next
time the console loads the image; no restart needed.

| File | What it is | Shown at |
|---|---|---|
| `categories/<category>.png` | top-screen banner when the category's tile is selected | 400×240 |
| `categories/<category>-tile.png` | the category's tile in the menu carousel | 128×96 |
| `titles/<title>.png` | top-screen banner on a title's page | 400×240 |
| `titles/<title>-icon.png` | a title's icon | 128×128 |
| `telops.txt` | the scrolling ticker, one line per message (`#` lines are skipped) | |

`<category>` is the name shown in the shop, lowercase, words joined with dashes: `all-homebrew`, `my-backups`,
`games`, `utilities`...

`<title>` is the 16-digit title ID (`000400000BA1A700`) or the title's name the same way (`balatro3ds`).

The bottom quarter of a banner sits under the shop's balance bar, so keep important parts out of it.
