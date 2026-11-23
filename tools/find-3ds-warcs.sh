#!/usr/bin/env bash
# Finds which WARCs of ArchiveBot job bopw5 (the 2022 eShop 3DS/Wii U crawl) hold 3DS shop data, by downloading
# only the job's CDX indexes (small text files listing each captured URL and the WARC it's in).
#   tools/find-3ds-warcs.sh [dir]        default dir: warcs/cdx
# Needs `ia` logged in. Prints, per WARC, how many 3DS catalog replies and 3DS images it holds.
set -euo pipefail
dir=${1:-warcs/cdx}
mkdir -p "$dir"
items=(
  archiveteam_archivebot_go_20220218160002
  archiveteam_archivebot_go_20220218190002
  archiveteam_archivebot_go_20220218200002
  archiveteam_archivebot_go_20220218230001
  archiveteam_archivebot_go_20220219010002
  archiveteam_archivebot_go_20220219040001
  archiveteam_archivebot_go_20220219070001
  archiveteam_archivebot_go_20220219090001
  archiveteam_archivebot_go_20220219110002
  archiveteam_archivebot_go_20220219140001
  archiveteam_archivebot_go_20220219160001
  archiveteam_archivebot_go_20220219190001
  archiveteam_archivebot_go_20220219210001
  archiveteam_archivebot_go_20220219230001
  archiveteam_archivebot_go_20220220010001
  archiveteam_archivebot_go_20220220020002
  archiveteam_archivebot_go_20220220040001
  archiveteam_archivebot_go_20220220060001
  archiveteam_archivebot_go_20220220070001
  archiveteam_archivebot_go_20220220090001
  archiveteam_archivebot_go_20220220110001
  archiveteam_archivebot_go_20220220130001
  archiveteam_archivebot_go_20220220160001
  archiveteam_archivebot_go_20220220180002
  archiveteam_archivebot_go_20220220200001
  archiveteam_archivebot_go_20220220220001
  archiveteam_archivebot_go_20220221000002
  archiveteam_archivebot_go_20220221020002
  archiveteam_archivebot_go_20220221040001
  archiveteam_archivebot_go_20220221060001
  archiveteam_archivebot_go_20220221090001
  archiveteam_archivebot_go_20220221110002
  archiveteam_archivebot_go_20220221140001
  archiveteam_archivebot_go_20220221170001
  archiveteam_archivebot_go_20220221190001
  archiveteam_archivebot_go_20220221210001
)
for it in "${items[@]}"; do
  echo "== $it" >&2
  ia download "$it" --glob="*bopw5*.os.cdx.gz" --no-directories --destdir "$dir" >&2 || echo "   (failed: $it)" >&2
done

echo
echo "WARCs with 3DS data (catalog = samurai.ctr replies, images = kanzashi-ctr / img.ctr files):"
# CDX lines: urlkey timestamp url mime status digest redirect meta length offset filename
zcat "$dir"/*.os.cdx.gz | awk '
  $3 ~ /samurai\.ctr\.shop/ { cat[$NF]++ }
  $3 ~ /(kanzashi-ctr|img\.ctr\.shop)/ { img[$NF]++ }
  END {
    for (f in cat) all[f]=1; for (f in img) all[f]=1
    for (f in all) printf "%6d catalog %6d images  %s\n", cat[f]+0, img[f]+0, f
  }' | sort -k5
