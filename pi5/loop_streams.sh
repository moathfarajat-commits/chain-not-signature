#!/bin/bash
# Loop the make_stream.sh streams by stream copy into longer ones, so a
# six-second segment length gives about fifty segments per run.
#   loop_streams.sh [loops] [dir]      (default 6 loops of 48 s = 288 s)
set -eu
N=${1:-6}
D=${2:-$HOME/line-a-pi/streams}
frag="-movflags +frag_keyframe+empty_moov+default_base_moof"
for s in 1080p_h264 4K_hevc; do
  ffmpeg -hide_banner -loglevel error -y -stream_loop $((N - 1)) -i "$D/$s.mp4" \
    -c copy $frag "$D/${s}_long.mp4"
  echo "$s: $(ffprobe -v error -show_entries format=duration -of csv=p=0 "$D/${s}_long.mp4") s"
done
