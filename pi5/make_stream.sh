#!/bin/bash
# Encoded test streams for e6_stream.py: fragmented MP4 (CMAF-style), one
# fragment per second (GOP of one second at 30 fps), so a segment of k seconds
# is k consecutive fragments.
#
#   1080p30 H.264 at 12 Mbit/s and 4K30 HEVC at 40 Mbit/s, constrained by VBV
#   so the bitrate holds whatever the content. The picture is ffmpeg's test
#   pattern with temporal noise, which keeps the encoder at its rate target;
#   the hashing and signing cost depends on bytes, not on what they show.
#
# usage: make_stream.sh [seconds] [outdir]
set -eu
SEC=${1:-48}
OUT=${2:-$HOME/line-a-pi/streams}
mkdir -p "$OUT"
SRC="testsrc2=size=%s:rate=30,noise=alls=12:allf=t,format=yuv420p"
frag="-movflags +frag_keyframe+empty_moov+default_base_moof -g 30 -keyint_min 30 -sc_threshold 0"

ffmpeg -hide_banner -loglevel error -y -f lavfi -i "$(printf "$SRC" 1920x1080)" -t "$SEC" \
  -c:v libx264 -preset veryfast -b:v 12M -maxrate 12M -bufsize 12M $frag \
  -x264-params "keyint=30:min-keyint=30:scenecut=0" "$OUT/1080p_h264.mp4"

ffmpeg -hide_banner -loglevel error -y -f lavfi -i "$(printf "$SRC" 3840x2160)" -t "$SEC" \
  -c:v libx265 -preset ultrafast -b:v 40M -maxrate 40M -bufsize 40M $frag \
  -x265-params "keyint=30:min-keyint=30:scenecut=0:log-level=error" "$OUT/4K_hevc.mp4"

ls -l "$OUT"
