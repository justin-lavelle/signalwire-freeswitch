#!/bin/bash
# Bridge a SIPp caller to a callee that answers a=inactive and then
# re-INVITEs a=sendrecv on the same media address. Audio toward the
# caller is dropped unless rtp-ignore-inactive-answer is on.
#
# The setting starts off. The runner checks three calls:
#   inactive_answer      global off, no channel variable: caller receives no RTP
#   inactive_answer      fsctl rtp_ignore_inactive_answer enable: caller receives RTP
#   inactive_answer_fix  global off, channel variable set: caller receives RTP
#
# Usage:
#   FS_BIN=/usr/local/freeswitch/bin/freeswitch \
#   FS_CLI=/usr/local/freeswitch/bin/fs_cli \
#   ./run_inactive_answer.sh

set -eu

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"
FS_BIN="${FS_BIN:-/usr/local/freeswitch/bin/freeswitch}"
FS_CLI="${FS_CLI:-/usr/local/freeswitch/bin/fs_cli}"
RUN="${RUN_DIR:-/tmp/inactive-answer-sipp}"
PCAP="$ROOT/sipp-scenarios/inactive_answer_pcmu.pcap"
UAC_PORT_MIN=6000
UAC_PORT_MAX=6020
DROP_MAX=10
PASS_MIN=40
FS_PID=""

mkdir -p "$RUN/conf" "$RUN/log" "$RUN/db" "$RUN/run"

fscli() {
	"$FS_CLI" -H 127.0.0.1 -P 8021 -p ClueCon -x "$1" -t 3000
}

cleanup() {
	if [[ -n "$FS_PID" ]] && kill -0 "$FS_PID" 2>/dev/null; then
		kill "$FS_PID" 2>/dev/null || true
		wait "$FS_PID" 2>/dev/null || true
	fi
	pkill -x sipp 2>/dev/null || true
	pkill -x tcpdump 2>/dev/null || true
	rm -f "$PCAP"
}
trap cleanup EXIT

make_pcap() {
	python3 - "$PCAP" <<'PY'
import struct, socket, sys
path = sys.argv[1]

def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF

pkts = []
seq = 0
ts = 0
ssrc = 0x11223344
for n in range(100):
    rtp = struct.pack("!BBHII", 0x80, 0, seq, ts, ssrc) + (b"\xff" * 160)
    seq = (seq + 1) & 0xFFFF
    ts += 160
    udp_len = 8 + len(rtp)
    udp = struct.pack("!HHHH", 40000, 40002, udp_len, 0) + rtp
    ip_len = 20 + len(udp)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, ip_len, n + 1, 0, 64, 17, 0,
                     socket.inet_aton("127.0.0.1"), socket.inet_aton("127.0.0.1"))
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    eth = b"\xff" * 6 + b"\x02\x00\x00\x00\x00\x01" + b"\x08\x00"
    frame = eth + ip + udp
    hdr = struct.pack("<IIII", n // 50, (n % 50) * 20000, len(frame), len(frame))
    pkts.append(hdr + frame)

with open(path, "wb") as fh:
    fh.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    fh.write(b"".join(pkts))
PY
}

prepare_conf() {
	rm -rf "$RUN/conf"
	mkdir -p "$RUN/conf"
	cp "$ROOT/conf-sipp/freeswitch.xml" "$RUN/conf/freeswitch.xml"
	python3 - "$RUN/conf/freeswitch.xml" <<'PY'
import sys
path = sys.argv[1]
text = open(path).read()
text = text.replace("$${local_ip_v4}", "127.0.0.1")
old = """      <modules>
        <load module="mod_console"/>
        <load module="mod_sofia"/>
        <load module="mod_loopback"/>
        <load module="mod_dptools"/>
        <load module="mod_dialplan_xml"/>
        <load module="mod_commands"/>
        <load module="mod_test"/> 
        <load module="mod_tone_stream"/>
        <load module="mod_voicemail"/>
        <load module="mod_sndfile"/>
        <load module="mod_say_en" />
      </modules>"""
new = """      <modules>
        <load module="mod_console"/>
        <load module="mod_sofia"/>
        <load module="mod_dptools"/>
        <load module="mod_dialplan_xml"/>
        <load module="mod_commands"/>
        <load module="mod_event_socket"/>
      </modules>"""
if old not in text:
    sys.exit("modules block not found in conf-sipp")
text = text.replace(old, new, 1)
needle = "    </configuration>\n\n<configuration name=\"voicemail.conf\""
insert = """    </configuration>

    <configuration name="event_socket.conf" description="Socket Client">
      <settings>
        <param name="nat-map" value="false"/>
        <param name="listen-ip" value="127.0.0.1"/>
        <param name="listen-port" value="8021"/>
        <param name="password" value="ClueCon"/>
      </settings>
    </configuration>

<configuration name="voicemail.conf\""""
if needle not in text:
    sys.exit("event_socket insertion point not found")
text = text.replace(needle, insert, 1)
open(path, "w").write(text)
PY
}

start_fs() {
	: >"$RUN/log/freeswitch.log"
	"$FS_BIN" -nf -nc -nonat -conf "$RUN/conf" -log "$RUN/log" -db "$RUN/db" -run "$RUN/run" \
		>"$RUN/log/console.log" 2>&1 &
	FS_PID=$!
	local i
	for i in $(seq 1 60); do
		if fscli "sofia status" 2>/dev/null | grep -q "external"; then
			fscli "sofia global siptrace on" >/dev/null || true
			fscli "fsctl loglevel debug" >/dev/null || true
			return 0
		fi
		if ! kill -0 "$FS_PID" 2>/dev/null; then
			echo "FreeSWITCH exited during startup" >&2
			tail -80 "$RUN/log/freeswitch.log" >&2 || true
			return 1
		fi
		sleep 0.5
	done
	echo "FreeSWITCH did not open the external profile" >&2
	tail -80 "$RUN/log/freeswitch.log" >&2 || true
	return 1
}

media_flow() {
	python3 - <<'PY'
import os, subprocess, sys
cli = os.environ["FS_CLI"]
def fs(*args):
    out = subprocess.check_output([cli, "-H", "127.0.0.1", "-P", "8021", "-p", "ClueCon", "-x", " ".join(args), "-t", "3000"], text=True, stderr=subprocess.DEVNULL)
    return out
text = fs("show", "channels")
rows = []
for line in text.splitlines():
    if line.startswith("uuid,") or not line.strip() or line[0].isdigit() and " total." in line:
        continue
    parts = line.split(",")
    if len(parts) < 2 or len(parts[0]) < 30:
        continue
    rows.append((parts[0], parts[1]))
inbound = [u for u, d in rows if d == "inbound"]
if not inbound:
    print("none")
    sys.exit(0)
print(fs("uuid_getvar", inbound[0], "audio_media_flow").strip())
PY
}

rtp_count() {
	local cap="$1"
	local port="$2"
	tcpdump -n -r "$cap" "udp dst port $port" 2>/dev/null | wc -l | tr -d ' '
}

uac_media_port() {
	local trace="$1"
	python3 - "$trace" <<'PY'
import re, sys
text = open(sys.argv[1], errors="replace").read()
m = re.search(r"INVITE sip:.*?m=audio (\d+) RTP/AVP", text, re.S)
print(m.group(1) if m else "")
PY
}

run_case() {
	local name="$1"
	local extension="$2"
	local expect="$3"
	local trace="$RUN/${name}.msg"
	local cap="$RUN/${name}.pcap"
	local uas_err="$RUN/${name}.uas.err"
	local uac_err="$RUN/${name}.uac.err"
	rm -f "$trace" "$cap" "$uas_err" "$uac_err"
	pkill -x sipp 2>/dev/null || true
	pkill -x tcpdump 2>/dev/null || true
	sleep 0.3

	tcpdump -i lo -n -w "$cap" udp >/dev/null 2>&1 &
	local tshark_pid=$!
	sleep 0.4

	sipp 127.0.0.1 -i 127.0.0.1 -sf "$ROOT/sipp-scenarios/uas_inactive_then_sendrecv.xml" \
		-p 5092 -mp 7000 -m 1 -nr -timeout 30s -recv_timeout 20000 \
		-trace_err -error_file "$uas_err" \
		>"$RUN/${name}.uas.log" 2>&1 &
	local uas_pid=$!
	sleep 0.5

	sipp 127.0.0.1:5080 -i 127.0.0.1 -sf "$ROOT/sipp-scenarios/uac_inactive_answer.xml" \
		-p 5064 -mp 6000 -m 1 -nr -s "$extension" \
		-timeout 30s -recv_timeout 25000 \
		-trace_msg -message_file "$trace" -trace_err -error_file "$uac_err" \
		>"$RUN/${name}.uac.log" 2>&1 &
	local uac_pid=$!

	local flow="none"
	local cur
	while kill -0 "$uac_pid" 2>/dev/null; do
		cur="$(FS_CLI="$FS_CLI" media_flow || true)"
		if [[ -n "$cur" && "$cur" != "none" && "$cur" != "_undef_" ]]; then
			flow="$cur"
		fi
		sleep 0.2
	done

	local uac_rc=0
	wait "$uac_pid" || uac_rc=$?
	wait "$uas_pid" || true
	sleep 0.3
	kill -INT "$tshark_pid" 2>/dev/null || true
	wait "$tshark_pid" 2>/dev/null || true

	local port
	port="$(uac_media_port "$trace")"
	local packets=0
	if [[ -n "$port" && -f "$cap" ]]; then
		packets="$(rtp_count "$cap" "$port")"
	fi

	local ok=0
	if [[ "$expect" == "drop" && "$packets" -le "$DROP_MAX" && "$flow" == "inactive" ]]; then
		ok=1
	fi
	if [[ "$expect" == "pass" && "$packets" -ge "$PASS_MIN" && "$flow" == "sendrecv" ]]; then
		ok=1
	fi

	echo "CASE $name extension=$extension flow=$flow rtp_to_caller=$packets port=${port:-unknown} sipp_rc=$uac_rc expect=$expect result=$([[ $ok -eq 1 ]] && echo PASS || echo FAIL)"
	if [[ $ok -ne 1 ]]; then
		echo "--- uac error ---" >&2
		cat "$uac_err" >&2 || true
		echo "--- uas error ---" >&2
		cat "$uas_err" >&2 || true
		echo "--- uac log ---" >&2
		tail -40 "$RUN/${name}.uac.log" >&2 || true
		echo "--- uas log ---" >&2
		tail -40 "$RUN/${name}.uas.log" >&2 || true
		echo "--- sip trace ---" >&2
		tail -80 "$trace" >&2 || true
		return 1
	fi
	return 0
}

command -v sipp >/dev/null
command -v tcpdump >/dev/null
command -v python3 >/dev/null
[[ -x "$FS_BIN" && -x "$FS_CLI" ]]

make_pcap
prepare_conf
start_fs

fail=0
run_case off inactive_answer drop || fail=1
fscli "fsctl rtp_ignore_inactive_answer enable" >/dev/null
run_case fsctl inactive_answer pass || fail=1
fscli "fsctl rtp_ignore_inactive_answer disable" >/dev/null
run_case channel_var inactive_answer_fix pass || fail=1

if [[ $fail -ne 0 ]]; then
	echo "Inactive-answer SIPp run failed. Logs: $RUN" >&2
	exit 1
fi
echo "Inactive-answer SIPp run passed."
exit 0
