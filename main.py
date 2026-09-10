from flask import Flask, request, render_template_string
import socket
import struct
import time
import os

app = Flask(__name__)

DEFAULT_TIMEOUT = 3.0

def read_cstring(data, offset):
    if offset >= len(data):
        return "", offset

    end = data.find(b"\x00", offset)

    if end == -1:
        return data[offset:].decode("utf-8", errors="replace"), len(data)

    return data[offset:end].decode("utf-8", errors="replace"), end + 1


def format_time(seconds):
    try:
        seconds = int(max(0, seconds))
    except:
        return "00:00:00"

    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    secs = seconds % 60

    return "{:02d}:{:02d}:{:02d}".format(hours, minutes, secs)


def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return ip


def drain_socket(sock):
    """Throw away any stale datagrams sitting in the receive buffer."""
    sock.setblocking(False)
    try:
        while True:
            sock.recvfrom(65535)
    except BlockingIOError:
        pass
    except OSError:
        pass
    finally:
        sock.setblocking(True)
        sock.settimeout(DEFAULT_TIMEOUT)


def receive_a2s_response(sock, first_data=None):
    """
    Reassemble GoldSrc/Source split UDP responses.

    GoldSrc uses:
        FF FF FF FE
        4-byte request id
        1-byte split info
        payload

    For GoldSrc, ValvePython/steam decodes the split byte as:
        packet_index = (byte & 0xF0) >> 4
        packet_count = byte & 0x0F
    """
    if first_data is None:
        first_data, addr = sock.recvfrom(65535)

    if len(first_data) < 4:
        return first_data

    if first_data[:4] != b"\xfe\xff\xff\xff":
        return first_data

    packets = {}
    data = first_data

    # Read the first packet and determine the GoldSrc split format.
    while True:
        if len(data) < 9:
            raise ValueError("Invalid split packet: shorter than 9 bytes")

        split_byte = data[8]

        # GoldSrc split format:
        #   high nibble = packet number
        #   low nibble  = total packet count
        #
        packet_number = (split_byte & 0xF0) >> 4
        total_packets = split_byte & 0x0F

        # Some old implementations can expose a zero/invalid total.
        # In that case this cannot be safely reassembled.
        if total_packets <= 0:
            raise ValueError(
                "Invalid GoldSrc split count: {}".format(total_packets)
            )

        packets[packet_number] = data[9:]

        if len(packets) >= total_packets:
            break

        data, addr = sock.recvfrom(65535)

    # Reassemble in packet-index order.
    combined = b""
    for i in range(total_packets):
        if i not in packets:
            raise ValueError("Missing split packet {}".format(i))
        combined += packets[i]

    return combined


def parse_info(data):

    if len(data) < 6:
        raise ValueError(
            "A2S_INFO response is too short"
        )

    if data[:4] != b"\xff\xff\xff\xff":
        raise ValueError(
            "Invalid A2S_INFO header"
        )

    response_type = data[4]

    # ========================================================
    # MODERN A2S_INFO
    # ========================================================

    if response_type == 0x49:

        offset = 5

        protocol = data[offset]
        offset += 1

        name, offset = read_cstring(
            data, offset
        )

        map_name, offset = read_cstring(
            data, offset
        )

        folder, offset = read_cstring(
            data, offset
        )

        game, offset = read_cstring(
            data, offset
        )

        if offset + 2 > len(data):
            raise ValueError(
                "Incomplete A2S_INFO response"
            )

        app_id = struct.unpack_from(
            "<H", data, offset
        )[0]

        offset += 2

        if offset + 5 > len(data):
            raise ValueError(
                "Incomplete player information"
            )

        players = data[offset]
        max_players = data[offset + 1]
        bots = data[offset + 2]

        server_type = chr(
            data[offset + 3]
        )

        environment = chr(
            data[offset + 4]
        )

        offset += 5

        visibility = 0

        if offset < len(data):
            visibility = data[offset]
            offset += 1

        vac = 0

        if offset < len(data):
            vac = data[offset]
            offset += 1

        result = {
            "response_type": "0x49",
            "protocol": protocol,
            "name": name,
            "map": map_name,
            "folder": folder,
            "game": game,
            "app_id": app_id,

            "players": players,
            "max_players": max_players,
            "bots": bots,

            "server_type": server_type,
            "environment": environment,

            "password": bool(visibility),
            "vac": bool(vac)
        }

        # ----------------------------------------------------
        # EDF
        # ----------------------------------------------------

        if offset < len(data):

            edf = data[offset]
            offset += 1

            result["edf"] = "0x{:02X}".format(edf)

            # Port
            if edf & 0x80:

                if offset + 2 <= len(data):

                    result["port"] = struct.unpack_from(
                        "<H",
                        data,
                        offset
                    )[0]

                    offset += 2

            # SteamID
            if edf & 0x10:

                if offset + 8 <= len(data):

                    result["steam_id"] = struct.unpack_from(
                        "<Q",
                        data,
                        offset
                    )[0]

                    offset += 8

            # SourceTV
            if edf & 0x40:

                if offset + 2 <= len(data):

                    tv_port = struct.unpack_from(
                        "<H",
                        data,
                        offset
                    )[0]

                    offset += 2

                    tv_name, offset = read_cstring(
                        data,
                        offset
                    )

                    result["tv_port"] = tv_port
                    result["tv_name"] = tv_name

            # Keywords
            if edf & 0x20:

                keywords, offset = read_cstring(
                    data,
                    offset
                )

                result["keywords"] = keywords

            # Game ID
            if edf & 0x01:

                if offset + 8 <= len(data):

                    result["game_id"] = struct.unpack_from(
                        "<Q",
                        data,
                        offset
                    )[0]

                    offset += 8

        return result

    # ========================================================
    # LEGACY GOLDSRC A2M_INFO
    # RESPONSE = 0x6D
    # ========================================================

    elif response_type == 0x6D:

        offset = 5

        address, offset = read_cstring(
            data,
            offset
        )

        name, offset = read_cstring(
            data,
            offset
        )

        map_name, offset = read_cstring(
            data,
            offset
        )

        folder, offset = read_cstring(
            data,
            offset
        )

        game, offset = read_cstring(
            data,
            offset
        )

        result = {
            "response_type": "0x6D",

            "protocol": None,

            "name": name,
            "map": map_name,
            "folder": folder,
            "game": game,

            "address": address,

            "players": None,
            "max_players": None,
            "bots": None,

            "server_type": None,
            "environment": None,

            "password": False,
            "vac": False,

            "mod": False
        }

        # ----------------------------------------------------
        # LEGACY GOLDSRC FIELDS
        #
        # players
        # max players
        # protocol
        # server type
        # OS
        # password
        # mod
        #
        # Example:
        #
        # 07 0c 2f 64 6c 00 00
        #
        # 07 = 7 players
        # 0c = 12 max players
        # 2f = protocol 47
        # 64 = dedicated
        # 6c = Linux
        # 00 = no password
        # 00 = not a mod
        # ----------------------------------------------------

        if offset + 7 <= len(data):

            result["players"] = data[offset]
            offset += 1

            result["max_players"] = data[offset]
            offset += 1

            result["protocol"] = data[offset]
            offset += 1

            result["server_type"] = chr(
                data[offset]
            )

            offset += 1

            result["environment"] = chr(
                data[offset]
            )

            offset += 1

            result["password"] = bool(
                data[offset]
            )

            offset += 1

            result["mod"] = bool(
                data[offset]
            )

            offset += 1

        # ----------------------------------------------------
        # MOD INFORMATION
        # ----------------------------------------------------

        if result["mod"]:

            if offset < len(data):

                result["mod_website"], offset = read_cstring(
                    data,
                    offset
                )

            if offset < len(data):

                result["mod_download"], offset = read_cstring(
                    data,
                    offset
                )

            # Null byte
            if offset < len(data):
                offset += 1

            if offset + 4 <= len(data):

                result["mod_version"] = struct.unpack_from(
                    "<I",
                    data,
                    offset
                )[0]

                offset += 4

            if offset + 4 <= len(data):

                result["mod_size"] = struct.unpack_from(
                    "<I",
                    data,
                    offset
                )[0]

                offset += 4

            if offset < len(data):

                result["mod_type"] = data[offset]
                offset += 1

            if offset < len(data):

                result["mod_dll"] = data[offset]
                offset += 1

        # ----------------------------------------------------
        # VAC / SECURE
        # ----------------------------------------------------

        if offset < len(data):

            result["vac"] = bool(
                data[offset]
            )

            offset += 1

        # ----------------------------------------------------
        # BOTS
        # ----------------------------------------------------

        if offset < len(data):

            result["bots"] = data[offset]
            offset += 1

        return result

    else:

        raise ValueError(
            "Unknown A2S_INFO response type: 0x{:02X}".format(
                response_type
            )
        )


def parse_players(data):

    if len(data) < 6:
        raise ValueError(
            "A2S_PLAYER response too short"
        )

    if data[:4] != b"\xff\xff\xff\xff":
        raise ValueError(
            "Invalid A2S_PLAYER header"
        )

    if data[4] != 0x44:

        raise ValueError(
            "Unexpected A2S_PLAYER response: 0x{:02X}".format(
                data[4]
            )
        )

    offset = 5

    player_count = data[offset]
    offset += 1

    players = []

    for _ in range(player_count):

        if offset >= len(data):
            break

        index = data[offset]
        offset += 1

        name, offset = read_cstring(
            data,
            offset
        )

        if offset + 8 > len(data):
            break

        score = struct.unpack_from(
            "<i",
            data,
            offset
        )[0]

        offset += 4

        duration = struct.unpack_from(
            "<f",
            data,
            offset
        )[0]

        offset += 4

        players.append({
            "index": index,
            "name": name,
            "score": score,
            "duration": duration,
            "duration_text": format_time(duration)
        })

    return players


def query_info_legacy(sock, target):
    """Send the classic 'details' request. Returns (info_dict, raw_bytes)."""
    sock.sendto(b"\xff\xff\xff\xff" + b"details\x00", target)
    data, _ = sock.recvfrom(65535)
    if data[:4] == b"\xfe\xff\xff\xff":
        data = receive_a2s_response(sock, data)
    return parse_info(data), data


def query_players_legacy(sock, target):
    """WON2 player list. Returns (players, error, challenge=None)."""
    sock.sendto(b"\xff\xff\xff\xff" + b"players\x00", target)
    try:
        data, _ = sock.recvfrom(65535)
    except socket.timeout:
        return [], "Legacy player query timed out", None
    except Exception as e:
        return [], "Legacy player error: {}".format(e), None
    if data[:4] == b"\xfe\xff\xff\xff":
        try:
            data = receive_a2s_response(sock, data)
        except Exception as e:
            return [], "Legacy player split error: {}".format(e), None
    if len(data) < 5 or data[:4] != b"\xff\xff\xff\xff" or data[4] != 0x44:
        rtype = data[4] if len(data) > 4 else 0
        return [], "Unexpected legacy player response (0x{:02X})".format(rtype), None
    try:
        return parse_players(data), None, None
    except Exception as e:
        return [], "Legacy player parse error: {}".format(e), None


def parse_rules_legacy(data):
    """Parse a WON rules payload in modern-shaped or bare-pair form."""
    if len(data) < 4 or data[:4] != b"\xff\xff\xff\xff":
        raise ValueError("Invalid legacy rules header")
    offset = 4
    rules = []
    if offset < len(data) and data[offset] == 0x45:
        offset += 1
        if offset + 2 > len(data):
            raise ValueError("Incomplete legacy rules count")
        count = struct.unpack_from("<H", data, offset)[0]
        offset += 2
        for _ in range(count):
            if offset >= len(data):
                break
            key, offset = read_cstring(data, offset)
            value, offset = read_cstring(data, offset)
            rules.append({"key": key, "value": value})
        return rules
    while offset < len(data):
        key, offset = read_cstring(data, offset)
        if not key:
            break
        if offset >= len(data):
            rules.append({"key": key, "value": ""})
            break
        value, offset = read_cstring(data, offset)
        rules.append({"key": key, "value": value})
    return rules


def query_rules_legacy(sock, target):
    """WON2 rules. No challenge mechanism in the legacy protocol."""
    sock.sendto(b"\xff\xff\xff\xff" + b"rules\x00", target)
    try:
        data, _ = sock.recvfrom(65535)
    except socket.timeout:
        return [], "Legacy rules query timed out"
    except Exception as e:
        return [], "Legacy rules error: {}".format(e)
    if data[:4] == b"\xfe\xff\xff\xff":
        try:
            data = receive_a2s_response(sock, data)
        except Exception as e:
            return [], "Legacy rules split error: {}".format(e)
    print("[WON2 RULES] {}B: {}".format(len(data), data.hex(" ")))
    try:
        return parse_rules_legacy(data), None
    except Exception as e:
        return [], "Legacy rules parse error: {}".format(e)


def query_server(host, port):
    """Query a Half-Life WON/WON2 game server using the classic UDP protocol."""
    start_time = time.time()

    try:
        port = int(port)
    except (TypeError, ValueError):
        return {"error": "Invalid port."}

    if not (1 <= port <= 65535):
        return {"error": "Invalid port."}

    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        return {"error": "Could not resolve hostname: {}".format(host)}

    target = (ip, port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(DEFAULT_TIMEOUT)

    try:
        # --------------------------------------------------------
        # WON / WON2 DETAILS
        # FF FF FF FF "details" 00
        # --------------------------------------------------------
        info_start = time.time()
        info, info_data = query_info_legacy(sock, target)
        info_ping = (time.time() - info_start) * 1000.0

        # --------------------------------------------------------
        # WON / WON2 PLAYERS
        # FF FF FF FF "players" 00
        # --------------------------------------------------------
        drain_socket(sock)
        players, player_error, _ = query_players_legacy(sock, target)

        # --------------------------------------------------------
        # WON / WON2 RULES
        # FF FF FF FF "rules" 00
        # --------------------------------------------------------
        drain_socket(sock)
        rules, rules_error = query_rules_legacy(sock, target)

        total_time = (time.time() - start_time) * 1000.0

        # WON2 details is the authoritative server-info response.
        # Player/rule queries are separate legacy requests.
        info["protocol_family"] = "WON2"

        return {
            "target": "{}:{}".format(host, port),
            "ip": ip,
            "hostname": reverse_dns(ip),
            "ping": info_ping,
            "total_time": total_time,
            "bytes": len(info_data),
            "raw": info_data.hex(" "),
            "info": info,
            "players_list": players,
            "player_error": player_error,
            "rules": rules,
            "rules_error": rules_error,
            "is_legacy": True,
            "queried_at": time.strftime("%Y-%m-%d %H:%M:%S")
        }

    except socket.timeout:
        return {
            "error": "Connection timed out. Server did not answer the WON2 details query.",
            "target": "{}:{}".format(host, port),
            "ip": ip
        }
    except Exception as e:
        return {
            "error": str(e),
            "target": "{}:{}".format(host, port),
            "ip": ip
        }
    finally:
        sock.close()



HTML = r"""
<!DOCTYPE html>

<html>

<head>

<meta charset="UTF-8">

<meta name="viewport"
      content="width=device-width, initial-scale=1.0">

<title>WON2 Server Query</title>

<style>

body {
    font-family: Arial, sans-serif;
    background: #111;
    color: #eee;
    margin: 0;
    padding: 20px;
}

.container {
    max-width: 1100px;
    margin: auto;
}

h1 {
    margin-bottom: 20px;
}

h2 {
    margin-top: 10px;
}

form {
    background: #1c1c1c;
    padding: 18px;
    border-radius: 8px;
    margin-bottom: 20px;
}

input {
    background: #111;
    color: white;
    border: 1px solid #555;
    padding: 10px;
    border-radius: 5px;
    margin-right: 8px;
}

button {
    padding: 10px 18px;
    border: 0;
    border-radius: 5px;
    cursor: pointer;
}

.card {
    background: #1c1c1c;
    padding: 18px;
    border-radius: 8px;
    margin-bottom: 18px;
    overflow-x: auto;
}

table {
    width: 100%;
    border-collapse: collapse;
    margin-top: 10px;
}

th,
td {
    border-bottom: 1px solid #444;
    padding: 9px;
    text-align: left;
}

th {
    background: #252525;
}

tr:hover {
    background: #222;
}

.label {
    font-weight: bold;
    width: 200px;
}

.good {
    color: #6cff6c;
}

.bad {
    color: #ff6868;
}

.warning {
    color: #ffd866;
}

pre {
    background: #080808;
    padding: 12px;
    border-radius: 5px;
    overflow-x: auto;
    white-space: pre-wrap;
    word-break: break-all;
}

.small {
    color: #aaa;
    font-size: 13px;
}

.player-name {
    font-weight: bold;
}

</style>

</head>

<body>

<div class="container">

<h1>WON2 Server Query</h1>


<form method="POST">

<input
    type="text"
    name="host"
    placeholder="IP or hostname"
    value="{{ host }}"
    required
>

<input
    type="number"
    name="port"
    placeholder="Port"
    value="{{ port }}"
    min="1"
    max="65535"
    required
>

<button type="submit">
    Query Server
</button>

</form>


{% if result %}


{% if result.error %}


<div class="card">

<h2 class="bad">
Server Offline / Query Failed
</h2>

<p>
{{ result.error }}
</p>

{% if result.target %}

<p>
<b>Target:</b>
{{ result.target }}
</p>

{% endif %}

</div>


{% else %}


<!-- =======================================================
     SERVER STATUS
======================================================== -->

<div class="card">

<h2>
{{ result.info.name }}
</h2>

<p class="good">
● Server responded
</p>

<table>

<tr>
<td class="label">
Target
</td>

<td>
{{ result.target }}
</td>
</tr>


<tr>
<td class="label">
IP Address
</td>

<td>
{{ result.ip }}
</td>
</tr>


<tr>
<td class="label">
Hostname
</td>

<td>
{{ result.hostname }}
</td>
</tr>


<tr>
<td class="label">
Ping
</td>

<td>
{{ "%.2f"|format(result.ping) }} ms
</td>
</tr>


<tr>
<td class="label">
Bytes Received
</td>

<td>
{{ result.bytes }}
</td>
</tr>


<tr>
<td class="label">
Total Query Time
</td>

<td>
{{ "%.2f"|format(result.total_time) }} ms
</td>
</tr>


<tr>
<td class="label">
Response Type
</td>

<td>
{{ result.info.response_type }}
</td>
</tr>


<tr>
<td class="label">
Protocol Family
</td>

<td>
WON2 / Legacy GoldSrc
</td>
</tr>


<tr>
<td class="label">
Protocol
</td>

<td>

{% if result.info.protocol is not none %}

{{ result.info.protocol }}

{% else %}

N/A

{% endif %}

</td>
</tr>

</table>

</div>


<!-- =======================================================
     SERVER INFO
======================================================== -->

<div class="card">

<h2>
Server Info
</h2>

<table>


<tr>
<td class="label">
Server Name
</td>

<td>
{{ result.info.name }}
</td>
</tr>


<tr>
<td class="label">
Map
</td>

<td>
{{ result.info.map }}
</td>
</tr>


<tr>
<td class="label">
Game / Mod
</td>

<td>
{{ result.info.game }}
</td>
</tr>


<tr>
<td class="label">
Game Folder
</td>

<td>
{{ result.info.folder }}
</td>
</tr>


<tr>
<td class="label">
Players
</td>

<td>

{% if result.info.players is not none %}

{{ result.info.players }}
/
{{ result.info.max_players }}

{% else %}

None

{% endif %}

</td>
</tr>


<tr>
<td class="label">
Bots
</td>

<td>

{% if result.info.bots is not none %}

{{ result.info.bots }}

{% else %}

None

{% endif %}

</td>
</tr>


<tr>
<td class="label">
Protocol
</td>

<td>

{% if result.info.protocol is not none %}

{{ result.info.protocol }}

{% else %}

N/A

{% endif %}

</td>
</tr>


<tr>
<td class="label">
Server Type
</td>

<td>

{% if result.info.server_type %}

{{ result.info.server_type }}

{% else %}

N/A

{% endif %}

</td>
</tr>


<tr>
<td class="label">
Operating System
</td>

<td>

{% if result.info.environment == "l" %}

Linux

{% elif result.info.environment == "w" %}

Windows

{% elif result.info.environment == "m" %}

Mac

{% elif result.info.environment %}

{{ result.info.environment }}

{% else %}

N/A

{% endif %}

</td>
</tr>


<tr>
<td class="label">
Password Protected
</td>

<td>

{% if result.info.password %}

Yes

{% else %}

No

{% endif %}

</td>
</tr>


<tr>
<td class="label">
VAC
</td>

<td>

{% if result.info.vac %}

Enabled

{% else %}

Disabled

{% endif %}

</td>
</tr>


{% if result.info.app_id %}

<tr>

<td class="label">
App ID
</td>

<td>
{{ result.info.app_id }}
</td>

</tr>

{% endif %}


{% if result.info.keywords %}

<tr>

<td class="label">
Keywords
</td>

<td>
{{ result.info.keywords }}
</td>

</tr>

{% endif %}


{% if result.info.tv_port %}

<tr>

<td class="label">
SourceTV Port
</td>

<td>
{{ result.info.tv_port }}
</td>

</tr>

{% endif %}


{% if result.info.tv_name %}

<tr>

<td class="label">
SourceTV Name
</td>

<td>
{{ result.info.tv_name }}
</td>

</tr>

{% endif %}


</table>

</div>


<!-- =======================================================
     PLAYERS
======================================================== -->

<div class="card">

<h2>
Players ({{ result.players_list|length }})
</h2>


{% if result.players_list %}


<table>

<tr>

<th>
#
</th>

<th>
Player Name
</th>

<th>
Score
</th>

<th>
Connected Time
</th>

</tr>


{% for player in result.players_list %}


<tr>

<td>
{{ player.index }}
</td>

<td class="player-name">
{{ player.name }}
</td>

<td>
{{ player.score }}
</td>

<td>
{{ player.duration_text }}
</td>

</tr>


{% endfor %}

</table>


{% else %}


{% if result.player_error %}

<p class="warning">
{{ result.player_error }}
</p>

{% else %}

<p>
No players connected.
</p>

{% endif %}


{% endif %}

</div>


<!-- =======================================================
     RULES
======================================================== -->

<div class="card">

<h2>
Server Rules ({{ result.rules|length }})
</h2>


{% if result.rules %}


<table>

<tr>

<th>
Rule
</th>

<th>
Value
</th>

</tr>


{% for rule in result.rules %}


<tr>

<td>
{{ rule.key }}
</td>

<td>
{{ rule.value }}
</td>

</tr>


{% endfor %}

</table>


{% else %}


{% if result.rules_error %}

<p class="warning">
{{ result.rules_error }}
</p>

{% else %}

<p>
No rules returned.
</p>

{% endif %}


{% endif %}

</div>


<!-- =======================================================
     RAW PACKET
======================================================== -->

<div class="card">

<h2>
Raw A2S_INFO Packet
</h2>

<pre>{{ result.raw }}</pre>

</div>


<div class="card">

<p class="small">
Queried at: {{ result.queried_at }}
</p>

</div>


{% endif %}


{% endif %}

</div>

</body>

</html>
"""




@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    host = ""
    port = "27015"

    if request.method == "POST":
        host = request.form.get("host", "").strip()
        port = request.form.get("port", "27015").strip()
        if host:
            result = query_server(host, port)

    return render_template_string(HTML, result=result, host=host, port=port)


@app.route("/health")
def health():
    return "OK"


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
