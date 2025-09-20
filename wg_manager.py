# wg_manager.py
import os
import subprocess
import ipaddress
import json
import stat

class WGManagerError(Exception):
    pass

class WGManager:
    def __init__(self, wg_iface, client_dir, wg_subnet, server_public_key=None, uid=0):
        self.wg_iface = wg_iface
        self.client_dir = client_dir
        self.wg_subnet = ipaddress.ip_network(wg_subnet)
        self.server_public_key = server_public_key
        os.makedirs(self.client_dir, exist_ok=True)
        st = os.stat(self.client_dir)
        if st.st_uid != uid:  # или ожидаемый uid
            raise WGManagerError("CLIENT_DIR must be owned by root")
        if (st.st_mode & 0o077) != uid:
            raise WGManagerError("CLIENT_DIR must not be group/other writable")


    # --- helper subprocess wrapper (avoid logging secrets) ---
    def _run(self, cmd, input_data=None, check=True):
        """Run subprocess and return stdout (text). Raises WGManagerError on failure."""
        try:
            proc = subprocess.run(
                cmd,
                input=input_data,
                capture_output=True,
                check=check,
                text=True,
                env=os.environ
            )
            return proc.stdout.strip()
        except subprocess.CalledProcessError as e:
            # redact stderr before storing into the exception message
            safe_err = "Что-то пошло не так. Напиши админу" if e.stderr else "Упс. Не понял что произошло - напиши админу."
            # store stderr in debug-only attribute, not in the message
            ex = WGManagerError(f"Command failed: {' '.join(cmd)}; exit={e.returncode}; stderr={safe_err}")
            # attach full stderr for admin logs only
            ex._full_stderr = e.stderr
            raise ex

    # --- status ---
    def status(self):
        # Return sanitized wg show output
        out = self._run(["wg", "show", self.wg_iface, "dump"])
        # The dump contains keys and such — sanitize private-like fields:
        # wg dump columns: interface, private key, public key, listen port, fwmark, peer public key, preshared key, endpoint, allowed ips, latest handshake, rx_bytes, tx_bytes
        # We will hide columns that look like keys by replacing long base64-like strings with "<REDACTED>"
        sanitized_lines = []
        for line in out.splitlines():
            cols = line.split("\t")
            safe_cols = []
            for c in cols:
                if len(c) > 40 and all(ch.isalnum() or ch in "+/=" for ch in c[:20]):
                    safe_cols.append("<REDACTED>")
                else:
                    safe_cols.append(c)
            sanitized_lines.append("\t".join(safe_cols))
        return "\n".join(sanitized_lines) if sanitized_lines else "(no output)"

    # --- key generation ---
    def _gen_keypair(self):
        priv = self._run(["wg", "genkey"])
        # use subprocess.run without shell
        proc = subprocess.run(["wg", "pubkey"], input=priv + "\n", capture_output=True, text=True, check=True)
        pub = proc.stdout.strip()
        return priv.strip(), pub.strip()


    # --- find next free IP ---
    def _list_used_ips(self):
        used = set()
        # scan client metadata files
        for fn in os.listdir(self.client_dir):
            if fn.endswith(".json"):
                try:
                    with open(os.path.join(self.client_dir, fn), "r") as f:
                        j = json.load(f)
                    ip = j.get("client_ip")
                    if ip:
                        used.add(ip.split("/")[0])
                except Exception:
                    continue
        # also parse 'wg show' for allowed-ips
        try:
            dump = self._run(["wg", "show", self.wg_iface, "dump"])
            for line in dump.splitlines():
                cols = line.split("\t")
                if len(cols) >= 9:
                    allowed = cols[8]
                    for a in allowed.split(","):
                        a = a.strip()
                        if a:
                            used.add(a.split("/")[0])
        except WGManagerError:
            pass
        return used

    def _next_free_ip(self):
        used = self._list_used_ips()
        # skip network address and server address; start from .2
        # iterate hosts in wg_subnet (exclude network and broadcast)
        for ip in self.wg_subnet.hosts():
            s = str(ip)
            if s not in used:
                return s + '/' + str(self.wg_subnet.prefixlen)
        raise WGManagerError("No free IPs available in subnet")

    # --- add client ---
    def add_client(self, name, allowed_ips=None):
        # name: simple filename-safe string
        if not name or any(ch in name for ch in r"\/:*?\"<>| "):
            raise WGManagerError("Invalid client name")
        meta_path = os.path.join(self.client_dir, f"{name}.json")
        conf_path = os.path.join(self.client_dir, f"{name}.conf")
        if os.path.exists(meta_path) or os.path.exists(conf_path):
            raise WGManagerError("Client with that name already exists")

        priv, pub = self._gen_keypair()
        client_ip = self._next_free_ip()
        if not allowed_ips:
            allowed_ips = "0.0.0.0/0"

        # add peer to live interface (requires root)
        try:
            self._run(["wg", "set", self.wg_iface, "peer", pub, "allowed-ips", client_ip.split("/")[0] + "/32"])
        except WGManagerError as e:
            # try to not leave private data lingering
            raise WGManagerError(f"Failed to add peer to interface: {e}")

        # build client config (do not log priv)
        server_pub = self.server_public_key or "<SERVER_PUBLIC_KEY>"
        server_ip = ""  # user can put actual endpoint later
        client_conf = [
            "[Interface]",
            f"PrivateKey = {priv}",
            f"Address = {client_ip}",
            "DNS = 1.1.1.1",
            "",
            "[Peer]",
            f"PublicKey = {server_pub}",
            "AllowedIPs = 0.0.0.0/0",
        ]
        client_conf_text = "\n".join(client_conf)

        # write files with restricted permissions
        with open(conf_path, "w", encoding="utf-8") as f:
            f.write(client_conf_text)
        os.chmod(conf_path, stat.S_IRUSR | stat.S_IWUSR)  # 600

        meta = {
            "name": name,
            "client_ip": client_ip,
            "pubkey": pub,
            "conf_path": conf_path,
        }
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)
        os.chmod(meta_path, stat.S_IRUSR | stat.S_IWUSR)

        # Return non-sensitive info and full client config for delivery to user
        return {
            "name": name,
            "client_ip": client_ip,
            "pubkey": pub,
            "conf_path": conf_path,
            "client_conf": client_conf_text
        }

    # --- remove client ---
    def remove_client(self, name):
        meta_path = os.path.join(self.client_dir, f"{name}.json")
        if not os.path.exists(meta_path):
            raise WGManagerError("Client not found")
        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)
        pub = meta.get("pubkey")
        conf_path = meta.get("conf_path")
        # remove peer from live interface
        try:
            self._run(["wg", "set", self.wg_iface, "peer", pub, "remove"])
        except WGManagerError as e:
            # still proceed to cleanup files (logically)
            raise WGManagerError(f"Failed to remove peer from interface: {e}")
        # remove files
        try:
            if conf_path and os.path.exists(conf_path):
                os.remove(conf_path)
            os.remove(meta_path)
        except Exception as e:
            # non-fatal cleanup error
            raise WGManagerError(f"Failed to remove client files: {e}")
        return True
