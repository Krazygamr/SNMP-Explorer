import os, shlex
import paramiko

def ssh_connect(cfg, timeout=15):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    if cfg.key_path and os.path.exists(cfg.key_path):
        pkey = paramiko.RSAKey.from_private_key_file(cfg.key_path)
        client.connect(cfg.host, port=cfg.port, username=cfg.username, pkey=pkey, timeout=timeout)
    else:
        client.connect(cfg.host, port=cfg.port, username=cfg.username, password=cfg.password, timeout=timeout)
    return client

def ssh_exec(cfg, command: str, timeout=20):
    c = ssh_connect(cfg, timeout=timeout)
    try:
        stdin, stdout, stderr = c.exec_command(command, timeout=timeout)
        out = stdout.read().decode('utf-8', 'ignore')
        err = stderr.read().decode('utf-8', 'ignore')
        code = stdout.channel.recv_exit_status()
        return code, out, err
    finally:
        c.close()

def sftp_read(cfg, remote_path: str) -> str:
    transport = paramiko.Transport((cfg.host, cfg.port))
    try:
        if cfg.key_path and os.path.exists(cfg.key_path):
            pkey = paramiko.RSAKey.from_private_key_file(cfg.key_path)
            transport.connect(username=cfg.username, pkey=pkey)
        else:
            transport.connect(username=cfg.username, password=cfg.password)
        sftp = paramiko.SFTPClient.from_transport(transport)
        with sftp.open(remote_path, 'r') as f:
            return f.read().decode('utf-8', 'ignore')
    finally:
        transport.close()

def sftp_write(cfg, remote_path: str, content: str):
    transport = paramiko.Transport((cfg.host, cfg.port))
    try:
        if cfg.key_path and os.path.exists(cfg.key_path):
            pkey = paramiko.RSAKey.from_private_key_file(cfg.key_path)
            transport.connect(username=cfg.username, pkey=pkey)
        else:
            transport.connect(username=cfg.username, password=cfg.password)
        sftp = paramiko.SFTPClient.from_transport(transport)
        try:
            sftp.rename(remote_path, remote_path + ".bak")
        except Exception:
            pass
        with sftp.open(remote_path, 'w') as f:
            f.write(content)
    finally:
        transport.close()
def _sudo_wrap(cfg, inner_cmd: str) -> str:
    """
    Build a command that runs `inner_cmd` with sudo. If cfg.password is set,
    we feed it via stdin (-S) so no TTY is needed.
    """
    quoted = shlex.quote(inner_cmd)
    if cfg.password:
        pw = shlex.quote(cfg.password)
        return f"bash -lc \"echo {pw} | sudo -S -p '' bash -lc {quoted}\""
    else:
        return f"sudo bash -lc {quoted}"

def push_file_with_sudo(cfg, content: str, dest_path: str, mode: str = "0644", owner: str = "root", group: str = "root"):
    """
    Uploads to /tmp, then sudo-installs into place with a timestamped backup.
    """
    tmp_name = f"/tmp/.snmp_prom_editor_{os.path.basename(dest_path)}"
    # 1) upload to /tmp (unprivileged write)
    transport = paramiko.Transport((cfg.host, cfg.port))
    try:
        if cfg.key_path and os.path.exists(cfg.key_path):
            pkey = paramiko.RSAKey.from_private_key_file(cfg.key_path)
            transport.connect(username=cfg.username, pkey=pkey)
        else:
            transport.connect(username=cfg.username, password=cfg.password)
        sftp = paramiko.SFTPClient.from_transport(transport)
        with sftp.open(tmp_name, 'w') as f:
            f.write(content)
    finally:
        transport.close()

    # 2) sudo: backup + install + cleanup
    inner = (
        f"dest={shlex.quote(dest_path)}; tmp={shlex.quote(tmp_name)}; "
        f"ts=$(date +%s); "
        f"[ -f \"$dest\" ] && cp -a \"$dest\" \"$dest.bak.$ts\" || true; "
        f"install -o {owner} -g {group} -m {mode} \"$tmp\" \"$dest\"; "
        f"rm -f \"$tmp\""
    )
    code, out, err = ssh_exec(cfg, _sudo_wrap(cfg, inner))
    if code != 0:
        raise RuntimeError((out or err or "sudo install failed").strip())
    

    # at bottom of common/sshio.py
def probe_snmp_metrics(cfg):
    cmd = (
        "(command -v curl >/dev/null 2>&1 && curl -s http://127.0.0.1:9116/metrics) "
        "|| (command -v wget >/dev/null 2>&1 && wget -qO- http://127.0.0.1:9116/metrics) "
        "|| echo __ERR_NO_HTTP_CLIENT__"
    )
    code, out, err = ssh_exec(cfg, cmd, timeout=25)
    if "__ERR_NO_HTTP_CLIENT__" in out:
        return False, 0, "no curl/wget on Pi"
    if code != 0 and not out:
        return False, 0, (err or "unknown error")
    lines = [ln for ln in out.splitlines() if ln and not ln.lstrip().startswith("#")]
    return True, len(lines), ""
