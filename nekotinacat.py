#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════╗
║   NekotinaCat_Framework v1.0.0 — CRIMSON SENTINEL               ║
║   Defensive Security Monitor · Vulnerability & Malware Analyzer  ║
║   Sistema: Linux/Unix/macOS                                      ║
╚══════════════════════════════════════════════════════════════════╝
"""

import os, sys, subprocess, threading, time, json, re, math, hashlib
import platform, socket, struct, ctypes
from pathlib import Path
from datetime import datetime

try:
    import tkinter as tk
    from tkinter import font as tkfont, scrolledtext, messagebox
except ImportError:
    print("[!] tkinter não encontrado. Instale: sudo apt install python3-tk")
    sys.exit(1)

try:
    import psutil
    PSUTIL_OK = True
except ImportError:
    PSUTIL_OK = False

# ═══════════════════════════════════════════════════════
#  PALETA CRIMSON SENTINEL
# ═══════════════════════════════════════════════════════
BG       = "#060404"
BG2      = "#0a0606"
BG3      = "#110808"
PANEL    = "#0d0505"
BORDER   = "#8b0000"
GLOW1    = "#cc1a1a"
GLOW2    = "#ff3333"
GLOW3    = "#ff6666"
TEXT     = "#f0dede"
MUTED    = "#7a5a5a"
SUCCESS  = "#22c55e"
WARNING  = "#f59e0b"
DANGER   = "#ef4444"
CYAN     = "#22d3ee"
MONO     = "#ff8888"
MONO2    = "#ffaaaa"
GOLD     = "#fbbf24"

VERSION  = "1.0.0"
NAME     = "NekotinaCat_Framework"
CODENAME = "CRIMSON SENTINEL"

# ═══════════════════════════════════════════════════════
#  MÓDULOS DE ANÁLISE
# ═══════════════════════════════════════════════════════

def run(cmd, timeout=30):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return "", "TIMEOUT", -1
    except Exception as e:
        return "", str(e), -1


class SystemAnalyzer:
    """Análise de sistema, distro, kernel e BIOS."""

    @staticmethod
    def full_report():
        results = {}

        # OS / Distro
        results['os'] = platform.system()
        results['kernel'] = platform.release()
        results['arch']   = platform.machine()
        results['node']   = platform.node()

        # Distro Linux
        if os.path.exists("/etc/os-release"):
            with open("/etc/os-release") as f:
                for line in f:
                    if "=" in line:
                        k, v = line.strip().split("=", 1)
                        results[k.lower()] = v.strip('"')

        # BIOS / DMI
        dmi_fields = {
            'bios_vendor':   '/sys/class/dmi/id/bios_vendor',
            'bios_version':  '/sys/class/dmi/id/bios_version',
            'bios_date':     '/sys/class/dmi/id/bios_date',
            'board_name':    '/sys/class/dmi/id/board_name',
            'board_vendor':  '/sys/class/dmi/id/board_vendor',
            'sys_vendor':    '/sys/class/dmi/id/sys_vendor',
            'product_name':  '/sys/class/dmi/id/product_name',
        }
        for k, path in dmi_fields.items():
            try:
                results[k] = Path(path).read_text().strip()
            except:
                results[k] = "N/A"

        # Secure Boot
        sb_out, _, _ = run("mokutil --sb-state 2>/dev/null || echo 'N/A'")
        results['secure_boot'] = sb_out or "N/A"

        # UEFI vs BIOS
        results['firmware'] = "UEFI" if Path("/sys/firmware/efi").exists() else "Legacy BIOS"

        # CPU
        cpu_out, _, _ = run("grep 'model name' /proc/cpuinfo | head -1 | cut -d: -f2")
        results['cpu'] = cpu_out.strip() if cpu_out else platform.processor()
        results['cpu_cores'] = os.cpu_count()

        # RAM
        if PSUTIL_OK:
            mem = psutil.virtual_memory()
            results['ram_total'] = f"{mem.total // (1024**3)} GB"
            results['ram_used']  = f"{mem.used  // (1024**3)} GB"
            results['ram_pct']   = f"{mem.percent}%"

        # Uptime
        up, _, _ = run("uptime -p 2>/dev/null")
        results['uptime'] = up or "N/A"

        # Timezone
        tz, _, _ = run("timedatectl show -p Timezone --value 2>/dev/null || date +%Z")
        results['timezone'] = tz or "N/A"

        return results


class VulnScanner:
    """Detecta vulnerabilidades no sistema local."""

    KERNEL_VULNS = {
        "dirty_cow":      ("3.2","4.8.3",  "CVE-2016-5195", "Dirty COW — Escalada de privilégio via copy-on-write"),
        "spectre":        ("2.6","4.19.0", "CVE-2017-5753", "Spectre Variant 1 — Side-channel CPU"),
        "meltdown":       ("2.6","4.19.0", "CVE-2017-5754", "Meltdown — Leitura de memória kernel"),
        "stack_clash":    ("2.6","4.11.9", "CVE-2017-1000364","Stack Clash — Colisão de pilha"),
        "looney_tunables":("6.0","6.5.1",  "CVE-2023-4911", "Looney Tunables — Buffer overflow glibc"),
    }

    @staticmethod
    def check_kernel_vulns():
        findings = []
        kernel = platform.release()

        # Mitigations via /proc/sys
        mitigations = {
            "spectre_v1":  "/sys/devices/system/cpu/vulnerabilities/spectre_v1",
            "spectre_v2":  "/sys/devices/system/cpu/vulnerabilities/spectre_v2",
            "meltdown":    "/sys/devices/system/cpu/vulnerabilities/meltdown",
            "l1tf":        "/sys/devices/system/cpu/vulnerabilities/l1tf",
            "mds":         "/sys/devices/system/cpu/vulnerabilities/mds",
            "srbds":       "/sys/devices/system/cpu/vulnerabilities/srbds",
            "retbleed":    "/sys/devices/system/cpu/vulnerabilities/retbleed",
        }
        for name, path in mitigations.items():
            try:
                status = Path(path).read_text().strip()
                if "Vulnerable" in status:
                    sev = "HIGH"
                elif "Mitigation" in status:
                    sev = "MITIGATED"
                else:
                    sev = "OK"
                findings.append({
                    'type': 'CPU_VULN', 'name': name.upper(),
                    'status': sev, 'detail': status,
                })
            except:
                pass

        return findings

    @staticmethod
    def check_suid_binaries():
        """Lista binários SUID — vetor de escalonamento de privilégio."""
        findings = []
        out, _, rc = run("find / -perm -4000 -type f 2>/dev/null", timeout=20)
        if out:
            for line in out.splitlines()[:30]:
                findings.append({'type': 'SUID', 'path': line.strip(), 'status': 'WARN'})
        return findings

    @staticmethod
    def check_open_ports():
        """Portas abertas localmente."""
        findings = []
        out, _, _ = run("ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null")
        if out:
            for line in out.splitlines()[1:]:
                if 'LISTEN' in line or ':' in line:
                    findings.append({'type': 'OPEN_PORT', 'detail': line.strip(), 'status': 'INFO'})
        return findings

    @staticmethod
    def check_world_writable():
        """Arquivos world-writable em /etc — risco de backdoor."""
        findings = []
        out, _, _ = run("find /etc -perm -o+w -type f 2>/dev/null", timeout=15)
        if out:
            for line in out.splitlines()[:20]:
                findings.append({'type': 'WORLD_WRITE', 'path': line.strip(), 'status': 'HIGH'})
        return findings

    @staticmethod
    def check_crontabs():
        """Crontabs suspeitos."""
        findings = []
        locations = [
            "/etc/crontab", "/etc/cron.d", "/var/spool/cron/crontabs",
            "/etc/cron.hourly", "/etc/cron.daily",
        ]
        for loc in locations:
            p = Path(loc)
            if p.is_file():
                try:
                    content = p.read_text(errors='replace')
                    for ln in content.splitlines():
                        if any(x in ln for x in ['wget','curl','bash','python','nc ','ncat','base64']) and not ln.startswith('#'):
                            findings.append({'type': 'SUSPICIOUS_CRON', 'path': str(p), 'detail': ln[:100], 'status': 'HIGH'})
                except:
                    pass
            elif p.is_dir():
                for f in p.iterdir():
                    try:
                        content = f.read_text(errors='replace')
                        for ln in content.splitlines():
                            if any(x in ln for x in ['wget','curl','bash','python','nc ','ncat','base64']) and not ln.startswith('#'):
                                findings.append({'type': 'SUSPICIOUS_CRON', 'path': str(f), 'detail': ln[:100], 'status': 'HIGH'})
                    except:
                        pass
        return findings

    @staticmethod
    def check_ssh_config():
        """Configuração SSH insegura."""
        findings = []
        sshd_config = Path("/etc/ssh/sshd_config")
        if sshd_config.exists():
            try:
                content = sshd_config.read_text()
                checks = {
                    r'PermitRootLogin\s+yes':         ('HIGH',   'Root login SSH permitido!'),
                    r'PasswordAuthentication\s+yes':   ('MEDIUM', 'Autenticação por senha SSH ativa'),
                    r'PermitEmptyPasswords\s+yes':     ('CRITICAL','Senhas vazias SSH permitidas!'),
                    r'X11Forwarding\s+yes':            ('MEDIUM', 'X11 Forwarding ativo'),
                    r'Protocol\s+1':                   ('HIGH',   'SSHv1 ainda habilitado!'),
                }
                for pattern, (sev, msg) in checks.items():
                    if re.search(pattern, content, re.IGNORECASE):
                        findings.append({'type': 'SSH_CONFIG', 'status': sev, 'detail': msg})
            except:
                pass
        return findings

    @staticmethod
    def check_passwd_shadow():
        """Usuários sem senha e contas suspeitas."""
        findings = []
        try:
            with open('/etc/passwd') as f:
                for line in f:
                    parts = line.strip().split(':')
                    if len(parts) >= 7:
                        user, pw, uid, gid, _, home, shell = parts[:7]
                        if uid == '0' and user != 'root':
                            findings.append({'type': 'SHADOW_UID0', 'status': 'CRITICAL',
                                             'detail': f'Usuário {user} tem UID 0 (root)!'})
                        if pw == '' and shell not in ['/sbin/nologin','/usr/sbin/nologin','/bin/false','']:
                            findings.append({'type': 'EMPTY_PASS', 'status': 'HIGH',
                                             'detail': f'Usuário {user} sem senha e com shell ativo!'})
        except:
            pass
        return findings

    @staticmethod
    def check_firewall():
        """Status do firewall."""
        findings = []
        for cmd, name in [("ufw status 2>/dev/null","UFW"),("iptables -L 2>/dev/null | head -3","iptables")]:
            out, _, rc = run(cmd)
            if out:
                if "inactive" in out.lower() or "Status: inactive" in out:
                    findings.append({'type': 'FIREWALL', 'name': name, 'status': 'HIGH', 'detail': f'{name}: INATIVO!'})
                else:
                    findings.append({'type': 'FIREWALL', 'name': name, 'status': 'OK', 'detail': f'{name}: Ativo'})
        return findings

    @staticmethod
    def check_packages_updates():
        """Pacotes com updates de segurança pendentes."""
        findings = []
        # apt
        out, _, _ = run("apt list --upgradable 2>/dev/null | grep -i security | head -10", timeout=20)
        if out:
            count = len(out.splitlines())
            findings.append({'type': 'PKG_UPDATE', 'status': 'MEDIUM',
                              'detail': f'{count} atualização(ões) de segurança pendente(s)'})
        # rpm/dnf
        out2, _, _ = run("dnf updateinfo list security 2>/dev/null | head -5", timeout=10)
        if out2 and 'Error' not in out2:
            findings.append({'type': 'PKG_UPDATE_RPM', 'status': 'MEDIUM',
                              'detail': out2.splitlines()[0]})
        return findings


class MalwareScanner:
    """Análise básica de malware e rootkits."""

    SUSPICIOUS_PROCS = [
        'nc','ncat','netcat','nmap','masscan','hydra','medusa',
        'msfconsole','msfvenom','metasploit',
        'cryptominer','xmrig','minerd','cpuminer',
        'tcpdump','wireshark','ettercap','bettercap',
    ]

    SUSPICIOUS_DIRS = [
        '/tmp/.','  ','...','.. ','...',
    ]

    @staticmethod
    def check_processes():
        findings = []
        if PSUTIL_OK:
            for proc in psutil.process_iter(['pid','name','cmdline','username','cpu_percent']):
                try:
                    name  = (proc.info['name'] or '').lower()
                    cmdline = ' '.join(proc.info['cmdline'] or []).lower()
                    for sus in MalwareScanner.SUSPICIOUS_PROCS:
                        if sus in name or sus in cmdline:
                            findings.append({
                                'type': 'SUSPICIOUS_PROC',
                                'status': 'HIGH',
                                'pid': proc.info['pid'],
                                'name': proc.info['name'],
                                'detail': cmdline[:80],
                            })
                except:
                    pass
        return findings

    @staticmethod
    def check_startup():
        """Entradas de autorun suspeitas."""
        findings = []
        paths = [
            Path.home() / ".config/autostart",
            Path("/etc/xdg/autostart"),
            Path("/etc/init.d"),
            Path("/lib/systemd/system"),
        ]
        suspicious_kw = ['wget','curl','base64','python -c','bash -c','eval']
        for p in paths:
            if p.is_dir():
                for f in list(p.iterdir())[:50]:
                    try:
                        content = f.read_text(errors='replace')
                        for kw in suspicious_kw:
                            if kw in content:
                                findings.append({
                                    'type': 'SUSPICIOUS_STARTUP',
                                    'status': 'HIGH',
                                    'path': str(f),
                                    'detail': f'Keyword encontrada: {kw}',
                                })
                                break
                    except:
                        pass
        return findings

    @staticmethod
    def check_hidden_files_tmp():
        """Arquivos ocultos em /tmp — vetor comum de malware."""
        findings = []
        out, _, _ = run("find /tmp /var/tmp -name '.*' -o -name '* *' 2>/dev/null", timeout=10)
        if out:
            for line in out.splitlines()[:20]:
                findings.append({'type': 'HIDDEN_TMP', 'status': 'MEDIUM', 'path': line.strip()})
        return findings

    @staticmethod
    def check_rootkit_indicators():
        """Indicadores simples de rootkits."""
        findings = []
        # chkrootkit se disponível
        out, _, rc = run("which chkrootkit 2>/dev/null")
        if out:
            result, _, _ = run("chkrootkit 2>/dev/null | grep -i infected", timeout=30)
            if result:
                for line in result.splitlines():
                    findings.append({'type': 'ROOTKIT', 'status': 'CRITICAL', 'detail': line.strip()})
        # rkhunter se disponível
        out2, _, _ = run("which rkhunter 2>/dev/null")
        if out2:
            findings.append({'type': 'ROOTKIT_TOOL', 'status': 'INFO',
                             'detail': 'rkhunter disponível — execute: sudo rkhunter --check'})
        # /dev com arquivos suspeitos
        out3, _, _ = run("find /dev -type f 2>/dev/null | head -10", timeout=5)
        if out3:
            for line in out3.splitlines():
                if not any(ok in line for ok in ['fd','stdin','stdout','stderr','null','zero','random','urandom','tty','pts']):
                    findings.append({'type': 'DEV_FILE', 'status': 'HIGH',
                                     'path': line.strip(), 'detail': 'Arquivo incomum em /dev'})
        return findings

    @staticmethod
    def hash_check(filepath):
        """Calcula MD5/SHA256 de um arquivo."""
        try:
            data = Path(filepath).read_bytes()
            return {
                'md5':    hashlib.md5(data).hexdigest(),
                'sha256': hashlib.sha256(data).hexdigest(),
                'size':   len(data),
            }
        except Exception as e:
            return {'error': str(e)}


class NetworkAnalyzer:
    """Análise de rede defensiva."""

    @staticmethod
    def get_interfaces():
        findings = []
        if PSUTIL_OK:
            addrs = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
            for iface, addr_list in addrs.items():
                iface_info = {'name': iface, 'addresses': []}
                for addr in addr_list:
                    iface_info['addresses'].append({
                        'family': str(addr.family),
                        'address': addr.address,
                    })
                if iface in stats:
                    s = stats[iface]
                    iface_info['up']    = s.isup
                    iface_info['speed'] = s.speed
                findings.append(iface_info)
        return findings

    @staticmethod
    def get_connections():
        conns = []
        if PSUTIL_OK:
            for c in psutil.net_connections(kind='inet'):
                try:
                    conns.append({
                        'status': c.status,
                        'laddr':  f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else '',
                        'raddr':  f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else '',
                        'pid':    c.pid,
                    })
                except:
                    pass
        return conns

    @staticmethod
    def check_promiscuous():
        """Detecta interfaces em modo promíscuo (sniffing)."""
        findings = []
        out, _, _ = run("ip link show 2>/dev/null")
        for line in out.splitlines():
            if 'PROMISC' in line:
                findings.append({'type': 'PROMISC', 'status': 'HIGH', 'detail': line.strip()})
        return findings


# ═══════════════════════════════════════════════════════
#  INTERFACE GRÁFICA — NekotinaCat
# ═══════════════════════════════════════════════════════

class NekotinaApp(tk.Tk):

    W, H = 1100, 700

    def __init__(self):
        super().__init__()
        self.title(f"{NAME} — {CODENAME}")
        self.configure(bg=BG)
        self.overrideredirect(True)
        try:
            self.attributes("-alpha", 0.97)
        except:
            pass

        self._center()
        self.geometry(f"{self.W}x{self.H}")

        self._drag_x = self._drag_y = 0
        self._scan_running = False
        self._current_tab  = "dashboard"

        self._build_ui()
        self._animate_glow()
        self._animate_penta()
        self._refresh_dashboard()

    def _center(self):
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        x  = (sw - self.W) // 2
        y  = (sh - self.H) // 2
        self.geometry(f"{self.W}x{self.H}+{x}+{y}")

    # ── Layout ─────────────────────────────────────────

    def _build_ui(self):
        # Canvas principal
        self.cv = tk.Canvas(self, width=self.W, height=self.H,
                             bg=BG, highlightthickness=0)
        self.cv.pack(fill="both", expand=True)

        # Frame geral sobre o canvas
        self.cv.create_rectangle(0, 0, self.W, self.H, fill=BG, outline="")

        self._draw_borders()
        self._draw_titlebar()
        self._draw_cat_panel()
        self._draw_sidebar()
        self._draw_main_area()
        self._update_datetime()

    def _draw_borders(self):
        c = self.cv
        # Borda externa glow
        self._border_outer = c.create_rectangle(1,1,self.W-1,self.H-1,
                                                  outline=GLOW1, width=2)
        self._border_inner = c.create_rectangle(3,3,self.W-3,self.H-3,
                                                  outline=GLOW2+"44", width=1)

    def _draw_titlebar(self):
        c = self.cv
        c.create_rectangle(0,0,self.W,46, fill=BG2, outline="")
        c.create_line(0,46,self.W,46, fill=GLOW1, width=1)

        # Ícone skull-cat ASCII
        c.create_text(18, 23, text="◈", font=("Courier New",16,"bold"),
                      fill=GLOW2, anchor="w")
        c.create_text(44, 14, text=NAME, font=("Courier New",13,"bold"),
                      fill=TEXT, anchor="w")
        c.create_text(44, 32, text=f"v{VERSION}  ·  {CODENAME}",
                      font=("Courier New",8), fill=MUTED, anchor="w")

        # DateTime
        self._dt_text = c.create_text(self.W//2, 23, text="",
                                       font=("Courier New",10), fill=GLOW3)

        # Botões WM
        for i, (sym, col, cmd) in enumerate([
            ("−", WARNING, self.iconify),
            ("□", CYAN,    lambda: None),
            ("✕", GLOW1,   self.destroy),
        ]):
            bx = self.W - 35 - i*36
            btn = c.create_text(bx, 23, text=sym, font=("Courier New",14,"bold"), fill=MUTED)
            c.tag_bind(btn,"<Enter>", lambda e,b=btn,co=col: c.itemconfigure(b, fill=co))
            c.tag_bind(btn,"<Leave>",lambda e,b=btn: c.itemconfigure(b, fill=MUTED))
            c.tag_bind(btn,"<Button-1>", lambda e,fn=cmd: fn())

        # Drag
        c.bind("<ButtonPress-1>",   self._press)
        c.bind("<B1-Motion>",       self._drag)

    def _draw_cat_panel(self):
        """Painel direito: gato com olhos vermelhos + pentagrama brilhante."""
        c = self.cv
        px, py = self.W - 220, 50

        c.create_rectangle(px, py, self.W-4, self.H-4,
                            fill="#070303", outline=BORDER, width=1)

        # ── GATO ─────────────────────────────────────
        cx, cy = px + 108, py + 160

        # Corpo
        c.create_oval(cx-65, cy-50, cx+65, cy+65,
                      fill="#0d0505", outline=GLOW1, width=1)

        # Cabeça
        c.create_oval(cx-55, cy-130, cx+55, cy-20,
                      fill="#110808", outline=GLOW1, width=1)

        # Orelhas
        c.create_polygon(cx-55, cy-90, cx-75, cy-155, cx-30, cy-105,
                         fill="#1a0808", outline=GLOW1, width=1)
        c.create_polygon(cx+55, cy-90, cx+75, cy-155, cx+30, cy-105,
                         fill="#1a0808", outline=GLOW1, width=1)
        # Inner ear
        c.create_polygon(cx-53, cy-92, cx-68, cy-145, cx-32, cy-107,
                         fill=BORDER+"66")
        c.create_polygon(cx+53, cy-92, cx+68, cy-145, cx+32, cy-107,
                         fill=BORDER+"66")

        # ── Olhos vermelhos brilhantes ────────────────
        for ex in [cx-22, cx+22]:
            # glow externo
            c.create_oval(ex-16, cy-90, ex+16, cy-58,
                          fill="#220000", outline=GLOW2, width=2)
            # íris vermelha
            c.create_oval(ex-11, cy-87, ex+11, cy-61,
                          fill=GLOW1)
            # pupila vertical
            c.create_oval(ex-4, cy-88, ex+4, cy-60,
                          fill="#000")
            # reflexo brilhante
            c.create_oval(ex-7, cy-85, ex-3, cy-79,
                          fill=GLOW3)

        # Nariz
        c.create_polygon(cx-5, cy-55, cx+5, cy-55, cx, cy-48,
                         fill=BORDER)

        # Bigodes
        for dy in [-4, 0, 4]:
            c.create_line(cx-45, cy-52+dy, cx-10, cy-52+dy,
                          fill=BORDER+"88", width=1)
            c.create_line(cx+10, cy-52+dy, cx+45, cy-52+dy,
                          fill=BORDER+"88", width=1)

        # Boca
        c.create_arc(cx-12, cy-50, cx-2, cy-42, start=180, extent=180,
                     outline=GLOW1, style="arc", width=1)
        c.create_arc(cx+2, cy-50, cx+12, cy-42, start=180, extent=180,
                     outline=GLOW1, style="arc", width=1)

        # Patas
        for px2 in [cx-35, cx+10]:
            c.create_oval(px2, cy+40, px2+30, cy+75,
                          fill="#0d0505", outline=GLOW1+"66", width=1)
            # dedos
            for dx in [0, 10, 20]:
                c.create_oval(px2+dx, cy+60, px2+dx+8, cy+78,
                              fill="#110808", outline=BORDER+"44")

        # Cauda
        c.create_arc(cx+20, cy+10, cx+140, cy+90, start=60, extent=200,
                     outline=GLOW1, style="arc", width=2)

        # ── PENTAGRAMA brilhando ──────────────────────
        self._penta_cx = cx
        self._penta_cy = cy + 140
        self._penta_r  = 52
        self._penta_items = []
        self._draw_pentagram(c, cx, cy+140, 52)

        # Texto do painel
        c.create_text(cx, cy+205, text="NEKOTINACAT", font=("Courier New",9,"bold"),
                      fill=GLOW1)
        c.create_text(cx, cy+218, text="CRIMSON SENTINEL", font=("Courier New",7),
                      fill=MUTED)

        # Status do sistema
        self._sys_status_text = c.create_text(cx, py+460,
            text="SISTEMA: VERIFICANDO…",
            font=("Courier New",8,"bold"), fill=WARNING)

    def _draw_pentagram(self, c, cx, cy, r):
        for item in self._penta_items:
            c.delete(item)
        self._penta_items.clear()

        # Círculo externo
        item = c.create_oval(cx-r-6, cy-r-6, cx+r+6, cy+r+6,
                              outline=GLOW1, width=1)
        self._penta_items.append(item)

        # Círculo interno
        item2 = c.create_oval(cx-r+4, cy-r+4, cx+r-4, cy+r-4,
                               outline=BORDER+"66", width=1)
        self._penta_items.append(item2)

        # Pontos do pentagrama
        pts = []
        for i in range(5):
            angle = math.radians(-90 + i * 144)
            pts.append((cx + r * math.cos(angle), cy + r * math.sin(angle)))

        # Linhas (estrela de 5 pontas)
        order = [0, 2, 4, 1, 3, 0]
        for i in range(len(order)-1):
            x1, y1 = pts[order[i]]
            x2, y2 = pts[order[i+1]]
            item = c.create_line(x1, y1, x2, y2, fill=GLOW1, width=1)
            self._penta_items.append(item)

        # Vértices
        for px2, py2 in pts:
            item = c.create_oval(px2-3, py2-3, px2+3, py2+3, fill=GLOW2, outline="")
            self._penta_items.append(item)

        # Centro
        item = c.create_text(cx, cy, text="✦", font=("Courier New",10,"bold"),
                              fill=GLOW2)
        self._penta_items.append(item)

    def _draw_sidebar(self):
        c = self.cv
        # Sidebar
        c.create_rectangle(0, 46, 175, self.H, fill=BG2, outline="")
        c.create_line(175, 46, 175, self.H, fill=GLOW1, width=1)

        tabs = [
            ("◈", "dashboard",   "DASHBOARD"),
            ("⚡", "vulnscan",    "VULN SCAN"),
            ("🦠", "malware",     "MALWARE"),
            ("🌐", "network",     "REDE"),
            ("🔧", "system",      "SISTEMA"),
            ("📋", "log",         "LOG"),
        ]

        self._tab_buttons = {}
        for i, (icon, key, label) in enumerate(tabs):
            y = 80 + i * 70
            bg_item  = c.create_rectangle(2, y-22, 173, y+22,
                                           fill=BG3 if key=="dashboard" else BG2, outline="")
            bar_item = c.create_rectangle(2, y-22, 6, y+22,
                                           fill=GLOW1 if key=="dashboard" else BG2, outline="")
            ico_item = c.create_text(30, y-5, text=icon, font=("Courier New",16), fill=GLOW1)
            lbl_item = c.create_text(90, y-5, text=label, font=("Courier New",10,"bold"),
                                      fill=TEXT if key=="dashboard" else MUTED)
            self._tab_buttons[key] = (bg_item, bar_item, lbl_item)
            for item in [bg_item, bar_item, ico_item, lbl_item]:
                c.tag_bind(item, "<Button-1>", lambda e, k=key: self._switch_tab(k))
                c.tag_bind(item, "<Enter>",
                           lambda e, bg=bg_item, l=lbl_item: (
                               c.itemconfigure(bg, fill=BG3),
                               c.itemconfigure(l, fill=TEXT)))
                c.tag_bind(item, "<Leave>",
                           lambda e, k2=key, bg=bg_item, l=lbl_item: (
                               c.itemconfigure(bg, fill=BG3 if self._current_tab==k2 else BG2),
                               c.itemconfigure(l, fill=TEXT if self._current_tab==k2 else MUTED)))

        # Botão SCAN
        self._scan_btn = tk.Button(self, text="▶  INICIAR SCAN",
            font=("Courier New",11,"bold"),
            bg=GLOW1, fg="#fff",
            activebackground="#8b0000", activeforeground="#fff",
            relief="flat", bd=0, cursor="hand2",
            command=self._start_full_scan)
        self._scan_btn.place(x=10, y=500, width=155, height=38)

        # Progresso
        c.create_rectangle(10, 548, 165, 562, fill="#1a0808", outline=BORDER, width=1)
        self._scan_prog = c.create_rectangle(10, 548, 10, 562, fill=GLOW1, outline="")
        self._scan_pct  = c.create_text(88, 555, text="", font=("Courier New",8), fill=TEXT)
        self._scan_lbl  = c.create_text(88, 572, text="Pronto", font=("Courier New",8),
                                         fill=MUTED, width=155)

    def _draw_main_area(self):
        """Área principal de conteúdo."""
        c = self.cv
        self._main_x = 180
        self._main_y = 50
        self._main_w = self.W - 220 - 180 - 4
        self._main_h = self.H - 54

        # Fundo da área principal
        c.create_rectangle(self._main_x, self._main_y,
                            self._main_x + self._main_w,
                            self._main_y + self._main_h,
                            fill=PANEL, outline=BORDER+"44", width=1)

        # Frame para conteúdo dinâmico
        self._content_frame = tk.Frame(self, bg=PANEL, bd=0)
        self._content_frame.place(x=self._main_x+4, y=self._main_y+4,
                                   width=self._main_w-8, height=self._main_h-8)

        self._show_dashboard()

    # ── Tabs ───────────────────────────────────────────

    def _switch_tab(self, key):
        c = self.cv
        for k, (bg, bar, lbl) in self._tab_buttons.items():
            if k == key:
                c.itemconfigure(bg, fill=BG3)
                c.itemconfigure(bar, fill=GLOW1)
                c.itemconfigure(lbl, fill=TEXT)
            else:
                c.itemconfigure(bg, fill=BG2)
                c.itemconfigure(bar, fill=BG2)
                c.itemconfigure(lbl, fill=MUTED)
        self._current_tab = key
        for w in self._content_frame.winfo_children():
            w.destroy()
        {
            "dashboard": self._show_dashboard,
            "vulnscan":  self._show_vulnscan,
            "malware":   self._show_malware,
            "network":   self._show_network,
            "system":    self._show_system,
            "log":       self._show_log,
        }[key]()

    def _make_log_widget(self, parent=None):
        if parent is None:
            parent = self._content_frame
        txt = tk.Text(parent, bg="#060202", fg=MONO,
                      font=("Courier New", 9), relief="flat", bd=0,
                      state="disabled", wrap="word",
                      insertbackground=GLOW1,
                      selectbackground=BORDER, selectforeground=TEXT)
        sb = tk.Scrollbar(parent, orient="vertical", command=txt.yview,
                           bg=BG, troughcolor=BG, activebackground=GLOW1,
                           relief="flat", bd=0)
        txt.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        txt.pack(fill="both", expand=True)
        return txt

    def _log_append(self, widget, msg, color=None):
        def _do():
            widget.configure(state="normal")
            if color:
                tag = f"col_{color.replace('#','')}"
                widget.tag_configure(tag, foreground=color)
                widget.insert("end", msg + "\n", tag)
            else:
                widget.insert("end", msg + "\n")
            widget.see("end")
            widget.configure(state="disabled")
        try:
            widget.after(0, _do)
        except:
            pass

    def _header_label(self, text, sub=""):
        tk.Label(self._content_frame, text=text,
                 font=("Courier New",14,"bold"), bg=PANEL, fg=GLOW2).pack(anchor="w", padx=12, pady=(10,0))
        if sub:
            tk.Label(self._content_frame, text=sub,
                     font=("Courier New",9), bg=PANEL, fg=MUTED).pack(anchor="w", padx=14, pady=(0,8))

    # ── Dashboard ──────────────────────────────────────

    def _show_dashboard(self):
        self._header_label("◈  DASHBOARD", "Visão geral do sistema em tempo real")

        # Grid de cards
        grid = tk.Frame(self._content_frame, bg=PANEL)
        grid.pack(fill="x", padx=8)

        cards_data = [
            ("🖥  SISTEMA", "sys_val"),
            ("🧠  CPU", "cpu_val"),
            ("💾  RAM", "ram_val"),
            ("🌐  REDE", "net_val"),
        ]

        self._dash_cards = {}
        for i, (title, key) in enumerate(cards_data):
            fr = tk.Frame(grid, bg=BG3, relief="flat", bd=0)
            fr.grid(row=0, column=i, padx=4, pady=4, sticky="nsew")
            grid.columnconfigure(i, weight=1)

            tk.Label(fr, text=title, font=("Courier New",9,"bold"),
                     bg=BG3, fg=GLOW1).pack(anchor="w", padx=8, pady=(8,2))
            lbl = tk.Label(fr, text="—", font=("Courier New",11,"bold"),
                           bg=BG3, fg=TEXT, wraplength=160, justify="left")
            lbl.pack(anchor="w", padx=8, pady=(2,8))
            self._dash_cards[key] = lbl

        # Log de eventos
        sep = tk.Frame(self._content_frame, bg=BORDER, height=1)
        sep.pack(fill="x", padx=8, pady=6)
        tk.Label(self._content_frame, text="⚡  EVENTOS RECENTES",
                 font=("Courier New",10,"bold"), bg=PANEL, fg=GLOW1).pack(anchor="w", padx=12)
        self._dash_log = self._make_log_widget()
        self._refresh_dashboard()

    def _refresh_dashboard(self):
        if not hasattr(self, '_dash_cards'):
            return

        info = SystemAnalyzer.full_report()
        os_str = info.get('pretty_name', info.get('os','?'))
        self._dash_cards['sys_val'].configure(
            text=f"{os_str}\n{info.get('kernel','?')}")
        self._dash_cards['cpu_val'].configure(
            text=f"{info.get('cpu','?')[:30]}\n{info.get('cpu_cores','?')} cores")
        self._dash_cards['ram_val'].configure(
            text=f"Total: {info.get('ram_total','?')}\nUso: {info.get('ram_pct','?')}")

        if PSUTIL_OK:
            net = psutil.net_io_counters()
            self._dash_cards['net_val'].configure(
                text=f"↑ {net.bytes_sent//1024//1024} MB\n↓ {net.bytes_recv//1024//1024} MB")

        if hasattr(self,'_dash_log'):
            ts = datetime.now().strftime("%H:%M:%S")
            self._log_append(self._dash_log,
                f"[{ts}] Firmware: {info.get('firmware','?')} | BIOS: {info.get('bios_vendor','?')} {info.get('bios_version','?')}",
                CYAN)
            self._log_append(self._dash_log,
                f"[{ts}] Produto: {info.get('product_name','?')} | Placa: {info.get('board_name','?')}",
                MONO2)
            self._log_append(self._dash_log,
                f"[{ts}] Secure Boot: {info.get('secure_boot','?')} | Uptime: {info.get('uptime','?')}",
                SUCCESS if "enabled" in info.get('secure_boot','').lower() else WARNING)

        self.after(10000, self._refresh_dashboard)

    # ── VulnScan ───────────────────────────────────────

    def _show_vulnscan(self):
        self._header_label("⚡  VULNERABILITY SCAN",
                           "Análise de CVEs, configurações inseguras e exposições")
        fr = tk.Frame(self._content_frame, bg=PANEL)
        fr.pack(fill="x", padx=8)
        tk.Button(fr, text="▶ Escanear Kernel/CPU",
                  font=("Courier New",9,"bold"), bg=GLOW1, fg="#fff",
                  relief="flat", bd=0, cursor="hand2", padx=10, pady=4,
                  command=lambda: self._run_vuln_scan("kernel")).pack(side="left", padx=4, pady=4)
        tk.Button(fr, text="▶ SSH / Usuários",
                  font=("Courier New",9,"bold"), bg=BG3, fg=TEXT,
                  relief="flat", bd=0, cursor="hand2", padx=10, pady=4,
                  command=lambda: self._run_vuln_scan("users")).pack(side="left", padx=4, pady=4)
        tk.Button(fr, text="▶ Firewall / Portas",
                  font=("Courier New",9,"bold"), bg=BG3, fg=TEXT,
                  relief="flat", bd=0, cursor="hand2", padx=10, pady=4,
                  command=lambda: self._run_vuln_scan("ports")).pack(side="left", padx=4, pady=4)
        tk.Button(fr, text="▶ SUID / Cron",
                  font=("Courier New",9,"bold"), bg=BG3, fg=TEXT,
                  relief="flat", bd=0, cursor="hand2", padx=10, pady=4,
                  command=lambda: self._run_vuln_scan("suid")).pack(side="left", padx=4, pady=4)

        self._vuln_log = self._make_log_widget()
        self._log_append(self._vuln_log, f"NekotinaCat VulnScanner v{VERSION} — pronto.", CYAN)
        self._log_append(self._vuln_log, "Selecione um módulo de scan acima.", MUTED)

    def _run_vuln_scan(self, mode):
        if not hasattr(self, '_vuln_log'):
            return
        log = self._vuln_log

        def _sev_color(s):
            return {
                'CRITICAL':'#ff0000','HIGH':DANGER,'MEDIUM':WARNING,
                'MITIGATED':SUCCESS,'OK':SUCCESS,'INFO':CYAN,
            }.get(s, MONO)

        def worker():
            self._log_append(log, f"\n[+] Iniciando scan: {mode.upper()} — {datetime.now().strftime('%H:%M:%S')}", GLOW2)
            try:
                findings = []
                if mode == "kernel":
                    findings = VulnScanner.check_kernel_vulns()
                elif mode == "users":
                    findings = VulnScanner.check_ssh_config() + VulnScanner.check_passwd_shadow()
                elif mode == "ports":
                    findings = VulnScanner.check_firewall() + VulnScanner.check_open_ports()
                elif mode == "suid":
                    findings = VulnScanner.check_suid_binaries() + VulnScanner.check_crontabs()

                if not findings:
                    self._log_append(log, "    [✓] Nenhum problema encontrado.", SUCCESS)
                else:
                    for f in findings:
                        sev   = f.get('status','INFO')
                        color = _sev_color(sev)
                        ftype = f.get('type','')
                        detail= f.get('detail') or f.get('path','') or f.get('name','')
                        self._log_append(log, f"    [{sev:8s}] {ftype}: {detail}", color)
            except Exception as e:
                self._log_append(log, f"    [!] Erro: {e}", DANGER)
            self._log_append(log, f"[+] Scan {mode.upper()} concluído.", GLOW1)

        threading.Thread(target=worker, daemon=True).start()

    # ── Malware ────────────────────────────────────────

    def _show_malware(self):
        self._header_label("🦠  MALWARE & ROOTKIT SCANNER",
                           "Processos suspeitos, autorun, arquivos ocultos, rootkits")
        fr = tk.Frame(self._content_frame, bg=PANEL)
        fr.pack(fill="x", padx=8)
        for label, mode in [
            ("▶ Processos", "procs"),
            ("▶ Autorun", "startup"),
            ("▶ /tmp Ocultos", "hidden"),
            ("▶ Rootkit", "rootkit"),
        ]:
            tk.Button(fr, text=label,
                      font=("Courier New",9,"bold"), bg=BG3, fg=TEXT,
                      relief="flat", bd=0, cursor="hand2", padx=10, pady=4,
                      command=lambda m=mode: self._run_malware_scan(m)
                      ).pack(side="left", padx=4, pady=4)

        self._malware_log = self._make_log_widget()
        self._log_append(self._malware_log, f"NekotinaCat MalwareScanner — pronto.", CYAN)

    def _run_malware_scan(self, mode):
        log = self._malware_log
        def worker():
            self._log_append(log, f"\n[+] MALWARE SCAN: {mode.upper()} — {datetime.now().strftime('%H:%M:%S')}", GLOW2)
            try:
                findings = {
                    "procs":   MalwareScanner.check_processes,
                    "startup": MalwareScanner.check_startup,
                    "hidden":  MalwareScanner.check_hidden_files_tmp,
                    "rootkit": MalwareScanner.check_rootkit_indicators,
                }[mode]()
                if not findings:
                    self._log_append(log, "    [✓] Nenhuma ameaça detectada.", SUCCESS)
                else:
                    for f in findings:
                        sev = f.get('status','INFO')
                        col = DANGER if sev in ('CRITICAL','HIGH') else WARNING if sev=='MEDIUM' else CYAN
                        detail = f.get('detail','') or f.get('path','') or f.get('name','')
                        self._log_append(log, f"    [{sev:8s}] {f.get('type')}: {detail}", col)
            except Exception as e:
                self._log_append(log, f"    [!] Erro: {e}", DANGER)
            self._log_append(log, "[+] Concluído.", GLOW1)
        threading.Thread(target=worker, daemon=True).start()

    # ── Network ────────────────────────────────────────

    def _show_network(self):
        self._header_label("🌐  ANÁLISE DE REDE",
                           "Interfaces, conexões ativas, modo promíscuo")
        fr = tk.Frame(self._content_frame, bg=PANEL)
        fr.pack(fill="x", padx=8)
        tk.Button(fr, text="▶ Interfaces", font=("Courier New",9,"bold"),
                  bg=BG3, fg=TEXT, relief="flat", bd=0, cursor="hand2", padx=10, pady=4,
                  command=self._show_interfaces).pack(side="left", padx=4, pady=4)
        tk.Button(fr, text="▶ Conexões", font=("Courier New",9,"bold"),
                  bg=BG3, fg=TEXT, relief="flat", bd=0, cursor="hand2", padx=10, pady=4,
                  command=self._show_connections).pack(side="left", padx=4, pady=4)
        tk.Button(fr, text="▶ Modo Promíscuo", font=("Courier New",9,"bold"),
                  bg=GLOW1, fg="#fff", relief="flat", bd=0, cursor="hand2", padx=10, pady=4,
                  command=self._check_promisc).pack(side="left", padx=4, pady=4)

        self._net_log = self._make_log_widget()
        self._log_append(self._net_log, "NekotinaCat NetworkAnalyzer — pronto.", CYAN)

    def _show_interfaces(self):
        log = self._net_log
        self._log_append(log, f"\n[+] INTERFACES — {datetime.now().strftime('%H:%M:%S')}", GLOW2)
        for iface in NetworkAnalyzer.get_interfaces():
            status = "UP" if iface.get('up') else "DOWN"
            color  = SUCCESS if iface.get('up') else MUTED
            self._log_append(log, f"    [{status}] {iface['name']} — speed: {iface.get('speed',0)} Mbps", color)
            for a in iface.get('addresses', []):
                self._log_append(log, f"           {a['address']}", MONO2)

    def _show_connections(self):
        log = self._net_log
        self._log_append(log, f"\n[+] CONEXÕES ATIVAS — {datetime.now().strftime('%H:%M:%S')}", GLOW2)
        conns = NetworkAnalyzer.get_connections()
        for c in conns[:40]:
            col = DANGER if c['raddr'] else MONO
            self._log_append(log,
                f"    [{c['status']:11s}] {c['laddr']:25s} → {c['raddr'] or '-':25s} PID:{c['pid']}", col)

    def _check_promisc(self):
        log = self._net_log
        self._log_append(log, f"\n[+] CHECK PROMÍSCUO — {datetime.now().strftime('%H:%M:%S')}", GLOW2)
        findings = NetworkAnalyzer.check_promiscuous()
        if not findings:
            self._log_append(log, "    [✓] Nenhuma interface em modo promíscuo.", SUCCESS)
        else:
            for f in findings:
                self._log_append(log, f"    [ALERTA] {f['detail']}", DANGER)

    # ── System ─────────────────────────────────────────

    def _show_system(self):
        self._header_label("🔧  INFORMAÇÕES DO SISTEMA",
                           "Hardware, BIOS/UEFI, distro, kernel, configurações")

        txt = self._make_log_widget()
        self._log_append(txt, f"{'='*60}", GLOW1)
        self._log_append(txt, f"  NekotinaCat — Relatório de Sistema", GLOW2)
        self._log_append(txt, f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", MUTED)
        self._log_append(txt, f"{'='*60}", GLOW1)

        def worker():
            info = SystemAnalyzer.full_report()
            sections = [
                ("OS / DISTRO", [
                    ('Sistema',    info.get('os','')),
                    ('Distro',     info.get('pretty_name', info.get('name',''))),
                    ('Versão',     info.get('version_id','')),
                    ('Kernel',     info.get('kernel','')),
                    ('Arch',       info.get('arch','')),
                    ('Hostname',   info.get('node','')),
                    ('Uptime',     info.get('uptime','')),
                    ('Timezone',   info.get('timezone','')),
                ]),
                ("FIRMWARE / BIOS", [
                    ('Tipo',         info.get('firmware','')),
                    ('Vendor BIOS',  info.get('bios_vendor','')),
                    ('Versão BIOS',  info.get('bios_version','')),
                    ('Data BIOS',    info.get('bios_date','')),
                    ('Fabricante',   info.get('sys_vendor','')),
                    ('Produto',      info.get('product_name','')),
                    ('Placa',        info.get('board_name','')),
                    ('Secure Boot',  info.get('secure_boot','')),
                ]),
                ("HARDWARE", [
                    ('CPU',   info.get('cpu','')),
                    ('Cores', str(info.get('cpu_cores',''))),
                    ('RAM Total', info.get('ram_total','')),
                    ('RAM Uso',   info.get('ram_used','')),
                    ('RAM %',     info.get('ram_pct','')),
                ]),
            ]
            for section_name, fields in sections:
                self._log_append(txt, f"\n  ── {section_name} ──", GLOW1)
                for k, v in fields:
                    if v:
                        self._log_append(txt, f"    {k:20s}: {v}", MONO2)

            # Discos
            self._log_append(txt, "\n  ── DISCOS ──", GLOW1)
            out, _, _ = run("lsblk -o NAME,SIZE,TYPE,MOUNTPOINT,FSTYPE 2>/dev/null | head -20")
            for line in out.splitlines():
                self._log_append(txt, f"    {line}", MONO)

            # Config do sistema
            self._log_append(txt, "\n  ── CONFIGURAÇÃO DO KERNEL (sysctl) ──", GLOW1)
            checks = {
                "net.ipv4.ip_forward":              ("Packet forwarding", "0"),
                "net.ipv4.conf.all.accept_redirects":("ICMP redirects",   "0"),
                "net.ipv4.tcp_syncookies":           ("SYN cookies",      "1"),
                "kernel.randomize_va_space":         ("ASLR",             "2"),
                "kernel.dmesg_restrict":             ("dmesg restrict",   "1"),
                "fs.suid_dumpable":                  ("SUID dumpable",    "0"),
            }
            for key, (desc, safe_val) in checks.items():
                out2, _, _ = run(f"sysctl -n {key} 2>/dev/null")
                val = out2.strip()
                ok  = val == safe_val
                color = SUCCESS if ok else WARNING
                self._log_append(txt, f"    {desc:30s}: {val:4s}  {'[OK]' if ok else '[RISCO]'}", color)

        threading.Thread(target=worker, daemon=True).start()

    # ── Log central ─────────────────────────────────────

    def _show_log(self):
        self._header_label("📋  LOG DE EVENTOS", "Histórico de scans e eventos do framework")
        if not hasattr(self, '_central_log'):
            self._central_log = self._make_log_widget()
        else:
            self._central_log.pack(fill="both", expand=True)

    # ── Full scan ──────────────────────────────────────

    def _start_full_scan(self):
        if self._scan_running:
            return
        self._scan_running = True
        self._scan_btn.configure(state="disabled", text="Escaneando…")

        def worker():
            steps = [
                (10,  "Analisando kernel CVEs…",    VulnScanner.check_kernel_vulns),
                (25,  "Verificando SSH…",            VulnScanner.check_ssh_config),
                (35,  "Verificando usuários…",       VulnScanner.check_passwd_shadow),
                (45,  "Verificando firewall…",       VulnScanner.check_firewall),
                (55,  "SUID binaries…",              VulnScanner.check_suid_binaries),
                (65,  "Crontabs suspeitos…",         VulnScanner.check_crontabs),
                (72,  "Processos maliciosos…",       MalwareScanner.check_processes),
                (80,  "Autorun suspeito…",           MalwareScanner.check_startup),
                (87,  "Arquivos ocultos /tmp…",      MalwareScanner.check_hidden_files_tmp),
                (93,  "Indicadores rootkit…",        MalwareScanner.check_rootkit_indicators),
                (97,  "Interface promíscua…",        NetworkAnalyzer.check_promiscuous),
                (100, "Scan completo.",              None),
            ]

            total_findings = []
            critical = 0

            for pct, msg, fn in steps:
                self._set_scan_progress(pct, msg)
                if fn:
                    try:
                        findings = fn()
                        total_findings.extend(findings)
                        for f in findings:
                            if f.get('status') in ('CRITICAL','HIGH'):
                                critical += 1
                    except:
                        pass
                time.sleep(0.3)

            # Resultado
            def _done():
                self._scan_running = False
                self._scan_btn.configure(state="normal", text="▶  INICIAR SCAN")
                if critical > 0:
                    self.cv.itemconfigure(self._sys_status_text,
                        text=f"⚠ {critical} AMEAÇA(S) DETECTADA(S)", fill=DANGER)
                else:
                    self.cv.itemconfigure(self._sys_status_text,
                        text="✓ SISTEMA: LIMPO", fill=SUCCESS)
                self._set_scan_progress(100, f"Concluído: {len(total_findings)} findings, {critical} críticos")
            self.after(0, _done)

        threading.Thread(target=worker, daemon=True).start()

    def _set_scan_progress(self, pct, msg=""):
        def _do():
            w = int((pct/100) * 155)
            self.cv.coords(self._scan_prog, 10, 548, 10+w, 562)
            self.cv.itemconfigure(self._scan_pct, text=f"{pct}%")
            if msg:
                self.cv.itemconfigure(self._scan_lbl, text=msg[:25])
        self.after(0, _do)

    # ── Animações ──────────────────────────────────────

    def _animate_glow(self):
        palette = [
            "#cc1a1a","#d42020","#dc2626","#e03030",
            "#dc2626","#d42020","#cc1a1a","#b81515",
            "#a01010","#b81515","#cc1a1a",
        ]
        idx = [0]
        def tick():
            if not self.winfo_exists():
                return
            col = palette[idx[0] % len(palette)]
            self.cv.itemconfigure(self._border_outer, outline=col)
            idx[0] += 1
            self.after(100, tick)
        tick()

    def _animate_penta(self):
        """Faz o pentagrama pulsar/girar com glow vermelho."""
        angle = [0.0]
        colors_glow = [
            "#8b0000","#a01010","#cc1a1a","#dc2626","#e03030",
            "#ff3333","#e03030","#dc2626","#cc1a1a","#a01010",
        ]
        idx = [0]
        def tick():
            if not self.winfo_exists():
                return
            # Redesenha pentagrama com ângulo rotacionado e cor oscilante
            col_old = GLOW1
            new_col = colors_glow[idx[0] % len(colors_glow)]

            # Recria os itens do pentagrama com nova cor
            for item in self._penta_items:
                try:
                    self.cv.itemconfigure(item, fill=new_col, outline=new_col)
                except:
                    pass

            idx[0] += 1
            self.after(150, tick)
        tick()

    def _update_datetime(self):
        if not self.winfo_exists():
            return
        now = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
        self.cv.itemconfigure(self._dt_text, text=now)
        self.after(1000, self._update_datetime)

    # ── Drag ───────────────────────────────────────────

    def _press(self, e):
        self._drag_x = e.x
        self._drag_y = e.y

    def _drag(self, e):
        dx = e.x - self._drag_x
        dy = e.y - self._drag_y
        self.geometry(f"+{self.winfo_x()+dx}+{self.winfo_y()+dy}")


# ═══════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════

if __name__ == "__main__":
    app = NekotinaApp()
    app.mainloop()
