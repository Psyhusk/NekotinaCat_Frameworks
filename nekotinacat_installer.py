#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════╗
║   NekotinaCat_Framework v1.0.0 — CRIMSON SENTINEL               ║
║   Installer · Frameless · Transparent · Red Glow                ║
╚══════════════════════════════════════════════════════════════════╝
"""

import os, sys, subprocess, threading, shutil, time, math
from pathlib import Path

try:
    import tkinter as tk
except ImportError:
    print("[!] tkinter não encontrado. sudo apt install python3-tk")
    sys.exit(1)

# ── Paleta ──────────────────────────────────────────────
BG      = "#060404"
BG2     = "#0a0606"
BG3     = "#110808"
GLOW1   = "#cc1a1a"
GLOW2   = "#ff3333"
GLOW3   = "#ff6666"
BORDER  = "#8b0000"
TEXT    = "#f0dede"
MUTED   = "#7a5a5a"
SUCCESS = "#22c55e"
DANGER  = "#ef4444"
WARNING = "#f59e0b"
MONO    = "#ff8888"

VERSION  = "1.0.0"
NAME     = "NekotinaCat_Framework"
CODENAME = "CRIMSON SENTINEL"

INSTALL_DIR  = Path.home() / ".local" / "share" / "nekotinacat"
BIN_DIR      = Path.home() / ".local" / "bin"
DESKTOP_FILE = Path.home() / ".local" / "share" / "applications" / "nekotinacat.desktop"
MAIN_SCRIPT  = "nekotinacat.py"


def run_cmd(cmd, timeout=60):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.returncode == 0, (r.stdout + r.stderr).strip()
    except Exception as e:
        return False, str(e)


def do_install(log_cb, prog_cb, done_cb):
    errors = []

    def step(pct, msg, fn=None):
        log_cb(f"[>>] {msg}")
        if fn:
            ok, out = fn()
            if not ok:
                log_cb(f"[!!] {out[:120] if out else 'Falhou'}")
                errors.append(msg)
            elif out:
                log_cb(f"     {out[:80]}")
        prog_cb(pct, msg)
        time.sleep(0.35)

    step(10, "Verificando Python 3.8+",
         lambda: (sys.version_info >= (3,8), sys.version))

    step(22, "Instalando psutil",
         lambda: run_cmd(f"{sys.executable} -m pip install psutil --quiet"))

    step(35, "Instalando customtkinter (opcional)",
         lambda: run_cmd(f"{sys.executable} -m pip install customtkinter --quiet"))

    step(48, "Instalando Pillow (ícone)",
         lambda: run_cmd(f"{sys.executable} -m pip install Pillow --quiet"))

    # Copiar arquivos
    log_cb(f"[>>] Criando diretório de instalação…")
    INSTALL_DIR.mkdir(parents=True, exist_ok=True)
    src = Path(__file__).parent / MAIN_SCRIPT
    if src.exists():
        shutil.copy2(src, INSTALL_DIR / MAIN_SCRIPT)
        log_cb(f"     {src} → {INSTALL_DIR / MAIN_SCRIPT}")
    else:
        log_cb(f"[!!] {MAIN_SCRIPT} não encontrado!")
        errors.append("Arquivo principal ausente")
    prog_cb(60, "Arquivos copiados")
    time.sleep(0.35)

    # Launcher
    log_cb("[>>] Criando launcher ~/.local/bin/nekotinacat…")
    BIN_DIR.mkdir(parents=True, exist_ok=True)
    launcher = BIN_DIR / "nekotinacat"
    launcher.write_text(
        f"#!/bin/bash\nexec {sys.executable} {INSTALL_DIR / MAIN_SCRIPT} \"$@\"\n"
    )
    launcher.chmod(0o755)
    log_cb(f"     Launcher: {launcher}")
    prog_cb(72, "Launcher criado")
    time.sleep(0.35)

    # .desktop entry
    log_cb("[>>] Criando entrada .desktop…")
    DESKTOP_FILE.parent.mkdir(parents=True, exist_ok=True)
    DESKTOP_FILE.write_text(f"""[Desktop Entry]
Name=NekotinaCat Framework {VERSION}
Comment=Defensive Security Monitor — {CODENAME}
Exec={sys.executable} {INSTALL_DIR / MAIN_SCRIPT}
Icon=security-high
Terminal=false
Type=Application
Categories=System;Security;Utility;
Keywords=security;monitor;vulnerability;malware;defensive;
StartupNotify=true
""")
    log_cb(f"     .desktop: {DESKTOP_FILE}")
    prog_cb(83, ".desktop criado")
    time.sleep(0.35)

    # Ferramentas do sistema
    log_cb("[>>] Verificando ferramentas recomendadas…")
    tools = {
        "ss":         "iproute2",
        "chkrootkit": "chkrootkit",
        "rkhunter":   "rkhunter",
        "lsblk":      "util-linux",
        "smartctl":   "smartmontools",
        "ufw":        "ufw",
        "sysctl":     "procps",
    }
    missing = []
    for t, pkg in tools.items():
        ok, _ = run_cmd(f"which {t}")
        if not ok:
            missing.append(pkg)
    if missing:
        log_cb(f"     [!] Pacotes recomendados ausentes:")
        log_cb(f"     sudo apt install {' '.join(missing)}")
    else:
        log_cb("     Todas as ferramentas detectadas.")
    prog_cb(95, "Verificação concluída")
    time.sleep(0.35)

    prog_cb(100, "Instalação concluída!")
    time.sleep(0.3)
    done_cb(errors)


# ═══════════════════════════════════════════════════════
#  JANELA DO INSTALLER
# ═══════════════════════════════════════════════════════

class NekotinaInstaller(tk.Tk):

    W, H = 820, 600

    def __init__(self):
        super().__init__()
        self.configure(bg=BG)
        self.overrideredirect(True)
        try:
            self.attributes("-alpha", 0.97)
        except:
            pass
        self._center()
        self.geometry(f"{self.W}x{self.H}")
        self._dx = self._dy = 0
        self._penta_items = []
        self._build()
        self._animate_glow()
        self._animate_penta()

    def _center(self):
        x = (self.winfo_screenwidth()  - self.W) // 2
        y = (self.winfo_screenheight() - self.H) // 2
        self.geometry(f"{self.W}x{self.H}+{x}+{y}")

    def _build(self):
        self.cv = tk.Canvas(self, width=self.W, height=self.H,
                             bg=BG, highlightthickness=0)
        self.cv.pack(fill="both", expand=True)

        # Bordas glow
        self._border = self.cv.create_rectangle(1,1,self.W-1,self.H-1,
                                                  outline=GLOW1, width=2)
        self.cv.create_rectangle(3,3,self.W-3,self.H-3,
                                  outline=BORDER+"66", width=1)

        self.cv.bind("<ButtonPress-1>",  self._press)
        self.cv.bind("<B1-Motion>",      self._drag)

        self._draw_cat_side()
        self._draw_header()
        self._draw_content()

    def _draw_cat_side(self):
        c = self.cv
        px = self.W - 240

        c.create_rectangle(px, 2, self.W-2, self.H-2,
                            fill="#070303", outline=BORDER, width=1)
        c.create_line(px, 2, px, self.H-2, fill=GLOW1, width=1)

        cx, cy = px + 118, 185

        # ── Gato ──────────────────────────────────────
        # Cabeça
        c.create_oval(cx-58, cy-135, cx+58, cy-20,
                      fill="#110808", outline=GLOW1, width=1)
        # Orelhas
        c.create_polygon(cx-58, cy-90, cx-80, cy-165, cx-28, cy-108,
                         fill="#1a0808", outline=GLOW1, width=1)
        c.create_polygon(cx+58, cy-90, cx+80, cy-165, cx+28, cy-108,
                         fill="#1a0808", outline=GLOW1, width=1)
        c.create_polygon(cx-55, cy-92, cx-70, cy-150, cx-30, cy-110,
                         fill=BORDER+"55")
        c.create_polygon(cx+55, cy-92, cx+70, cy-150, cx+30, cy-110,
                         fill=BORDER+"55")

        # OLHOS VERMELHOS
        for ex in [cx-23, cx+23]:
            c.create_oval(ex-17, cy-92, ex+17, cy-58,
                          fill="#220000", outline=GLOW2, width=2)
            c.create_oval(ex-12, cy-89, ex+12, cy-61,
                          fill=GLOW1)
            c.create_oval(ex-5,  cy-90, ex+5,  cy-60,
                          fill="#000")
            c.create_oval(ex-8,  cy-87, ex-3,  cy-80,
                          fill=GLOW3)

        # Nariz
        c.create_polygon(cx-5, cy-58, cx+5, cy-58, cx, cy-50,
                         fill=BORDER)

        # Bigodes
        for dy in [-5, 0, 5]:
            c.create_line(cx-50, cy-54+dy, cx-8, cy-54+dy, fill=BORDER+"77", width=1)
            c.create_line(cx+8,  cy-54+dy, cx+50, cy-54+dy, fill=BORDER+"77", width=1)

        # Boca
        c.create_arc(cx-13, cy-50, cx-1, cy-40, start=180, extent=180,
                     outline=GLOW1, style="arc", width=1)
        c.create_arc(cx+1,  cy-50, cx+13, cy-40, start=180, extent=180,
                     outline=GLOW1, style="arc", width=1)

        # Corpo
        c.create_oval(cx-68, cy-35, cx+68, cy+80,
                      fill="#0d0505", outline=GLOW1, width=1)

        # Patas
        for px2 in [cx-48, cx+18]:
            c.create_oval(px2, cy+60, px2+32, cy+95,
                          fill="#0d0505", outline=GLOW1+"66", width=1)
            for ddx in [0, 10, 20]:
                c.create_oval(px2+ddx, cy+78, px2+ddx+9, cy+98,
                              fill="#100606", outline=BORDER+"44")

        # Cauda
        c.create_arc(cx+20, cy+20, cx+150, cy+100, start=60, extent=200,
                     outline=GLOW1, style="arc", width=2)

        # ── PENTAGRAMA ────────────────────────────────
        self._penta_cx = cx
        self._penta_cy = cy + 175
        self._penta_r  = 55
        self._draw_penta()

        # Labels
        c.create_text(cx, self._penta_cy + 72, text="NEKOTINACAT",
                      font=("Courier New",9,"bold"), fill=GLOW1)
        c.create_text(cx, self._penta_cy + 86, text="CRIMSON SENTINEL",
                      font=("Courier New",7), fill=MUTED)

        self._status_side = c.create_text(cx, self.H - 30,
            text="INSTALLER READY", font=("Courier New",8,"bold"), fill=MUTED)

    def _draw_penta(self):
        c = self.cv
        for item in self._penta_items:
            c.delete(item)
        self._penta_items.clear()

        cx, cy, r = self._penta_cx, self._penta_cy, self._penta_r

        # Círculos
        for offset, col in [(0, GLOW1), (8, BORDER+"55")]:
            it = c.create_oval(cx-r-offset, cy-r-offset, cx+r+offset, cy+r+offset,
                               outline=col, width=1)
            self._penta_items.append(it)

        # Pontos
        pts = [(cx + r*math.cos(math.radians(-90 + i*144)),
                cy + r*math.sin(math.radians(-90 + i*144))) for i in range(5)]

        # Linhas
        order = [0,2,4,1,3,0]
        for i in range(len(order)-1):
            x1,y1 = pts[order[i]]
            x2,y2 = pts[order[i+1]]
            it = c.create_line(x1,y1,x2,y2, fill=GLOW1, width=1)
            self._penta_items.append(it)

        # Vértices
        for px2,py2 in pts:
            it = c.create_oval(px2-3,py2-3,px2+3,py2+3, fill=GLOW2, outline="")
            self._penta_items.append(it)

        # Centro
        it = c.create_text(cx, cy, text="✦", font=("Courier New",11,"bold"), fill=GLOW2)
        self._penta_items.append(it)

    def _draw_header(self):
        c = self.cv
        c.create_rectangle(0, 0, self.W-238, 50, fill=BG2, outline="")
        c.create_line(0, 50, self.W-238, 50, fill=GLOW1, width=1)

        c.create_text(18, 25, text="◈", font=("Courier New",16,"bold"),
                      fill=GLOW2, anchor="w")
        c.create_text(46, 15, text=f"{NAME} — Installer",
                      font=("Courier New",13,"bold"), fill=TEXT, anchor="w")
        c.create_text(46, 33, text=f"v{VERSION}  ·  {CODENAME}",
                      font=("Courier New",8), fill=MUTED, anchor="w")

        # Fechar
        close_btn = c.create_text(self.W-252, 25, text="✕",
                                   font=("Courier New",14,"bold"), fill=MUTED)
        c.tag_bind(close_btn,"<Enter>",  lambda e: c.itemconfigure(close_btn, fill=GLOW1))
        c.tag_bind(close_btn,"<Leave>",  lambda e: c.itemconfigure(close_btn, fill=MUTED))
        c.tag_bind(close_btn,"<Button-1>", lambda e: self.destroy())

    def _draw_content(self):
        c = self.cv
        c.create_line(0, 82, self.W-238, 82, fill=BORDER+"55", width=1)

        # Destino
        c.create_text(20, 65, text="Destino:", font=("Courier New",9),
                      fill=MUTED, anchor="w")
        c.create_text(80, 65, text=str(INSTALL_DIR),
                      font=("Courier New",9,"bold"), fill=TEXT, anchor="w")

        # Componentes
        c.create_text(20, 100, text="Componentes do NekotinaCat_Framework:",
                      font=("Courier New",10,"bold"), fill=GLOW2, anchor="w")

        items = [
            ("◈", "Dashboard em tempo real — CPU, RAM, Rede, uptime"),
            ("⚡", "Vulnerability Scanner — CVEs, Kernel, SSH, firewall"),
            ("🦠", "Malware & Rootkit Scanner — processos, autorun, /dev"),
            ("🌐", "Network Analyzer — interfaces, conexões, promíscuo"),
            ("🔧", "System Inspector — BIOS/UEFI, distro, sysctl, discos"),
            ("📋", "Log Center — histórico completo de eventos"),
        ]
        for i, (icon, desc) in enumerate(items):
            y = 126 + i * 26
            c.create_text(22, y, text=icon, font=("Courier New",10), fill=GLOW1, anchor="w")
            c.create_text(45, y, text=desc, font=("Courier New",9),  fill=MUTED,  anchor="w")

        # Separador
        c.create_line(0, 295, self.W-238, 295, fill=BORDER+"66", width=1)
        c.create_text(20, 308, text="Progresso:", font=("Courier New",9),
                      fill=MUTED, anchor="w")

        # Barra
        c.create_rectangle(20, 320, 555, 338, fill="#1a0808", outline=BORDER, width=1)
        self._prog_bar = c.create_rectangle(20, 320, 20, 338, fill=GLOW1, outline="")
        self._prog_pct = c.create_text(290, 329, text="0%",
                                        font=("Courier New",9,"bold"), fill=TEXT)

        self._status_text = c.create_text(20, 350, text="Aguardando…",
                                           font=("Courier New",9), fill=MUTED, anchor="w")

        # Log box
        self._log_frame = tk.Frame(self, bg=BG3)
        self._log_frame.place(x=18, y=368, width=548, height=140)
        self._log_txt = tk.Text(self._log_frame,
                                 bg="#060202", fg=MONO,
                                 font=("Courier New",9), relief="flat", bd=0,
                                 state="disabled", wrap="word")
        sb = tk.Scrollbar(self._log_frame, orient="vertical",
                           command=self._log_txt.yview,
                           bg=BG, troughcolor=BG, activebackground=GLOW1,
                           relief="flat", bd=0)
        self._log_txt.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self._log_txt.pack(fill="both", expand=True)
        c.create_rectangle(17, 367, 567, 509, outline=BORDER, width=1)

        # Botões
        self._btn_install = tk.Button(self,
            text="▶  INSTALAR NEKOTINACAT",
            font=("Courier New",12,"bold"),
            bg=GLOW1, fg="#fff",
            activebackground=BORDER, activeforeground="#fff",
            relief="flat", bd=0, cursor="hand2",
            command=self._start_install)
        self._btn_install.place(x=18, y=520, width=270, height=40)

        self._btn_launch = tk.Button(self,
            text="🚀  LANÇAR FRAMEWORK",
            font=("Courier New",11,"bold"),
            bg="#1a1a1a", fg=MUTED,
            activebackground=BG3, activeforeground=TEXT,
            relief="flat", bd=0, cursor="arrow",
            state="disabled",
            command=self._launch)
        self._btn_launch.place(x=300, y=520, width=268, height=40)

    # ── Animações ──────────────────────────────────────

    def _animate_glow(self):
        colors = ["#cc1a1a","#d42020","#dc2626","#e03030","#dc2626",
                  "#cc1a1a","#b01010","#980d0d","#b01010","#cc1a1a"]
        idx = [0]
        def tick():
            if not self.winfo_exists(): return
            self.cv.itemconfigure(self._border, outline=colors[idx[0]%len(colors)])
            idx[0] += 1
            self.after(110, tick)
        tick()

    def _animate_penta(self):
        reds = ["#8b0000","#a01010","#cc1a1a","#dc2626","#ff3333",
                "#dc2626","#cc1a1a","#a01010","#8b0000"]
        idx = [0]
        def tick():
            if not self.winfo_exists(): return
            col = reds[idx[0] % len(reds)]
            for item in self._penta_items:
                try:
                    self.cv.itemconfigure(item, fill=col, outline=col)
                except:
                    pass
            idx[0] += 1
            self.after(140, tick)
        tick()

    # ── Drag ───────────────────────────────────────────

    def _press(self, e):
        self._dx = e.x
        self._dy = e.y

    def _drag(self, e):
        self.geometry(f"+{self.winfo_x()+e.x-self._dx}+{self.winfo_y()+e.y-self._dy}")

    # ── Log ────────────────────────────────────────────

    def _log(self, msg):
        def _do():
            self._log_txt.configure(state="normal")
            self._log_txt.insert("end", msg + "\n")
            self._log_txt.see("end")
            self._log_txt.configure(state="disabled")
        try:
            self._log_txt.after(0, _do)
        except:
            pass

    def _prog(self, pct, msg=""):
        def _do():
            w = int((pct/100) * 535)
            self.cv.coords(self._prog_bar, 20, 320, 20+w, 338)
            self.cv.itemconfigure(self._prog_pct, text=f"{pct}%")
            if msg:
                self.cv.itemconfigure(self._status_text, text=msg[:60])
        try:
            self.cv.after(0, _do)
        except:
            pass

    def _done(self, errors):
        def _do():
            if errors:
                self.cv.itemconfigure(self._status_text,
                    text=f"⚠ Concluído com {len(errors)} aviso(s)")
                self.cv.itemconfigure(self._status_text, fill=WARNING)
                self.cv.itemconfigure(self._status_side, text="INSTALADO ⚠", fill=WARNING)
            else:
                self.cv.itemconfigure(self._status_text,
                    text="✓ Instalação concluída com sucesso!")
                self.cv.itemconfigure(self._status_text, fill=SUCCESS)
                self.cv.itemconfigure(self._status_side, text="INSTALADO ✓", fill=SUCCESS)
            self._btn_install.configure(state="disabled", bg="#1a0808")
            self._btn_launch.configure(state="normal", bg=GLOW1, fg="#fff",
                                        activebackground=BORDER, cursor="hand2")
        try:
            self.cv.after(0, _do)
        except:
            pass

    def _start_install(self):
        self._btn_install.configure(state="disabled", text="Instalando…")
        self._log(f"◈ {NAME} — Iniciando instalação…")
        self._log("─" * 50)
        threading.Thread(
            target=do_install,
            args=(self._log, self._prog, self._done),
            daemon=True
        ).start()

    def _launch(self):
        target = INSTALL_DIR / MAIN_SCRIPT
        if target.exists():
            import subprocess as sp
            sp.Popen([sys.executable, str(target)])
            self.after(900, self.destroy)
        else:
            self._log(f"[!] Não encontrado: {target}")


if __name__ == "__main__":
    app = NekotinaInstaller()
    app.mainloop()
