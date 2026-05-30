#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════╗
║   NekotinaCat_Framework — Build Script (PyInstaller)            ║
║   Gera executável único com ícone (gato + pentagrama)           ║
║                                                                  ║
║   Uso:                                                           ║
║     python build_nekotinacat.py                                  ║
║     python build_nekotinacat.py --clean-only                     ║
║                                                                  ║
║   Pré-requisitos:                                                ║
║     pip install pyinstaller psutil Pillow                        ║
╚══════════════════════════════════════════════════════════════════╝
"""

import subprocess, sys, os, shutil, math
from pathlib import Path

# ── Config ──────────────────────────────────────────────
APP_NAME    = "NekotinaCat_Framework"
MAIN_SCRIPT = "nekotinacat_installer.py"  # entry point = installer
TOOL_SCRIPT = "nekotinacat.py"            # bundled junto
VERSION     = "1.0.0"
CODENAME    = "CRIMSON SENTINEL"
ICON_PNG    = "nekotinacat_icon.png"


def check_pyinstaller():
    try:
        import PyInstaller
        print(f"[+] PyInstaller {PyInstaller.__version__} disponível.")
        return True
    except ImportError:
        print("[*] Instalando PyInstaller…")
        r = subprocess.run([sys.executable,"-m","pip","install","pyinstaller"],
                           capture_output=True, text=True)
        if r.returncode == 0:
            print("[+] PyInstaller instalado.")
            return True
        print(f"[-] Falha: {r.stderr}")
        return False


def generate_icon():
    """
    Gera ícone PNG com gato de olhos vermelhos + pentagrama.
    Salva como nekotinacat_icon.png e converte para .ico (Windows).
    """
    try:
        from PIL import Image, ImageDraw, ImageFont
    except ImportError:
        print("[*] Instalando Pillow…")
        subprocess.run([sys.executable,"-m","pip","install","Pillow"],
                       capture_output=True)
        try:
            from PIL import Image, ImageDraw
        except ImportError:
            print("[!] Pillow indisponível — build sem ícone.")
            return None

    print("[*] Gerando ícone NekotinaCat (256×256)…")
    SIZE = 256
    img  = Image.new("RGBA", (SIZE, SIZE), (6, 4, 4, 255))
    d    = ImageDraw.Draw(img)

    BG    = (6, 4, 4, 255)
    RED1  = (204, 26, 26)
    RED2  = (255, 51, 51)
    RED3  = (255, 102, 102)
    DARK  = (17, 8, 8)
    DBORD = (139, 0, 0)

    cx, cy = SIZE//2, SIZE//2 - 15

    # Cabeça do gato
    d.ellipse([cx-62, cy-90, cx+62, cy+10], fill=DARK, outline=RED1, width=2)

    # Orelhas
    d.polygon([cx-62,cy-55, cx-88,cy-115, cx-28,cy-68], fill=(26,8,8), outline=RED1)
    d.polygon([cx+62,cy-55, cx+88,cy-115, cx+28,cy-68], fill=(26,8,8), outline=RED1)

    # Olhos VERMELHOS
    for ex in [cx-24, cx+24]:
        d.ellipse([ex-15, cy-60, ex+15, cy-30], fill=(34,0,0), outline=RED2, width=2)
        d.ellipse([ex-11, cy-57, ex+11, cy-33], fill=RED1)
        d.ellipse([ex-5,  cy-58, ex+5,  cy-32], fill=(0,0,0))
        d.ellipse([ex-9,  cy-56, ex-4,  cy-50], fill=RED3)

    # Nariz
    d.polygon([cx-5,cy-22, cx+5,cy-22, cx,cy-14], fill=DBORD)

    # Bigodes
    for dy in [-4, 0, 4]:
        d.line([cx-52, cy-22+dy, cx-10, cy-22+dy], fill=DBORD, width=1)
        d.line([cx+10, cy-22+dy, cx+52, cy-22+dy], fill=DBORD, width=1)

    # Corpo
    d.ellipse([cx-58, cy+5, cx+58, cy+75], fill=DARK, outline=RED1, width=1)

    # Pentagrama abaixo
    pr  = 40
    pcx = cx
    pcy = cy + 120
    d.ellipse([pcx-pr-5, pcy-pr-5, pcx+pr+5, pcy+pr+5],
              outline=RED1, width=1)
    pts = [(pcx + pr * math.cos(math.radians(-90 + i*144)),
            pcy + pr * math.sin(math.radians(-90 + i*144))) for i in range(5)]
    order = [0,2,4,1,3,0]
    for i in range(len(order)-1):
        x1,y1 = pts[order[i]]
        x2,y2 = pts[order[i+1]]
        d.line([x1,y1,x2,y2], fill=RED1, width=1)
    for px2,py2 in pts:
        d.ellipse([px2-3,py2-3,px2+3,py2+3], fill=RED2)

    # Borda vermelha circular externa
    d.ellipse([4,4,SIZE-4,SIZE-4], outline=RED1, width=2)

    img.save(ICON_PNG, format="PNG")
    print(f"[+] Ícone PNG: {ICON_PNG}")

    import platform
    if platform.system() == "Windows":
        ico_path = "nekotinacat.ico"
        img.save(ico_path, format="ICO",
                 sizes=[(256,256),(128,128),(64,64),(32,32),(16,16)])
        print(f"[+] Ícone ICO: {ico_path}")
        return ico_path
    else:
        return ICON_PNG


def check_scripts():
    ok = True
    for f in [MAIN_SCRIPT, TOOL_SCRIPT]:
        if Path(f).exists():
            print(f"[+] Encontrado: {f}")
        else:
            print(f"[-] FALTANDO: {f}")
            ok = False
    return ok


def build():
    print()
    print("="*65)
    print(f"  {APP_NAME} v{VERSION} — {CODENAME}")
    print("  Build Script · PyInstaller")
    print("="*65)
    print()

    if not check_pyinstaller():
        sys.exit(1)

    if not check_scripts():
        print("\n[-] Coloque nekotinacat.py e nekotinacat_installer.py")
        print("    no mesmo diretório que este script.")
        sys.exit(1)

    icon_path = generate_icon()

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",
        "--windowed",
        "--name",     APP_NAME,
        "--clean",
        "--noconfirm",
    ]

    if icon_path and Path(icon_path).exists():
        cmd += ["--icon", icon_path]

    # Bundle nekotinacat.py junto
    cmd += ["--add-data", f"{TOOL_SCRIPT}{os.pathsep}."]

    # Hidden imports
    for hi in [
        "tkinter","tkinter.font","tkinter.messagebox","tkinter.ttk",
        "psutil","psutil._pslinux","psutil._psposix","psutil._pswindows",
        "pathlib","hashlib","threading","subprocess","shutil",
        "json","re","math","random","datetime","socket","platform",
        "ctypes","struct",
    ]:
        cmd += ["--hidden-import", hi]

    cmd += ["--collect-submodules","psutil","--collect-data","psutil"]
    cmd.append(MAIN_SCRIPT)

    print(f"\n[>] Iniciando PyInstaller…")
    print(f"    Entry:  {MAIN_SCRIPT}")
    print(f"    Bundle: {TOOL_SCRIPT}")
    print(f"    Output: dist/{APP_NAME}")
    print()

    result = subprocess.run(cmd, text=True)

    if result.returncode == 0:
        print()
        print("="*65)
        print("  BUILD CONCLUÍDO COM SUCESSO!")
        print("="*65)
        import platform as plt
        ext  = ".exe" if plt.system() == "Windows" else ""
        exe  = Path("dist") / f"{APP_NAME}{ext}"
        if exe.exists():
            size = exe.stat().st_size / 1024 / 1024
            print(f"\n  Executável : {exe}")
            print(f"  Tamanho    : {size:.1f} MB")
            print(f"  Plataforma : {plt.system()} {plt.machine()}")
        print()
        print("  Para instalar:")
        print(f"    ./{APP_NAME}        (Linux/macOS)")
        print(f"    .\\{APP_NAME}.exe   (Windows)")
        print()
    else:
        print("\n[-] BUILD FALHOU.")
        print("    Verifique os erros acima.")
        print()
        print("    Dicas:")
        print("      pip install psutil Pillow pyinstaller")
        print("      sudo apt install python3-tk  (Linux)")
        sys.exit(1)


def clean():
    for item in [f"{APP_NAME}.spec", "build"]:
        p = Path(item)
        if p.exists():
            if p.is_dir(): shutil.rmtree(p)
            else: p.unlink()
            print(f"[*] Removido: {item}")


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description=f"Build — {APP_NAME} v{VERSION}")
    ap.add_argument("--clean-only", action="store_true",
                    help="Apenas limpa artifacts")
    args = ap.parse_args()

    if args.clean_only:
        clean()
    else:
        build()
        clean()
