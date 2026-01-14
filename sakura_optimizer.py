import argparse
import os
import platform
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

VERSION = "1.0.0"
# UPDATE_URL should point to the raw python file location
UPDATE_URL = "https://example.com/sakura_optimizer.py"

def check_for_updates(current_url):
    if not current_url or "example.com" in current_url:
        return
    try:
        print(f"{_c('96;1')}Checking for updates...{_c('0')}")
        with urllib.request.urlopen(current_url, timeout=5) as response:
            if response.status != 200:
                return
            new_code = response.read().decode('utf-8', errors='ignore')
            
            # Simple version extraction
            import re
            match = re.search(r'VERSION\s*=\s*["\']([^"\']+)["\']', new_code)
            if match:
                remote_version = match.group(1)
                if remote_version != VERSION:
                    print(f"{_c('92;1')}New version found: {remote_version} (Current: {VERSION}){_c('0')}")
                    print("Updating...")
                    
                    # Backup current
                    shutil.copy2(__file__, __file__ + ".bak")
                    
                    with open(__file__, "w", encoding="utf-8") as f:
                        f.write(new_code)
                        
                    print(f"{_c('92;1')}Update complete! Please restart the tool.{_c('0')}")
                    sys.exit(0)
                else:
                    print(f"You are on the latest version ({VERSION}).")
    except Exception as e:
        print(f"{_c('91;1')}Update check failed: {e}{_c('0')}")

def _supports_ansi():
    try:
        if os.name == "nt":
            return True
        return sys.stdout.isatty()
    except Exception:
        return False

def _c(code):
    if _supports_ansi():
        return f"\033[{code}m"
    return ""

def brand(art_level="premium"):
    if art_level == "premium":
        art = [
            " ________        __                     ",
            "/  _____/  ____ |  | __  ____  _____   ",
            "/   \\  ___ /  _ \\  |/ / /    \\ \\__  \\  ",
            "\\    \\_\\  (  <_> )    < |   |  \\/ __ \\_",
            " \\______  /\\____/|__|_ \\|___|  (____  /",
            "        \\/            \\/     \\/     \\/ ",
            "  Sakura Optimizer",
            "===========================================",
        ]
        return "\n".join([_c("95;1") + art[0] + _c("0")] + art[1:])
    bar = "-" * 10
    return f"{bar} Sakura Optimizer {bar}"

def log_path():
    try:
        return Path.home() / "sakura_optimizer.log"
    except Exception:
        return Path("sakura_optimizer.log")

def write_log(payload):
    try:
        p = log_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("a", encoding="utf-8") as f:
            f.write(payload + "\n")
    except Exception:
        pass

def detect_os():
    s = platform.system().lower()
    if "windows" in s:
        return "windows"
    if "darwin" in s or "mac" in s:
        return "macos"
    return "linux"


def _run(cmd, shell=False, timeout=20):
    try:
        p = subprocess.run(cmd, shell=shell, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, text=True)
        if p.returncode == 0:
            return p.stdout.strip()
        return ""
    except Exception:
        return ""

def _run_ps(ps_command, timeout=30):
    return _run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", ps_command], timeout=timeout)


def detect_gpu_vendors(os_name):
    vendors = set()
    if os_name == "windows":
        out = _run_ps("Get-CimInstance Win32_VideoController | Select-Object -ExpandProperty Name")
        if not out:
            out = _run(["wmic", "path", "win32_VideoController", "get", "name"])
        names = [x.strip().lower() for x in out.splitlines() if x.strip()]
    elif os_name == "linux":
        out = _run(["bash", "-lc", "lspci -nn | grep -i 'vga\\|3d\\|display'"])
        names = [x.strip().lower() for x in out.splitlines() if x.strip()]
    else:
        out = _run(["system_profiler", "SPDisplaysDataType"])
        names = [x.strip().lower() for x in out.splitlines() if x.strip()]
    joined = " ".join(names)
    if any(k in joined for k in ["nvidia", "geforce", "quadro"]):
        vendors.add("nvidia")
    if any(k in joined for k in ["amd", "radeon", "ati"]):
        vendors.add("amd")
    if any(k in joined for k in ["intel", "uhd", "iris", "hd graphics"]):
        vendors.add("intel")
    return sorted(vendors)


def detect_cpu_vendor(os_name):
    try:
        if os_name == "windows":
            out = _run(["wmic", "cpu", "get", "Name"])
            line = [x for x in out.splitlines() if x and "Name" not in x]
            n = " ".join(line).lower()
        elif os_name == "linux":
            out = _run(["bash", "-lc", "cat /proc/cpuinfo | grep -i 'model name' | head -n 1"])
            n = out.lower()
        else:
            out = _run(["sysctl", "-n", "machdep.cpu.brand_string"])
            n = out.lower()
        if "amd" in n or "ryzen" in n or "epyc" in n:
            return "amd"
        if "intel" in n or "core" in n or "xeon" in n:
            return "intel"
        if "apple" in n or "m1" in n or "m2" in n or "m3" in n:
            return "apple"
    except Exception:
        pass
    return "unknown"


def detect_ram(os_name):
    try:
        if os_name == "windows":
            out = _run(["wmic", "ComputerSystem", "get", "TotalPhysicalMemory"])
            lines = [x for x in out.splitlines() if x.strip() and "TotalPhysicalMemory" not in x]
            if lines:
                return int(lines[0].strip())
        elif os_name == "linux":
            out = _run(["bash", "-lc", "cat /proc/meminfo | grep MemTotal | awk '{print $2}'"])
            if out:
                return int(out.strip()) * 1024
        else:
            out = _run(["sysctl", "-n", "hw.memsize"])
            if out:
                return int(out.strip())
    except Exception:
        return 0
    return 0


def human_bytes(n):
    if n <= 0:
        return "unknown"
    units = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    f = float(n)
    while f >= 1024 and i < len(units) - 1:
        f /= 1024
        i += 1
    return f"{f:.1f} {units[i]}"


def clean_temp(os_name, apply):
    total_removed = 0
    paths = []
    if os_name == "windows":
        paths.append(Path(os.environ.get("TEMP", "")))
        paths.append(Path(os.environ.get("TMP", "")))
        paths.append(Path.home() / "AppData" / "Local" / "Temp")
    elif os_name == "linux":
        paths.append(Path("/tmp"))
        paths.append(Path.home() / ".cache")
    else:
        paths.append(Path("/tmp"))
        paths.append(Path.home() / "Library" / "Caches")
    for p in paths:
        if not p.exists():
            continue
        for item in p.iterdir():
            try:
                size = 0
                try:
                    if item.is_file():
                        size = item.stat().st_size
                except Exception:
                    size = 0
                total_removed += size
                if apply:
                    if item.is_dir():
                        shutil.rmtree(item, ignore_errors=True)
                    else:
                        try:
                            item.unlink(missing_ok=True)
                        except Exception:
                            pass
            except Exception:
                pass
    return total_removed


def flush_dns(os_name, apply):
    if not apply:
        return True
    if os_name == "windows":
        out = _run(["ipconfig", "/flushdns"])
        return bool(out)
    if os_name == "linux":
        cmds = [
            ["bash", "-lc", "systemd-resolve --flush-caches"],
            ["bash", "-lc", "resolvectl flush-caches"],
            ["bash", "-lc", "sudo -n service nscd restart"],
        ]
        for c in cmds:
            r = _run(c)
            if r:
                return True
        return False
    out = _run(["dscacheutil", "-flushcache"])
    out2 = _run(["killall", "-HUP", "mDNSResponder"])
    return bool(out or out2)


def set_power_plan_windows(apply):
    plans = _run(["powercfg", "/list"])
    if not plans:
        return False, ""
    target = ""
    for line in plans.splitlines():
        s = line.strip()
        if "High performance" in s or "Ultimate Performance" in s:
            gid = s[s.find("(") + 1 : s.find(")")]
            target = gid
            break
    if not target:
        for line in plans.splitlines():
            s = line.strip()
            if "Balanced" in s:
                gid = s[s.find("(") + 1 : s.find(")")]
                target = gid
                break
    if not target:
        return False, ""
    if apply:
        _run(["powercfg", "/setactive", target])
    return True, target


def list_startup_items(os_name):
    items = []
    if os_name == "windows":
        startup_folder = Path(os.environ.get("APPDATA", "")) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
        if startup_folder.exists():
            for f in startup_folder.iterdir():
                items.append(str(f))
        reg1 = _run(["reg", "query", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"])
        reg2 = _run(["reg", "query", r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run"])
        for out in [reg1, reg2]:
            for line in out.splitlines():
                if "REG_" in line:
                    items.append(line.strip())
    elif os_name == "linux":
        autostart = Path.home() / ".config" / "autostart"
        if autostart.exists():
            for f in autostart.glob("*.desktop"):
                items.append(str(f))
    else:
        agents = Path.home() / "Library" / "LaunchAgents"
        if agents.exists():
            for f in agents.glob("*.plist"):
                items.append(str(f))
    return items


def optimize_gpu_settings_preview(vendors, os_name):
    actions = []
    if "nvidia" in vendors:
        actions.append("Recommend NVIDIA Control Panel: Prefer maximum performance")
    if "amd" in vendors:
        actions.append("Recommend AMD Radeon: Enable Smart Access Memory if supported")
    if "intel" in vendors:
        actions.append("Recommend Intel Graphics: Set performance mode when available")
    if os_name == "windows":
        actions.append("Recommend Windows Graphics Settings per-app to High performance")
    return actions

def spinner(text, seconds=1.5):
    frames = ["|", "/", "-", "\\"]
    start = time.time()
    i = 0
    while time.time() - start < seconds:
        sys.stdout.write(f"\r{_c('96;1')}{text} {_c('0')}{frames[i % len(frames)]}")
        sys.stdout.flush()
        time.sleep(0.1)
        i += 1
    sys.stdout.write("\r" + " " * (len(text) + 4) + "\r")

def progress(task, steps=20, delay=0.03):
    width = max(10, min(40, shutil.get_terminal_size((80, 20)).columns // 4))
    sys.stdout.write(f"{_c('92;1')}{task}{_c('0')}\n")
    for i in range(steps + 1):
        filled = int((i / steps) * width)
        bar = "[" + "#" * filled + "-" * (width - filled) + "]"
        sys.stdout.write(f"\r{bar} {int((i/steps)*100)}%")
        sys.stdout.flush()
        time.sleep(delay)
    sys.stdout.write("\n")


def prefer_interface_metric(mode, apply):
    if detect_os() != "windows":
        return []
    preview = []
    if mode == "auto":
        eth = _run_ps("(Get-NetAdapter -Physical | Where-Object { $_.Status -eq 'Up' -and $_.Name -notmatch 'Wi-?Fi|WLAN' } | Select-Object -ExpandProperty Name) -join ','")
        preferred = "ethernet" if eth else "wifi"
    else:
        preferred = mode
    eth_metric = 10 if preferred == "ethernet" else 50
    wifi_metric = 10 if preferred == "wifi" else 50
    eth_list = _run_ps("(Get-NetAdapter -Physical | Where-Object { $_.Name -notmatch 'Wi-?Fi|WLAN' } | Select-Object -ExpandProperty Name) -join ','")
    wifi_list = _run_ps("(Get-NetAdapter -Name 'Wi-Fi','WLAN','WiFi' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name) -join ','")
    for a in [x for x in (eth_list.split(",") if eth_list else []) if x]:
        preview.append(f"Set metric {eth_metric} on {a}")
        if apply:
            _run_ps(f"Set-NetIPInterface -InterfaceAlias '{a}' -InterfaceMetric {eth_metric}", timeout=10)
    for a in [x for x in (wifi_list.split(",") if wifi_list else []) if x]:
        preview.append(f"Set metric {wifi_metric} on {a}")
        if apply:
            _run_ps(f"Set-NetIPInterface -InterfaceAlias '{a}' -InterfaceMetric {wifi_metric}", timeout=10)
    if apply:
        _run(["ipconfig", "/flushdns"])
        _run(["netsh", "interface", "ip", "delete", "arpcache"])
    return preview

def clear_recycle(apply):
    if detect_os() != "windows":
        return False
    if apply:
        _run_ps("Clear-RecycleBin -Force -ErrorAction SilentlyContinue", timeout=20)
    return True

def get_debloat_candidates(keep_list):
    if detect_os() != "windows":
        return []
    conservative = [
        "Microsoft.BingNews",
        "Microsoft.BingWeather",
        "Microsoft.GetHelp",
        "Microsoft.MicrosoftOfficeHub",
        "Microsoft.MicrosoftSolitaireCollection",
        "Microsoft.SkypeApp",
        "Microsoft.Todos",
        "Microsoft.Microsoft3DViewer",
        "Microsoft.MicrosoftStickyNotes",
        "Clipchamp.Clipchamp",
        "TikTok.TikTok",
        "Disney.ESPN",
        "SpotifyAB.SpotifyMusic",
        "Facebook.Facebook",
    ]
    keep_set = set(keep_list or [])
    q = "Get-AppxPackage -AllUsers | Select-Object Name, PackageFullName"
    out = _run_ps(q, timeout=30)
    names = []
    for line in out.splitlines():
        s = line.strip()
        if not s:
            continue
        parts = s.split()
        n = parts[0] if parts else s
        if any(k.lower() in n.lower() for k in keep_set):
            continue
        if n in conservative:
            names.append(n)
    return names

def debloat_execute(mode, apply, keep_list, remove_names):
    result = {"preview": [], "removed": []}
    if detect_os() != "windows":
        return result
    if mode == "auto":
        to_remove = get_debloat_candidates(keep_list)
    else:
        to_remove = []
        out = _run_ps("Get-AppxPackage -AllUsers | Select-Object Name, PackageFullName", timeout=30)
        for line in out.splitlines():
            s = line.strip()
            if not s:
                continue
            n = s.split()[0]
            if any(r.lower() in n.lower() for r in (remove_names or [])):
                if not any(k.lower() in n.lower() for k in (keep_list or [])):
                    to_remove.append(n)
    result["preview"] = to_remove
    if apply:
        for n in to_remove:
            pf = _run_ps(f"(Get-AppxPackage -AllUsers | Where-Object {{$_.Name -eq '{n}'}} | Select-Object -ExpandProperty PackageFullName) | Select-Object -First 1")
            if pf:
                _run_ps(f"Remove-AppxPackage -Package '{pf}' -AllUsers -ErrorAction SilentlyContinue", timeout=30)
                result["removed"].append(n)
    return result

def run_optimizations(os_name, apply):
    results = {}
    removed = clean_temp(os_name, apply)
    results["temp_cleanup_bytes"] = removed
    results["dns_flushed"] = flush_dns(os_name, apply)
    if os_name == "windows":
        ok, plan = set_power_plan_windows(apply)
        results["power_plan_set"] = ok
        results["power_plan_guid"] = plan
    return results


def main():
    parser = argparse.ArgumentParser(prog="sakura-optimizer")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--no-powerplan", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--category", choices=["all", "network", "system", "storage", "cpu", "gpu", "debloat"], default="all")
    parser.add_argument("--network", choices=["auto", "ethernet", "wifi"], default="auto")
    parser.add_argument("--debloat-mode", choices=["auto", "manual"], default="auto")
    parser.add_argument("--keep", nargs="*", default=["Microsoft", "Xbox", "Store", "Photos"])
    parser.add_argument("--remove", nargs="*", default=[])
    parser.add_argument("--art-level", choices=["basic", "premium"], default="premium")
    parser.add_argument("--update-url", default=UPDATE_URL, help="URL to check for updates")
    parser.add_argument("--no-update", action="store_true", help="Skip update check")
    args = parser.parse_args()

    print(brand(args.art_level))
    
    if not args.no_update and not args.json:
        check_for_updates(args.update_url)

    spinner("Loading Sakura environment", 1.0)
    os_name = detect_os()
    cpu = detect_cpu_vendor(os_name)
    gpus = detect_gpu_vendors(os_name)
    ram_b = detect_ram(os_name)
    print(f"{_c('93;1')}OS{_c('0')}: {os_name}")
    print(f"{_c('93;1')}CPU{_c('0')}: {cpu}")
    print(f"{_c('93;1')}GPU{_c('0')}: {', '.join(gpus) if gpus else 'unknown'}")
    print(f"{_c('93;1')}RAM{_c('0')}: {human_bytes(ram_b)}")

    actions = []
    if args.category in ("all", "system"):
        actions.extend(["Clean temporary files", "Flush DNS cache"])
        if os_name == "windows" and not args.no_powerplan:
            actions.append("Set power plan")
    if args.category in ("all", "network"):
        actions.append(f"Prefer interface metrics: {args.network}")
        actions.extend(["Flush DNS cache", "Clear ARP cache"])
    if args.category in ("all", "storage"):
        actions.append("Clear Recycle Bin")
    if args.category in ("all", "gpu"):
        actions.extend(optimize_gpu_settings_preview(gpus, os_name))
    if args.category in ("all", "debloat"):
        actions.append(f"Debloat: {args.debloat_mode}")

    print(f"{_c('94;1')}Planned actions{_c('0')}:")
    for a in actions:
        print(f"- {a}")

    res = {"system": {}, "network": {}, "storage": {}, "cpu": {}, "gpu": {}, "debloat": {}}
    if args.category in ("all", "network"):
        progress("Network optimization")
        net_preview = prefer_interface_metric(args.network, args.apply)
        for line in net_preview:
            print(f"- {line}")
    if args.category in ("all", "system", "cpu"):
        progress("System optimization")
        sysr = run_optimizations(os_name, args.apply)
        res["system"] = sysr
        startups = list_startup_items(os_name)
        print("Startup items preview:")
        for s in startups[:25]:
            print(f"- {s}")
    if args.category in ("all", "storage"):
        progress("Storage optimization")
        res["storage"]["recycle_cleared"] = clear_recycle(args.apply)
    if args.category in ("all", "debloat"):
        progress("Debloat")
        deb = debloat_execute(args.debloat_mode, args.apply, args.keep, args.remove)
        res["debloat"] = deb

    if args.json:
        import json
        out = {
            "os": os_name,
            "cpu": cpu,
            "gpu": gpus,
            "ram_bytes": ram_b,
            "actions": actions,
            "results": res,
            "apply": args.apply,
            "category": args.category,
            "network": args.network,
            "debloat_mode": args.debloat_mode,
            "keep": args.keep,
            "remove_names": args.remove,
            "timestamp": int(time.time()),
        }
        print(json.dumps(out, indent=2))
        try:
            write_log(json.dumps(out, separators=(",", ":"), ensure_ascii=False))
        except Exception:
            pass
    else:
        print("Results:")
        if "temp_cleanup_bytes" in res.get("system", {}):
            print(f"- Temp cleanup: {human_bytes(res['system'].get('temp_cleanup_bytes', 0))}{' removed' if args.apply else ' candidate'}")
        dns = "yes" if res.get("system", {}).get("dns_flushed") else "no"
        print(f"- DNS flushed: {dns}")
        if os_name == "windows" and not args.no_powerplan and "power_plan_set" in res.get("system", {}):
            print(f"- Power plan set: {'yes' if res['system'].get('power_plan_set') else 'no'} {res['system'].get('power_plan_guid','')}")
        if args.category in ("all", "storage"):
            print(f"- Recycle bin cleared: {'yes' if res.get('storage',{}).get('recycle_cleared') else 'no'}")
        if args.category in ("all", "debloat"):
            print("- Debloat preview:")
            prev = res.get("debloat", {}).get("preview", [])
            if prev:
                for n in prev[:25]:
                    print(f"  * {n}")
            else:
                print("  * (none)")
            if args.apply:
                rem = res.get("debloat", {}).get("removed", [])
                print("- Debloat removed:")
                if rem:
                    for n in rem[:25]:
                        print(f"  * {n}")
                else:
                    print("  * (none)")
        print(f"Mode: {'apply' if args.apply else 'dry-run'}")
        try:
            payload = {
                "os": os_name,
                "cpu": cpu,
                "gpu": gpus,
                "ram_bytes": ram_b,
                "results": res,
                "apply": args.apply,
                "timestamp": int(time.time()),
            }
            import json
            write_log(json.dumps(payload, separators=(",", ":"), ensure_ascii=False))
        except Exception:
            pass


if __name__ == "__main__":
    main()
