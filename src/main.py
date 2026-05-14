# imports
import ctypes
from email.mime import base
import json
import os
import re
import socket
import shutil
import time
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
from ascii_banner import ASCII_BANNER
from tlds import TLD_LIST
import tlds
from tqdm import tqdm
import subprocess
import sys
import threading


# couleurs
GREEN  = "\033[92m"
RED    = "\033[91m"
WHITE  = "\033[97m"
RESET  = "\033[0m"

WHOIS_FREE_MARKERS = (
    "no match",
    "not found",
    "no data found",
    "domain not found",
    "no entries found",
    "status: free",
    "available",
)

WHOIS_TAKEN_MARKERS = (
    "domain name:",
    "registrar:",
    "creation date:",
)


# affichage du terminal
def enable_ansi_on_windows() -> None:
    if os.name != "nt":
        return
    try:
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)
    except Exception:
        pass


def green(text: str) -> str:
    return f"{GREEN}{text}{RESET}"


def format_result(domain: str, status: str) -> str:
    if status == "TAKEN":
        return f"{RED}[TAKEN]{RESET}     {WHITE}{domain}{RESET}"
    return f"{GREEN}[FREE]{RESET}      {WHITE}{domain}{RESET}"


# vérification de la disponibilité du domaine
def normalize_sld(raw: str) -> str:
    label = raw.strip().lower()
    label = re.sub(r"[^a-z0-9-]", "-", label)
    label = re.sub(r"-+", "-", label).strip("-")
    return (label or "example")[:63]


def domain_resolves(domain: str) -> bool:
    try:
        socket.getaddrinfo(domain, None)
        return True
    except socket.gaierror:
        return False


def domain_is_reachable(domain: str, timeout: float = 1.5) -> bool:
    for port in (80, 443):
        try:
            with socket.create_connection((domain, port), timeout=timeout):
                return True
        except OSError:
            continue
    return False


def whois_query(server: str, query: str, timeout: float = 3.0) -> str:
    with socket.create_connection((server, 43), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall((query + "\r\n").encode("utf-8", errors="ignore"))
        chunks = []
        while chunk := sock.recv(4096):
            chunks.append(chunk)
    return b"".join(chunks).decode("utf-8", errors="ignore")


@lru_cache(maxsize=2048)
def whois_server_for_tld(tld: str) -> str | None:
    try:
        response = whois_query("whois.iana.org", tld)
    except OSError:
        return None

    for line in response.splitlines():
        if line.lower().startswith("whois:"):
            _, _, server = line.partition(":")
            return server.strip()

    return None


def check_whois(domain: str) -> str | None:
    tld = domain.rsplit(".", 1)[-1]
    server = whois_server_for_tld(tld)

    if not server:
        return None

    try:
        response = whois_query(server, domain)
    except OSError:
        return None

    text = response.lower()

    if any(marker in text for marker in WHOIS_FREE_MARKERS):
        return "FREE"

    if any(marker in text for marker in WHOIS_TAKEN_MARKERS):
        return "TAKEN"

    return None


@lru_cache(maxsize=1)
def _load_rdap_bootstrap() -> dict[str, str]:
    url = "https://data.iana.org/rdap/dns.json"
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            bootstrap = json.loads(resp.read())
        result = {}
        for tlds, servers in bootstrap.get("services", []):
            if servers:
                for tld in tlds:
                    result[tld] = servers[0]
        return result
    except Exception:
        return {}


def rdap_server_for_tld(tld: str) -> str | None:
    return _load_rdap_bootstrap().get(tld)


def _rdap_fetch(url: str, timeout: float) -> str | None:
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
            if data.get("ldhName") or data.get("handle"):
                return "TAKEN"
        return None
    except urllib.error.HTTPError as e:
        if e.code in (404, 400):
            return "FREE"
        return None
    except Exception:
        return None


def check_rdap_official(domain: str, timeout: float = 3.0) -> str | None:
    tld = domain.rsplit(".", 1)[-1]
    server = rdap_server_for_tld(tld)
    if not server:
        return None
    return _rdap_fetch(server.rstrip("/") + "/domain/" + domain, timeout)


def check_rdap_fallback(domain: str, timeout: float = 3.0) -> str | None:
    for base in ("https://rdap.org", "https://rdap.arin.net/registry"):
        result = _rdap_fetch(f"{base}/domain/{domain}", timeout)
        if result is not None:
            return result
    return None


def check_domain(base: str, tld: str) -> tuple[str, str]:
    domain = f"{base}.{tld}"

    # niveau 1
    if domain_resolves(domain) and domain_is_reachable(domain):
        return domain, "TAKEN"

    # niveau 2
    result = check_rdap_official(domain)
    if result is not None:
        return domain, result

    # niveau 3
    result = check_whois(domain)
    if result is not None:
        return domain, result

    # niveau 4
    return domain, check_rdap_fallback(domain) or "FREE"

#loader
def loading_screen() -> None:
    install_done = threading.Event()

    def install():
        time.sleep(4)
        subprocess.call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(3)
        install_done.set()

    threading.Thread(target=install, daemon=True).start()

    lines = ASCII_BANNER.splitlines()
    total_steps = 40
    print("\033[?25l", end="", flush=True)
    start = time.time()
    pre_duration = 4.0
    post_start = None
    post_duration = 3.0
    reached_67 = False
    try:
        while True:
            elapsed = time.time() - start
            if install_done.is_set():
                progress = 1.0
            elif not reached_67:
                progress = min(elapsed / pre_duration * 0.67, 0.67)
                if progress >= 0.67:
                    reached_67 = True
                    post_start = time.time()
            else:
                post_elapsed = time.time() - post_start
                progress = 0.67 + min(post_elapsed / post_duration * 0.33, 0.33)
                if progress >= 1.0:
                    progress = 0.99
            filled = int(progress * total_steps)
            percent = progress * 100
            cols, rows = shutil.get_terminal_size()
            bar = "[" + "#" * filled + " " * (total_steps - filled) + "]"
            percent_str = f" {percent:.2f}% "
            bar_with_percent = bar[:21] + percent_str + bar[21:]
            loading_str = "Loading..."
            do_not_resize_str = "Do not resize the terminal during installation"
            h_pad_bar = max(0, (cols - len(bar_with_percent)) // 2)
            h_pad_loading = max(0, (cols - len(loading_str)) // 2)
            h_pad_do_not_resize = max(0, (cols - len(do_not_resize_str)) // 2)
            v_pad = max(0, (rows - len(lines) - 3) // 2)
            output = "\033[H"
            output += "\n" * v_pad
            for line in lines:
                h_pad = max(0, (cols - len(line)) // 2)
                output += f"{' ' * h_pad}{GREEN}{line}{RESET}\n"
            output += f"\n{' ' * h_pad_bar}{GREEN}{bar_with_percent}{RESET}"
            output += f"\n\n{' ' * h_pad_loading}{GREEN}{loading_str}{RESET}"
            output += f"\n\n{' ' * h_pad_do_not_resize}{GREEN}{do_not_resize_str}{RESET}"
            print(output, end="", flush=True)
            time.sleep(0.05)
            if install_done.is_set():
                break
    finally:
        print("\033[?25h", end="", flush=True)
        print("\033[2J\033[H", end="", flush=True)

def print_centered_banner_and_menu():
    cols, rows = shutil.get_terminal_size()
    lines = ASCII_BANNER.splitlines()
    v_pad = max(0, (rows - len(lines) - 6) // 2) - 1
    os.system('cls') if os.name == 'nt' else os.system('clear')
    output = "\033[H"
    output += "\n" * v_pad
    for line in lines:
        h_pad = max(0, (cols - len(line)) // 2)
        output += green(" " * h_pad + line) + "\n"
    output += "\n"
    output += green("[1] Global TLD check\n[2] Single domain check\n[3] Exit\n\nChoose an option : ")
    print(output, end="", flush=True)


def show_menu() -> tuple[str, list[str]]:
    last_size = shutil.get_terminal_size()
    print_centered_banner_and_menu()

    def check_resize():
        nonlocal last_size
        while True:
            size = shutil.get_terminal_size()
            if size != last_size:
                last_size = size
                print_centered_banner_and_menu()
            time.sleep(0.5)

    threading.Thread(target=check_resize, daemon=True).start()

    while True:
        ask_options = input("").strip()

        if ask_options == "1":
            raw = input(green("\n[SLD] Domain name : ")).strip()
            return normalize_sld(raw), list(TLD_LIST)

        elif ask_options == "2":
            raw = input(green("\n[STLD] Full domain : ")).strip().lower()
            if "." not in raw:
                print(green("Invalid domain. Perhaps you forgot a dot or a TLD ?"))
                print_centered_banner_and_menu()
                continue
            sld, _, tld = raw.partition(".")
            return normalize_sld(sld), [tld]

        elif ask_options == "3":
            print(green("\nThanks for using DomainTester !"))
            time.sleep(1)
            exit()

        else:
            print_centered_banner_and_menu()


def start_script() -> tuple[str, list[str]]:
    enable_ansi_on_windows()
    loading_screen()
    return show_menu()


def end_script(base: str, free: list[str], taken: list[str]) -> None:

    print(green("\n" + "=" * 60 + "\n"))
    print(green("[1] Save results in a txt\n[2] Restart\n[3] Exit\n"))
    ask_next = input(green("Choose an option : ")).strip()

    if ask_next == "1":
        filename = f"{base}_results.txt"
        with open(filename, "w", encoding="utf-8") as f:
            f.write("Available domains :\n")
            for domain in free:
                f.write(f"{domain}\n")

    elif ask_next == "2":
        os.system("cls" if os.name == "nt" else "clear")
        base, tld_list = show_menu()
        main_loop(base, tld_list)

    elif ask_next == "3":
        print(green("\nThanks for using DomainTester !"))
        time.sleep(1)
        exit()

    else:
        print(green("Invalid option. Please choose 1, 2 or 3"))
        end_script(base, free, taken)

def main_loop(base: str, tld_list: list[str]) -> None:
    tested = 0
    free: list[str] = []
    taken: list[str] = []

    with ThreadPoolExecutor(max_workers=128) as executor:
        futures = {executor.submit(check_domain, base, tld): tld for tld in tld_list}
        for future in as_completed(futures):
            tested += 1
            try:
                domain, status = future.result()
            except Exception:
                taken.append(f"{base}.{futures[future]}")
                continue
            if status == "TAKEN":
                taken.append(domain)
            else:
                status = "FREE"
                free.append(domain)
            print(format_result(domain, status))

    print(green("\n" + "=" * 60 + "\n"))
    if free:
        print(green("Available domains :\n"))
        for domain in free:
            print(format_result(domain, "FREE"))
        print()
    print(green("=" * 60 + "\n"))
    print(green("Results :\n"))
    print(green(f"Tested    : {tested}"))
    print(green(f"Free      : {len(free)}"))
    print(green(f"Taken     : {len(taken)}"))
    end_script(base, free, taken)

def main() -> None:
    base, tld_list = start_script()
    main_loop(base, tld_list)



# lancement du script
if __name__ == "__main__":
    main()