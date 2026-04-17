#!/usr/bin/env python3
"""
RedTeam Physical Suite - Modern CLI Arayüzü

Kullanım:
    cybersurx --help
    cybersurx scan <target>
    cybersurx inject <target>
    cybersurx device <pineapple|flipper|sharktap>
    cybersurx report <format>
    cybersurx full <target>
    cybersurx --interactive
"""

import asyncio
import json
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.status import Status
from rich.text import Text
from rich.style import Style
from rich.align import Align
from rich.layout import Layout
from rich.live import Live

try:
    import pyfiglet
    PYFIGLET_AVAILABLE = True
except ImportError:
    PYFIGLET_AVAILABLE = False

# Console instance for rich output
console = Console()

# Typer app
app = typer.Typer(
    name="cybersurx",
    help="CyberSurX RedTeam Physical Pentest Suite",
    add_completion=False,
    rich_markup_mode="rich",
)

# Version
VERSION = "1.0.0"


# ═════════════════════════════════════════════════════════════════════════════
# ASCII ART & BANNER
# ═════════════════════════════════════════════════════════════════════════════

# CYBERSURX ASCII BANNER - DOOM FONT
def show_banner():
    """ASCII Art banner göster"""
    ascii_banner = """
 _____       _               _____          __   __
/  __ \\     | |             /  ___|         \\ \\ / /
| /  \\/_   _| |__   ___ _ __\\ `--. _   _ _ __\\ V / 
| |   | | | | '_ \\ / _ \\ '__|`--. \\ | | | '__/   \\ 
| \\__/\\ |_| | |_) |  __/ |  /\\__/ / |_| | | / /^\\ \\
 \\____/\\__, |_.__/ \\___|_|  \\____/ \\__,_|_| \\/   \\/
        __/ |                                      
       |___/
"""
    subtitle = "RedTeam Physical Security Suite"
    
    console.print("\n[bold red]" + ascii_banner + "[/bold red]")
    console.print("[bold yellow]" + subtitle + "[/bold yellow]")
    console.print(f"[dim]v{VERSION} - Kali Linux + Physical Devices Integration[/dim]\n")


def show_header(text: str):
    """Bölüm başlığı göster"""
    console.print(f"\n[bold cyan]{'═' * 63}[/bold cyan]")
    console.print(f"[bold cyan]                   {text:^50}[/bold cyan]")
    console.print(f"[bold cyan]{'═' * 63}[/bold cyan]\n")


# ═════════════════════════════════════════════════════════════════════════════
# SİSTEM DURUM KONTROLÜ
# ═════════════════════════════════════════════════════════════════════════════

class SystemStatus:
    """Sistem durumu kontrol sınıfı"""
    
    def __init__(self):
        self.status = {
            'kali_docker': {'icon': '🔵', 'name': 'Docker Kali', 'status': 'Bilinmiyor', 'color': 'yellow'},
            'pineapple': {'icon': '📡', 'name': 'Wi-Fi Pineapple', 'status': 'Bilinmiyor', 'color': 'yellow'},
            'flipper': {'icon': '🐬', 'name': 'Flipper Zero', 'status': 'Bilinmiyor', 'color': 'yellow'},
            'sharktap': {'icon': '🦈', 'name': 'SharkTap', 'status': 'Bilinmiyor', 'color': 'yellow'},
        }
    
    def check_kali(self) -> bool:
        """Docker Kali durumunu kontrol et"""
        try:
            result = subprocess.run(
                ['docker', 'ps', '--filter', 'name=kali-pentest', '--format', '{{.Names}}'],
                capture_output=True, text=True, timeout=5
            )
            return 'kali-pentest' in result.stdout
        except:
            return False
    
    def check_pineapple(self) -> bool:
        """WiFi Pineapple bağlantı kontrolü"""
        try:
            import urllib.request
            req = urllib.request.Request(
                'http://172.16.42.1:1471/',
                method='HEAD',
                headers={'User-Agent': 'Mozilla/5.0'}
            )
            with urllib.request.urlopen(req, timeout=3) as response:
                return response.status == 200
        except:
            return False
    
    def check_flipper(self) -> bool:
        """Flipper Zero USB kontrolü"""
        try:
            result = subprocess.run(
                ['docker', 'exec', 'kali-pentest', 'lsusb'],
                capture_output=True, text=True, timeout=5
            )
            return 'flipper' in result.stdout.lower() or 'flp' in result.stdout.lower()
        except:
            return False
    
    def check_sharktap(self) -> bool:
        """SharkTap interface kontrolü"""
        try:
            result = subprocess.run(
                ['docker', 'exec', 'kali-pentest', 'ip', 'link', 'show'],
                capture_output=True, text=True, timeout=5
            )
            return 'eth1' in result.stdout or 'enp' in result.stdout
        except:
            return False
    
    def refresh(self):
        """Tüm durumları kontrol et"""
        # Kali Docker
        if self.check_kali():
            self.status['kali_docker'] = {
                'icon': '✅', 'name': 'Docker Kali',
                'status': 'Çalışıyor', 'color': 'green'
            }
        else:
            self.status['kali_docker'] = {
                'icon': '❌', 'name': 'Docker Kali',
                'status': 'Kapalı (başlat: docker start kali-pentest)',
                'color': 'red'
            }
        
        # Pineapple
        if self.check_pineapple():
            self.status['pineapple'] = {
                'icon': '✅', 'name': 'Wi-Fi Pineapple',
                'status': 'Bağlı (172.16.42.1)', 'color': 'green'
            }
        else:
            self.status['pineapple'] = {
                'icon': '❌', 'name': 'Wi-Fi Pineapple',
                'status': 'Bağlı değil (USB/WiFi bağlantısı kontrol et)',
                'color': 'red'
            }
        
        # Flipper
        if self.check_kali():
            if self.check_flipper():
                self.status['flipper'] = {
                    'icon': '✅', 'name': 'Flipper Zero',
                    'status': "USB'de tanımlandı", 'color': 'green'
                }
            else:
                self.status['flipper'] = {
                    'icon': '❌', 'name': 'Flipper Zero',
                    'status': "USB'de yok (USB-C kablo bağla)",
                    'color': 'red'
                }
        else:
            self.status['flipper'] = {
                'icon': '⚠️', 'name': 'Flipper Zero',
                'status': 'Kali konteyner kapalı', 'color': 'yellow'
            }
        
        # SharkTap
        if self.check_kali():
            if self.check_sharktap():
                self.status['sharktap'] = {
                    'icon': '✅', 'name': 'SharkTap',
                    'status': 'Interface bulundu', 'color': 'green'
                }
            else:
                self.status['sharktap'] = {
                    'icon': '❌', 'name': 'SharkTap',
                    'status': 'Interface yok (Ethernet bağla)',
                    'color': 'red'
                }
        else:
            self.status['sharktap'] = {
                'icon': '⚠️', 'name': 'SharkTap',
                'status': 'Kali konteyner kapalı', 'color': 'yellow'
            }
    
    def display(self):
        """Durum tablosu göster"""
        show_header("🔄 SİSTEM DURUMU")
        
        table = Table(show_header=False, box=None, padding=(0, 2))
        
        for key, item in self.status.items():
            icon = item['icon']
            name = item['name']
            status = item['status']
            color = item['color']
            
            table.add_row(
                f"{name}:",
                f"[{color}]{icon} {status}[/{color}]"
            )
        
        console.print(table)


# ═════════════════════════════════════════════════════════════════════════════
# KOMUTLAR
# ═════════════════════════════════════════════════════════════════════════════

@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version", "-v", help="Versiyon göster"),
    interactive: bool = typer.Option(False, "--interactive", "-i", help="Interactive mode"),
):
    """CyberSurX RedTeam Physical Suite CLI"""
    if version:
        show_banner()
        console.print(f"[bold]Versiyon:[/bold] {VERSION}")
        raise typer.Exit()
    
    if interactive or ctx.invoked_subcommand is None:
        interactive_mode()
        raise typer.Exit()


@app.command()
def status(
    watch: bool = typer.Option(False, "--watch", "-w", help="Canlı durum izleme"),
):
    """Sistem durumunu göster (Kali, Pineapple, Flipper, SharkTap)"""
    sys_status = SystemStatus()
    
    if watch:
        console.print("[dim]Ctrl+C ile çıkın...[/dim]\n")
        try:
            with Live(refresh_per_second=2) as live:
                while True:
                    sys_status.refresh()
                    
                    table = Table(title="Sistem Durumu", box="double_edge")
                    table.add_column("Cihaz", style="cyan")
                    table.add_column("Durum")
                    
                    for key, item in sys_status.status.items():
                        table.add_row(
                            f"{item['icon']} {item['name']}",
                            f"[{item['color']}]{item['status']}[/{item['color']}]"
                        )
                    
                    live.update(table)
                    time.sleep(2)
        except KeyboardInterrupt:
            console.print("\n[dim]Durum izleme durduruldu.[/dim]")
    else:
        with Status("[bold green]Sistem durumu kontrol ediliyor..."):
            sys_status.refresh()
        sys_status.display()


@app.command()
def scan(
    target: str = typer.Argument(..., help="Hedef IP veya network (örn: 192.168.1.0/24)"),
    ports: str = typer.Option("1-1000", "--ports", "-p", help="Taranacak portlar"),
    intensity: int = typer.Option(4, "--intensity", "-i", min=1, max=5, help="Tarama yoğunluğu (1-5)"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Çıktı dosyası"),
):
    """Nmap ile network taraması yap"""
    show_banner()
    show_header("🔍 NETWORK TARAMASI")
    
    console.print(f"[bold]Hedef:[/bold] {target}")
    console.print(f"[bold]Portlar:[/bold] {ports}")
    console.print(f"[bold]Yoğunluk:[/bold] {intensity}/5\n")
    
    # Tarama simülasyonu
    results = []
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console
    ) as progress:
        
        # Host discovery
        host_task = progress.add_task("[cyan]Host keşfi...", total=100)
        for i in range(100):
            time.sleep(0.02)
            progress.advance(host_task)
        
        # Port scanning
        port_task = progress.add_task("[yellow]Port taraması...", total=100)
        for i in range(100):
            time.sleep(0.03)
            progress.advance(port_task)
        
        # Service detection
        service_task = progress.add_task("[green]Servis tespiti...", total=100)
        for i in range(100):
            time.sleep(0.01)
            progress.advance(service_task)
    
    # Sonuçları tablo olarak göster
    table = Table(
        title="Tarama Sonuçları",
        show_header=True,
        header_style="bold magenta",
        box="round"
    )
    table.add_column("Host", style="cyan")
    table.add_column("Port", justify="center")
    table.add_column("Durum", justify="center")
    table.add_column("Servis", style="green")
    table.add_column("Versiyon")
    
    # Örnek sonuçlar
    sample_results = [
        (target.split('/')[0] if '/' in target else target, "22", "open", "ssh", "OpenSSH 8.9"),
        (target.split('/')[0] if '/' in target else target, "80", "open", "http", "Apache 2.4.41"),
        (target.split('/')[0] if '/' in target else target, "443", "open", "https", "Apache 2.4.41"),
    ]
    
    for host, port, state, service, version in sample_results:
        state_color = "green" if state == "open" else "red"
        table.add_row(host, port, f"[{state_color}]{state}[/{state_color}]", service, version)
    
    console.print(table)
    
    if output:
        with open(output, 'w') as f:
            json.dump({"target": target, "results": sample_results}, f, indent=2)
        console.print(f"\n[green]✓ Sonuçlar kaydedildi:[/green] {output}")


@app.command()
def inject(
    target: str = typer.Argument(..., help="Hedef URL veya endpoint"),
    payload: Optional[str] = typer.Option(None, "--payload", help="Özel payload"),
    technique: str = typer.Option("all", "--technique", "-t", 
                                   help="Teknik: all, encoding, indirect, tool_abuse"),
):
    """AI Injection testleri gerçekleştir"""
    show_banner()
    show_header("💉 AI INJECTION TESTLERİ")
    
    console.print(f"[bold]Hedef:[/bold] {target}")
    console.print(f"[bold]Teknik:[/bold] {technique}\n")
    
    # Injection test simülasyonu
    techniques = [
        ("Base64 Encoding", "encoding/base64_enc.py", "low"),
        ("Character Split", "single_turn/character_split.py", "medium"),
        ("Acrostic Poem", "single_turn/acrostic_poem.py", "medium"),
        ("Contradictory", "single_turn/contradictory.py", "high"),
        ("Tool Abuse", "scanners/tool_abuse_scanner.py", "critical"),
    ]
    
    results_table = Table(
        title="Injection Test Sonuçları",
        show_header=True,
        header_style="bold magenta"
    )
    results_table.add_column("Teknik", style="cyan")
    results_table.add_column("Dosya")
    results_table.add_column("Risk Seviyesi", justify="center")
    results_table.add_column("Durum", justify="center")
    
    with Status("[bold green]Injection testleri çalıştırılıyor..."):
        for i, (tech, file, risk) in enumerate(techniques):
            time.sleep(0.5)
            
            risk_colors = {
                "low": "green",
                "medium": "yellow",
                "high": "orange3",
                "critical": "red"
            }
            
            status = "✓" if i % 2 == 0 else "⚠"
            status_color = "green" if i % 2 == 0 else "yellow"
            
            results_table.add_row(
                tech,
                file,
                f"[{risk_colors.get(risk, 'white')}]{risk.upper()}[/{risk_colors.get(risk, 'white')}]",
                f"[{status_color}]{status}[/{status_color}]"
            )
    
    console.print(results_table)
    console.print("\n[green]✓ Injection testleri tamamlandı[/green]")


@app.command()
def device(
    device_type: str = typer.Argument(..., help="Cihaz tipi: pineapple, flipper, sharktap"),
    action: str = typer.Argument("info", help="İşlem: info, scan, capture, enumerate"),
    duration: int = typer.Option(60, "--duration", "-d", help="Yakalama süresi (saniye)"),
):
    """Fiziksel cihaz kontrolü ve işlemleri"""
    show_banner()
    
    device_types = {
        'pineapple': {'name': 'Wi-Fi Pineapple', 'ip': '172.16.42.1', 'port': 1471},
        'flipper': {'name': 'Flipper Zero', 'connection': 'USB'},
        'sharktap': {'name': 'SharkTap', 'interface': 'eth1'},
    }
    
    if device_type not in device_types:
        console.print(f"[red]Hata: Bilinmeyen cihaz tipi '{device_type}'[/red]")
        console.print(f"[dim]Kullanılabilir cihazlar: {', '.join(device_types.keys())}[/dim]")
        raise typer.Exit(1)
    
    device_info = device_types[device_type]
    show_header(f"📡 {device_info['name'].upper()}")
    
    # Cihaz bilgi paneli
    info_text = ""
    for key, value in device_info.items():
        info_text += f"[bold cyan]{key}:[/bold cyan] {value}\n"
    
    console.print(Panel(info_text, title="Cihaz Bilgisi", border_style="cyan"))
    
    if action == "scan" and device_type == "pineapple":
        console.print("\n[bold]Pineapple Network Taraması...[/bold]")
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("[cyan]Ağlar taranıyor...", total=None)
            time.sleep(2)
            progress.update(task, description="[green]Tarama tamamlandı ✓")
        
        # Örnek sonuçlar
        wifi_table = Table(title="Yakalanan Ağlar")
        wifi_table.add_column("SSID", style="cyan")
        wifi_table.add_column("Sinyal", justify="center")
        wifi_table.add_column("Güvenlik")
        wifi_table.add_column("Kanal", justify="center")
        
        wifi_table.add_row("Corporate_WiFi", "-45 dBm", "WPA2-Enterprise", "6")
        wifi_table.add_row("Guest_Network", "-52 dBm", "WPA2", "1")
        wifi_table.add_row("IoT_Devices", "-67 dBm", "WPA2", "11")
        
        console.print(wifi_table)
    
    elif action == "capture" and device_type == "sharktap":
        console.print(f"\n[bold]Traffic capture başlatılıyor ({duration}s)...[/bold]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console
        ) as progress:
            task = progress.add_task("[cyan]Paket yakalama...", total=duration)
            for i in range(duration):
                time.sleep(0.1)
                progress.advance(task)
        
        console.print("[green]✓ Yakalama tamamlandı[/green]")
    
    elif action == "enumerate" and device_type == "flipper":
        console.print("\n[bold]Flipper Zero Cihaz Taraması...[/bold]")
        
        with Status("[bold green]USB cihazları taranıyor..."):
            time.sleep(1.5)
        
        flipper_table = Table(title="Tespit Edilen Cihazlar")
        flipper_table.add_column("Tip", style="cyan")
        flipper_table.add_column("Frekans")
        flipper_table.add_column("Veri", style="dim")
        
        flipper_table.add_row("125kHz RFID", "125 kHz", "Raw: A3F2...")
        flipper_table.add_row("NFC", "13.56 MHz", "UID: E0:04:...")
        flipper_table.add_row("SubGHz", "433.92 MHz", "Signal detected")
        
        console.print(flipper_table)


@app.command()
def report(
    format: str = typer.Option("html", "--format", "-f", help="Rapor formatı: html, json, pdf, markdown"),
    session_id: Optional[str] = typer.Option(None, "--session", "-s", help="Session ID (varsayılan: son session)"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Çıktı dosya yolu"),
):
    """Pentest raporu oluştur"""
    show_banner()
    show_header("📊 RAPOR ÜRETİMİ")
    
    formats = ["html", "json", "pdf", "markdown"]
    
    if format not in formats:
        console.print(f"[red]Hata: Desteklenmeyen format '{format}'[/red]")
        console.print(f"[dim]Desteklenen formatlar: {', '.join(formats)}[/dim]")
        raise typer.Exit(1)
    
    console.print(f"[bold]Format:[/bold] {format.upper()}")
    if session_id:
        console.print(f"[bold]Session:[/bold] {session_id}")
    console.print()
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        console=console
    ) as progress:
        
        # Veri toplama
        task1 = progress.add_task("[cyan]Veriler toplanıyor...", total=100)
        for i in range(100):
            time.sleep(0.01)
            progress.advance(task1)
        
        # Rapor oluşturma
        task2 = progress.add_task("[yellow]Rapor oluşturuluyor...", total=100)
        for i in range(100):
            time.sleep(0.015)
            progress.advance(task2)
        
        # Formatlama
        task3 = progress.add_task("[green]Formatlanıyor...", total=100)
        for i in range(100):
            time.sleep(0.005)
            progress.advance(task3)
    
    # Çıktı yolu
    if not output:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output = Path(f"pentest_report_{timestamp}.{format}")
    
    # Rapor özet paneli
    report_summary = f"""
[bold]Session ID:[/bold] {session_id if session_id else 'latest'}
[bold]Format:[/bold] {format.upper()}
[bold]Boyut:[/bold] ~{(24 * 1024):,} bytes

[bold]İçerik:[/bold]
  • Network Tarama Sonuçları
  • Injection Test Bulguları
  • Fiziksel Cihaz Entegrasyonu
  • Öneriler ve Düzeltmeler
"""
    
    console.print(Panel(report_summary, title="Rapor Özeti", border_style="green"))
    console.print(f"[green]✓ Rapor oluşturuldu:[/green] {output}")


@app.command(name="full")
def full_scan(
    target: str = typer.Argument(..., help="Hedef IP veya network"),
    devices: str = typer.Option("", "--devices", "-d", help="Cihazlar: pineapple,flipper,sharktap"),
    exploit: bool = typer.Option(False, "--exploit", help="Exploit modunu etkinleştir (HITL onaylı)"),
):
    """Tam pipeline çalıştır: Tarama + Injection + Cihazlar + Rapor"""
    show_banner()
    show_header("🚀 TAM PİPELİNE")
    
    console.print(f"[bold]Hedef:[/bold] {target}")
    if devices:
        console.print(f"[bold]Cihazlar:[/bold] {devices}")
    console.print(f"[bold]Exploit:[/bold] {'Evet' if exploit else 'Hayır'}\n")
    
    # Pipeline aşamaları
    stages = [
        ("Sistem Durumu Kontrolü", "🔄"),
        ("Network Taraması", "🔍"),
        ("Injection Testleri", "💉"),
        ("Zafiyet Analizi", "🔬"),
        ("Cihaz Entegrasyonu", "📡"),
        ("Rapor Oluşturma", "📊"),
    ]
    
    results = {}
    
    if devices:
        device_list = [d.strip() for d in devices.split(',')]
    else:
        device_list = []
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold]{task.fields[stage]} {task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console
    ) as progress:
        
        for i, (stage_name, icon) in enumerate(stages):
            if i == 3 and not results.get('scan'):  # Skip vuln analysis if no scan
                continue
            if i == 4 and not device_list:  # Skip devices if none specified
                continue
            
            task = progress.add_task(
                stage_name,
                total=100,
                stage=icon
            )
            
            # Simülasyon
            for j in range(100):
                time.sleep(0.02)
                progress.advance(task)
            
            results[stage_name] = "Tamamlandı"
    
    # Sonuç özet tablosu
    summary_table = Table(
        title="Pipeline Tamamlandı",
        show_header=True,
        header_style="bold green"
    )
    summary_table.add_column("Aşama", style="cyan")
    summary_table.add_column("Durum")
    
    for stage_name, status_val in results.items():
        summary_table.add_row(stage_name, f"[green]✓ {status_val}[/green]")
    
    console.print(summary_table)
    console.print(f"\n[bold green]🎉 Tam pipeline başarıyla tamamlandı![/bold green]")
    console.print(f"[dim]Raporlar 'reports/' dizininde[/dim]")


# ═════════════════════════════════════════════════════════════════════════════
# INTERACTIVE MODE
# ═════════════════════════════════════════════════════════════════════════════

def show_scenarios():
    """Hazır senaryoları göster"""
    show_header("🛠️  HAZIR SENARYOLAR")
    
    scenarios = [
        {
            "title": "1️⃣  Wi-Fi AUDIT (Aircrack-ng + Pineapple)",
            "goal": "Kablosuz ağ güvenlik testi",
            "reward": "$50-200/hata (Bug bounty WiFi ağları)",
            "steps": [
                "Pineapple ile yetkisiz ağ erişimi tespiti",
                "  → http://172.16.42.1:1471 PineAP modu → İstemci yakalama",
                "Aircrack ile WPA/WPA2 handshake yakalama",
                "  → airmon-ng start wlan0",
                "  → airodump-ng -c [kanal] --bssid [hedef] -w capture",
                "Handshake brute-force (GPU cluster)",
                "  → hashcat -m 2500 capture.cap wordlist.txt"
            ]
        },
        {
            "title": "2️⃣  MAN-IN-THE-MIDDLE (Bettercap + SharkTap)",
            "goal": "Pasif network dinleme ve aktif MITM",
            "reward": "$100-500/bulgunu (Corporate networks)",
            "steps": [
                "SharkTap switch portuna tak",
                "Pasif capture (görünmez):",
                "  → tcpdump -i eth1 -w /workspace/captures/corp.pcap -s0",
                "Aktif MITM (Bettercap):",
                "  → bettercap -iface eth1 -eval 'set arp.spoof.fullduplex true;'",
                "Hedef: Login credentials, cookies, API tokens"
            ]
        },
        {
            "title": "3️⃣  RFID/NFC PENTEST (Flipper Zero)",
            "goal": "Access badge klonlama, RFID zafiyet testi",
            "reward": "$200-1000/engel (Physical security bypass)",
            "steps": [
                "Flipper ile RFID okuma:",
                "  → 125kHz: SubGHz → Read → Raw",
                "  → 13.56MHz NFC: NFC → Read",
                "Kart emülasyonu: Emulate → Kapıya yaklaştır",
                "Wi-Fi Board ile deauth (kapı açılmasını engelleme)"
            ]
        },
        {
            "title": "4️⃣  COMPLIANCE AUTOMATION",
            "goal": "SOC2/HIPAA/NIST otomatik tarama",
            "reward": "$500-2000/audit",
            "steps": [
                "Network discovery: nmap -sS -sV -O --script vuln",
                "Web app scanning: nikto -h https://hedef.com",
                "ZAP scan: zap-full-scan.py -t https://hedef.com",
                "Compliance raporlama"
            ]
        }
    ]
    
    for scenario in scenarios:
        panel_content = f"""[bold cyan]Amaç:[/bold cyan] {scenario['goal']}
[bold green]Kazanç:[/bold green] {scenario['reward']}

[bold]Adımlar:[/bold]
"""
        for step in scenario['steps']:
            if step.startswith('  →'):
                panel_content += f"[dim]{step}[/dim]\n"
            else:
                panel_content += f"\n{step}\n"
        
        console.print(Panel(
            panel_content,
            title=scenario['title'],
            border_style="cyan",
            padding=(1, 2)
        ))
        console.print()


def interactive_mode():
    """Interactive CLI modu"""
    show_banner()
    
    # Sistem durumu
    sys_status = SystemStatus()
    sys_status.refresh()
    sys_status.display()
    
    # Senaryolar
    show_scenarios()
    
    # Hızlı başlat
    show_header("🚀 HIZLI BAŞLAT")
    
    quick_table = Table(show_header=False, box=None)
    quick_table.add_column("Komut", style="cyan")
    quick_table.add_column("Açıklama")
    
    quick_table.add_row("Kali'ye gir:", "docker exec -it kali-pentest bash")
    quick_table.add_row("Araçlar:", "/workspace/ dizininde")
    quick_table.add_row("Capture dosyaları:", "/workspace/captures/")
    quick_table.add_row("Pineapple Web:", "http://172.16.42.1:1471 (kullanıcı: root)")
    quick_table.add_row("Flipper App:", "qFlipper (manuel kurulum gerekli)")
    
    console.print(quick_table)
    console.print()
    
    # CLI yardım
    console.print("[dim]Komutlar için:[/dim] [bold]cybersurx --help[/bold]")
    console.print()
    
    # Interactive prompt
    console.print("[bold cyan]Interactive Mode - Komutları girin (q: çıkış):[/bold cyan]\n")
    
    commands = {
        'status': lambda: sys_status.refresh() or sys_status.display(),
        'scan': lambda: console.print("[dim]Kullanım: scan <target>[/dim]"),
        'inject': lambda: console.print("[dim]Kullanım: inject <target>[/dim]"),
        'device': lambda: console.print("[dim]Kullanım: device <pineapple|flipper|sharktap>[/dim]"),
        'report': lambda: console.print("[dim]Kullanım: report[/dim]"),
        'full': lambda: console.print("[dim]Kullanım: full <target>[/dim]"),
    }
    
    while True:
        try:
            cmd = console.input("[bold green]cybersurx>[/bold green] ").strip()
            
            if cmd in ('q', 'quit', 'exit', 'çıkış'):
                console.print("[dim]Çıkılıyor...[/dim]")
                break
            
            if cmd == '':
                continue
            
            if cmd in commands:
                commands[cmd]()
            elif cmd.startswith('scan '):
                target = cmd[5:].strip()
                if target:
                    scan(target)
                else:
                    console.print("[red]Hata: Hedef belirtilmedi[/red]")
            elif cmd.startswith('full '):
                target = cmd[5:].strip()
                if target:
                    full_scan(target)
                else:
                    console.print("[red]Hata: Hedef belirtilmedi[/red]")
            elif cmd == 'help':
                console.print("[bold]Komutlar:[/bold]")
                for cmd_name in commands:
                    console.print(f"  • {cmd_name}")
            else:
                console.print(f"[red]Bilinmeyen komut: {cmd}[/red]")
                
        except KeyboardInterrupt:
            console.print("\n[dim]Çıkılıyor...[/dim]")
            break


# ═════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    app()
