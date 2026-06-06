#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║         NETWORK AUDIT TOOL — Vincent Degbe                  ║
║         Cybersécurité & Réseaux — vdegbe.github.io          ║
║         Scan de ports + Détection de vulnérabilités + PDF   ║
╚══════════════════════════════════════════════════════════════╝

Usage:
    python3 audit_reseau.py -t 192.168.1.0/24
    python3 audit_reseau.py -t 192.168.1.1 --ports 22,80,443,3389
    python3 audit_reseau.py -t 192.168.1.0/24 --output rapport_audit.pdf

Dépendances:
    pip install python-nmap reportlab colorama

Auteur : Vincent Degbe
"""

import argparse
import socket
import subprocess
import sys
import json
import os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── Vérification des dépendances ──
def check_deps():
    missing = []
    for pkg in ['nmap', 'reportlab', 'colorama']:
        try:
            __import__(pkg if pkg != 'nmap' else 'nmap')
        except ImportError:
            missing.append(pkg)
    if missing:
        print(f"[!] Modules manquants : {', '.join(missing)}")
        print(f"[!] Installez-les : pip install {' '.join(missing)}")
        sys.exit(1)

try:
    import nmap
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import cm
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, HRFlowable, Table, TableStyle
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY
    from colorama import Fore, Style, init
    init(autoreset=True)
    COLORAMA = True
except ImportError:
    COLORAMA = False

# ── Couleurs console ──
def c(text, color=''):
    if not COLORAMA:
        return text
    colors_map = {
        'red': Fore.RED, 'green': Fore.GREEN, 'yellow': Fore.YELLOW,
        'cyan': Fore.CYAN, 'blue': Fore.BLUE, 'magenta': Fore.MAGENTA,
        'white': Fore.WHITE, 'bold': Style.BRIGHT
    }
    return f"{colors_map.get(color, '')}{text}{Style.RESET_ALL}"

# ══════════════════════════════════════════
# BASE DE VULNÉRABILITÉS CONNUES
# (Services / versions obsolètes courants)
# ══════════════════════════════════════════
VULN_DB = {
    # SSH
    'ssh': [
        {'version_match': 'OpenSSH_7', 'cve': 'CVE-2023-38408', 'severity': 'ÉLEVÉ',
         'desc': 'OpenSSH < 9.3p2 — Remote code execution via ssh-agent',
         'reco': 'Mettre à jour OpenSSH vers la version 9.3p2 ou supérieure'},
        {'version_match': 'OpenSSH_6', 'cve': 'CVE-2018-15473', 'severity': 'MOYEN',
         'desc': 'OpenSSH < 7.7 — Username enumeration via timing attack',
         'reco': 'Mettre à jour OpenSSH. Désactiver l\'authentification par mot de passe'},
    ],
    # HTTP/Apache
    'http': [
        {'version_match': 'Apache/2.4.4', 'cve': 'CVE-2021-41773', 'severity': 'CRITIQUE',
         'desc': 'Apache 2.4.49 — Path traversal et RCE',
         'reco': 'Mettre à jour Apache vers 2.4.51+. Désactiver mod_cgi'},
        {'version_match': 'Apache/2.2', 'cve': 'CVE-2017-7679', 'severity': 'CRITIQUE',
         'desc': 'Apache 2.2.x (EOL) — Multiple critical vulnerabilities',
         'reco': 'Mettre à jour vers Apache 2.4.x immédiatement (version EOL)'},
        {'version_match': 'nginx/1.1', 'cve': 'CVE-2021-23017', 'severity': 'ÉLEVÉ',
         'desc': 'Nginx < 1.20.1 — DNS resolver buffer overflow',
         'reco': 'Mettre à jour Nginx vers 1.20.1 ou supérieure'},
    ],
    # SMB
    'microsoft-ds': [
        {'version_match': '', 'cve': 'CVE-2017-0144', 'severity': 'CRITIQUE',
         'desc': 'SMB — EternalBlue (MS17-010) potentiellement exploitable',
         'reco': 'Appliquer le patch MS17-010. Désactiver SMBv1. Bloquer port 445 depuis Internet'},
    ],
    # FTP
    'ftp': [
        {'version_match': 'vsftpd 2.3', 'cve': 'CVE-2011-2523', 'severity': 'CRITIQUE',
         'desc': 'vsFTPd 2.3.4 — Backdoor permettant accès shell root',
         'reco': 'Mettre à jour vsFTPd immédiatement. Considérer SFTP à la place'},
        {'version_match': '', 'cve': 'INFO-001', 'severity': 'MOYEN',
         'desc': 'FTP actif — Protocole non chiffré, credentials transmis en clair',
         'reco': 'Remplacer FTP par SFTP (SSH) ou FTPS pour chiffrer les échanges'},
    ],
    # Telnet
    'telnet': [
        {'version_match': '', 'cve': 'INFO-002', 'severity': 'CRITIQUE',
         'desc': 'Telnet actif — Protocole non chiffré, toutes les données en clair',
         'reco': 'Désactiver Telnet immédiatement. Remplacer par SSH v2'},
    ],
    # RDP
    'ms-wbt-server': [
        {'version_match': '', 'cve': 'CVE-2019-0708', 'severity': 'CRITIQUE',
         'desc': 'RDP exposé — BlueKeep potentiellement exploitable (pre-auth RCE)',
         'reco': 'Appliquer KB4499175. Activer NLA. Restreindre RDP derrière VPN uniquement'},
    ],
    # MySQL
    'mysql': [
        {'version_match': 'MySQL 5.5', 'cve': 'CVE-2016-6662', 'severity': 'CRITIQUE',
         'desc': 'MySQL 5.5.x — Remote code execution via config file',
         'reco': 'Mettre à jour MySQL 5.5 (EOL). Migrer vers MySQL 8.x'},
        {'version_match': '', 'cve': 'INFO-003', 'severity': 'MOYEN',
         'desc': 'MySQL exposé sur interface réseau — Base de données accessible',
         'reco': 'Restreindre MySQL à localhost (bind-address = 127.0.0.1)'},
    ],
    # SNMP
    'snmp': [
        {'version_match': '', 'cve': 'CVE-2002-0013', 'severity': 'ÉLEVÉ',
         'desc': 'SNMP v1/v2c — Community string "public" potentiellement active',
         'reco': 'Migrer vers SNMPv3 avec authentification. Changer la community string'},
    ],
}

# Ports à risque connus
RISKY_PORTS = {
    21: ('FTP', 'MOYEN', 'Protocole non chiffré'),
    23: ('Telnet', 'CRITIQUE', 'Protocole non chiffré — Désactiver immédiatement'),
    25: ('SMTP', 'MOYEN', 'Vérifier si relai ouvert'),
    53: ('DNS', 'FAIBLE', 'Vérifier si résolution récursive ouverte'),
    80: ('HTTP', 'FAIBLE', 'Trafic non chiffré — Forcer HTTPS'),
    111: ('RPC', 'MOYEN', 'Portmapper exposé'),
    135: ('MSRPC', 'MOYEN', 'RPC Windows exposé'),
    137: ('NetBIOS', 'MOYEN', 'NetBIOS — Peut exposer des informations système'),
    139: ('NetBIOS-SSN', 'MOYEN', 'Session NetBIOS'),
    445: ('SMB', 'CRITIQUE', 'SMB exposé — Vérifier EternalBlue (MS17-010)'),
    512: ('Rexec', 'CRITIQUE', 'Remote execution non sécurisé'),
    513: ('Rlogin', 'CRITIQUE', 'Remote login non sécurisé'),
    1433: ('MSSQL', 'ÉLEVÉ', 'SQL Server exposé sur réseau'),
    1521: ('Oracle', 'ÉLEVÉ', 'Oracle DB exposée sur réseau'),
    2049: ('NFS', 'ÉLEVÉ', 'NFS — Vérifier les exports'),
    3306: ('MySQL', 'ÉLEVÉ', 'MySQL exposé sur réseau'),
    3389: ('RDP', 'CRITIQUE', 'RDP exposé — Risque BlueKeep'),
    5432: ('PostgreSQL', 'MOYEN', 'PostgreSQL exposé sur réseau'),
    5900: ('VNC', 'ÉLEVÉ', 'VNC exposé — Vérifier authentification'),
    6379: ('Redis', 'CRITIQUE', 'Redis souvent sans auth — Accès total possible'),
    8080: ('HTTP-Alt', 'FAIBLE', 'Port HTTP alternatif exposé'),
    27017: ('MongoDB', 'CRITIQUE', 'MongoDB souvent sans auth par défaut'),
}

SEVERITY_ORDER = {'CRITIQUE': 0, 'ÉLEVÉ': 1, 'MOYEN': 2, 'FAIBLE': 3, 'INFO': 4}

# ══════════════════════════════════════════
# SCANNER
# ══════════════════════════════════════════
class NetworkAuditor:
    def __init__(self, target, ports=None, verbose=True):
        self.target = target
        self.ports = ports or '21,22,23,25,53,80,111,135,137,139,443,445,512,513,1433,1521,2049,3306,3389,5432,5900,6379,8080,8443,27017'
        self.verbose = verbose
        self.results = {}
        self.vulns = []
        self.start_time = datetime.now()

    def log(self, msg, color='white'):
        if self.verbose:
            print(c(msg, color))

    def banner(self):
        print(c("""
╔══════════════════════════════════════════════════════════════╗
║         NETWORK AUDIT TOOL v1.0 — Vincent Degbe             ║
║         Cybersécurité & Réseaux — vdegbe.github.io          ║
╚══════════════════════════════════════════════════════════════╝""", 'cyan'))
        print(c(f"  [*] Cible     : {self.target}", 'white'))
        print(c(f"  [*] Ports     : {self.ports[:60]}...", 'white'))
        print(c(f"  [*] Démarrage : {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}", 'white'))
        print()

    def scan(self):
        self.log("[*] Phase 1/3 — Scan des hôtes actifs & ports ouverts...", 'cyan')
        try:
            nm = nmap.PortScanner()
            nm.scan(
                hosts=self.target,
                ports=self.ports,
                arguments='-sV -sC -O --script=banner -T4 --open'
            )

            for host in nm.all_hosts():
                if nm[host].state() == 'up':
                    self.log(f"  [+] Hôte actif : {host}", 'green')
                    host_data = {
                        'ip': host,
                        'hostname': nm[host].hostname() or 'N/A',
                        'os': self._get_os(nm[host]),
                        'ports': []
                    }

                    for proto in nm[host].all_protocols():
                        for port in nm[host][proto].keys():
                            svc = nm[host][proto][port]
                            port_data = {
                                'port': port,
                                'proto': proto,
                                'state': svc['state'],
                                'service': svc['name'],
                                'product': svc.get('product', ''),
                                'version': svc.get('version', ''),
                                'extrainfo': svc.get('extrainfo', ''),
                            }
                            host_data['ports'].append(port_data)
                            self.log(f"    [{svc['state'].upper()}] {port}/{proto} — {svc['name']} {svc.get('product','')} {svc.get('version','')}",
                                     'green' if svc['state'] == 'open' else 'yellow')

                    self.results[host] = host_data

        except nmap.PortScannerError as e:
            self.log(f"[!] Erreur nmap : {e}", 'red')
            self.log("[!] Assurez-vous que nmap est installé (sudo apt install nmap)", 'yellow')
            sys.exit(1)
        except Exception as e:
            self.log(f"[!] Erreur : {e}", 'red')
            sys.exit(1)

    def _get_os(self, host_info):
        try:
            if host_info['osmatch']:
                return host_info['osmatch'][0]['name']
        except:
            pass
        return 'Inconnu'

    def analyze_vulns(self):
        self.log("\n[*] Phase 2/3 — Analyse des vulnérabilités...", 'cyan')

        for host, data in self.results.items():
            for port_data in data['ports']:
                if port_data['state'] != 'open':
                    continue

                port = port_data['port']
                service = port_data['service'].lower()
                version_str = f"{port_data['product']} {port_data['version']}".strip()

                # Vérification ports à risque
                if port in RISKY_PORTS:
                    svc_name, severity, desc = RISKY_PORTS[port]
                    vuln = {
                        'host': host,
                        'port': port,
                        'service': svc_name,
                        'cve': 'RISQUE-PORT',
                        'severity': severity,
                        'desc': desc,
                        'version': version_str,
                        'reco': f'Évaluer la nécessité d\'exposer le port {port} ({svc_name})',
                    }
                    self.vulns.append(vuln)
                    self.log(f"  [!] {host}:{port} — {severity} — {desc}", 
                             'red' if severity == 'CRITIQUE' else 'yellow')

                # Vérification base de vulnérabilités
                for svc_key, vuln_list in VULN_DB.items():
                    if svc_key in service:
                        for v in vuln_list:
                            if not v['version_match'] or v['version_match'].lower() in version_str.lower():
                                vuln = {
                                    'host': host,
                                    'port': port,
                                    'service': service,
                                    'cve': v['cve'],
                                    'severity': v['severity'],
                                    'desc': v['desc'],
                                    'version': version_str,
                                    'reco': v['reco'],
                                }
                                # Eviter les doublons
                                if not any(x['host'] == host and x['port'] == port and x['cve'] == v['cve'] for x in self.vulns):
                                    self.vulns.append(vuln)
                                    self.log(f"  [!] {host}:{port} — {v['severity']} — {v['cve']}", 
                                             'red' if v['severity'] == 'CRITIQUE' else 'yellow')

        # Trier par sévérité
        self.vulns.sort(key=lambda x: SEVERITY_ORDER.get(x['severity'], 99))
        self.log(f"\n  [+] {len(self.vulns)} vulnérabilités/risques identifiés", 'green')

    def print_summary(self):
        print()
        print(c("══════════════════════════════════════════════════════", 'cyan'))
        print(c("  RÉSUMÉ DE L'AUDIT", 'cyan'))
        print(c("══════════════════════════════════════════════════════", 'cyan'))
        print(c(f"  Hôtes scannés   : {len(self.results)}", 'white'))
        print(c(f"  Vulnérabilités  : {len(self.vulns)}", 'white'))

        counts = {}
        for v in self.vulns:
            counts[v['severity']] = counts.get(v['severity'], 0) + 1

        for sev, col in [('CRITIQUE', 'red'), ('ÉLEVÉ', 'yellow'), ('MOYEN', 'yellow'), ('FAIBLE', 'green')]:
            if sev in counts:
                print(c(f"  {sev:<10} : {counts[sev]}", col))
        print()

    def generate_pdf(self, output_path):
        self.log("[*] Phase 3/3 — Génération du rapport PDF...", 'cyan')

        DARK   = colors.HexColor('#0d1117')
        ACCENT = colors.HexColor('#00b4d8')
        RED    = colors.HexColor('#e63946')
        ORANGE = colors.HexColor('#f4a261')
        GREEN  = colors.HexColor('#2ec4b6')
        GRAY   = colors.HexColor('#6b7280')
        LGRAY  = colors.HexColor('#f1f5f9')
        NAVY   = colors.HexColor('#1e3a5f')
        WHITE  = colors.white

        doc = SimpleDocTemplate(
            output_path, pagesize=A4,
            leftMargin=2*cm, rightMargin=2*cm,
            topMargin=2*cm, bottomMargin=2*cm
        )

        def ps(name, **kw):
            return ParagraphStyle(name, **kw)

        h1    = ps('h1', fontSize=14, fontName='Helvetica-Bold', textColor=ACCENT, spaceBefore=14, spaceAfter=6, leading=18)
        h2    = ps('h2', fontSize=10, fontName='Helvetica-Bold', textColor=DARK, spaceBefore=8, spaceAfter=4)
        body  = ps('bd', fontSize=8.5, fontName='Helvetica', textColor=DARK, spaceAfter=4, leading=13, alignment=TA_JUSTIFY)
        mono  = ps('mn', fontSize=7.5, fontName='Courier', textColor=colors.HexColor('#22c55e'),
                   backColor=DARK, spaceAfter=4, leading=12, leftIndent=6)
        small = ps('sm', fontSize=7.5, fontName='Helvetica', textColor=GRAY, leading=11)
        title_s = ps('ts', fontSize=22, fontName='Helvetica-Bold', textColor=WHITE, leading=28)
        sub_s   = ps('ss', fontSize=11, fontName='Helvetica', textColor=ACCENT, leading=16)
        meta_s  = ps('ms', fontSize=8.5, fontName='Helvetica', textColor=colors.HexColor('#94a3b8'), leading=13)

        story = []
        end_time = datetime.now()
        duration = (end_time - self.start_time).seconds

        # ── COUVERTURE ──
        cover = Table([[
            Paragraph("RAPPORT D'AUDIT RÉSEAU", title_s),
            Paragraph(f"Cible : {self.target}", sub_s),
            Spacer(1, 8),
            Paragraph(f"Date : {self.start_time.strftime('%d/%m/%Y %H:%M')}  |  Durée : {duration}s", meta_s),
            Paragraph(f"Hôtes actifs : {len(self.results)}  |  Vulnérabilités : {len(self.vulns)}", meta_s),
            Paragraph("Réalisé par : Vincent Degbe  |  vdegbe.github.io", meta_s),
        ]], colWidths=[17*cm])
        cover.setStyle(TableStyle([
            ('BACKGROUND', (0,0),(-1,-1), DARK),
            ('TOPPADDING', (0,0),(-1,-1), 28),
            ('BOTTOMPADDING', (0,0),(-1,-1), 28),
            ('LEFTPADDING', (0,0),(-1,-1), 20),
            ('BOX', (0,0),(-1,-1), 2, ACCENT),
        ]))
        story.append(cover)
        story.append(Spacer(1, 12))

        # Compteurs sévérité
        counts = {}
        for v in self.vulns:
            counts[v['severity']] = counts.get(v['severity'], 0) + 1

        summary_data = [
            ['CRITIQUE', 'ÉLEVÉ', 'MOYEN', 'FAIBLE', 'HÔTES'],
            [str(counts.get('CRITIQUE', 0)), str(counts.get('ÉLEVÉ', 0)),
             str(counts.get('MOYEN', 0)), str(counts.get('FAIBLE', 0)), str(len(self.results))],
        ]
        st = Table(summary_data, colWidths=[3.4*cm]*5)
        st.setStyle(TableStyle([
            ('BACKGROUND', (0,0),(-1,0), DARK),
            ('TEXTCOLOR',  (0,0),(-1,0), ACCENT),
            ('FONTNAME',   (0,0),(-1,0), 'Helvetica-Bold'),
            ('FONTSIZE',   (0,0),(-1,-1), 8),
            ('ALIGN',      (0,0),(-1,-1), 'CENTER'),
            ('BACKGROUND', (0,1),(0,1), colors.HexColor('#3b0f0f')),
            ('TEXTCOLOR',  (0,1),(0,1), RED),
            ('BACKGROUND', (1,1),(1,1), colors.HexColor('#3b1f0a')),
            ('TEXTCOLOR',  (1,1),(1,1), ORANGE),
            ('BACKGROUND', (2,1),(2,1), colors.HexColor('#0a2a2a')),
            ('TEXTCOLOR',  (2,1),(2,1), GREEN),
            ('BACKGROUND', (3,1),(3,1), colors.HexColor('#1a2a1a')),
            ('TEXTCOLOR',  (3,1),(3,1), colors.HexColor('#86efac')),
            ('BACKGROUND', (4,1),(4,1), NAVY),
            ('TEXTCOLOR',  (4,1),(4,1), WHITE),
            ('FONTNAME',   (0,1),(-1,1), 'Helvetica-Bold'),
            ('FONTSIZE',   (0,1),(-1,1), 18),
            ('TOPPADDING', (0,0),(-1,-1), 7),
            ('BOTTOMPADDING',(0,0),(-1,-1), 7),
            ('BOX',        (0,0),(-1,-1), 0.5, GRAY),
            ('INNERGRID',  (0,0),(-1,-1), 0.3, GRAY),
        ]))
        story.append(st)
        story.append(Spacer(1, 14))

        # ── HÔTES DÉCOUVERTS ──
        story.append(Paragraph("1. HÔTES DÉCOUVERTS", h1))
        story.append(HRFlowable(width="100%", thickness=1, color=ACCENT, spaceAfter=8))

        if not self.results:
            story.append(Paragraph("Aucun hôte actif découvert sur la plage scannée.", body))
        else:
            for host, data in self.results.items():
                story.append(Paragraph(f"<b>{host}</b> — {data['hostname']} — OS : {data['os']}", h2))
                if data['ports']:
                    port_rows = [['Port', 'Proto', 'État', 'Service', 'Version']]
                    for p in data['ports']:
                        port_rows.append([
                            str(p['port']), p['proto'], p['state'],
                            p['service'], f"{p['product']} {p['version']}".strip()[:40]
                        ])
                    pt = Table(port_rows, colWidths=[1.5*cm, 1.5*cm, 1.8*cm, 3*cm, 9.2*cm])
                    pt.setStyle(TableStyle([
                        ('BACKGROUND', (0,0),(-1,0), NAVY),
                        ('TEXTCOLOR',  (0,0),(-1,0), WHITE),
                        ('FONTNAME',   (0,0),(-1,0), 'Helvetica-Bold'),
                        ('FONTSIZE',   (0,0),(-1,-1), 7.5),
                        ('ROWBACKGROUNDS', (0,1),(-1,-1), [LGRAY, WHITE]),
                        ('TOPPADDING', (0,0),(-1,-1), 4),
                        ('BOTTOMPADDING', (0,0),(-1,-1), 4),
                        ('LEFTPADDING', (0,0),(-1,-1), 5),
                        ('BOX',        (0,0),(-1,-1), 0.5, GRAY),
                        ('INNERGRID',  (0,0),(-1,-1), 0.3, GRAY),
                    ]))
                    story.append(pt)
                story.append(Spacer(1, 8))

        # ── VULNÉRABILITÉS ──
        story.append(Paragraph("2. VULNÉRABILITÉS & RISQUES IDENTIFIÉS", h1))
        story.append(HRFlowable(width="100%", thickness=1, color=ACCENT, spaceAfter=8))

        risk_colors_map = {'CRITIQUE': RED, 'ÉLEVÉ': ORANGE, 'MOYEN': colors.HexColor('#ca8a04'), 'FAIBLE': GREEN}

        if not self.vulns:
            story.append(Paragraph("✅ Aucune vulnérabilité connue détectée.", body))
        else:
            for i, v in enumerate(self.vulns, 1):
                rc = risk_colors_map.get(v['severity'], GRAY)
                hdr = Table([[
                    Paragraph(f"<b>#{i:02d} — {v['cve']}</b>",
                              ps('x', fontSize=9, fontName='Helvetica-Bold', textColor=WHITE, leading=13)),
                    Paragraph(f"<b>{v['host']}:{v['port']}</b>",
                              ps('x', fontSize=9, fontName='Helvetica', textColor=colors.HexColor('#94a3b8'), leading=13)),
                    Paragraph(f"<b>{v['severity']}</b>",
                              ps('x', fontSize=9, fontName='Helvetica-Bold', textColor=rc, leading=13,
                                 alignment=2)),
                ]], colWidths=[5*cm, 7*cm, 5*cm])
                hdr.setStyle(TableStyle([
                    ('BACKGROUND', (0,0),(-1,-1), DARK),
                    ('TOPPADDING', (0,0),(-1,-1), 6),
                    ('BOTTOMPADDING', (0,0),(-1,-1), 6),
                    ('LEFTPADDING', (0,0),(-1,-1), 8),
                    ('BOX', (0,0),(-1,-1), 1.5, rc),
                ]))
                story.append(hdr)

                details = [
                    [Paragraph('Service', ps('lbl', fontSize=8, fontName='Helvetica-Bold', textColor=GRAY)),
                     Paragraph(f"{v['service']} — {v['version']}" if v['version'] else v['service'], body)],
                    [Paragraph('Description', ps('lbl', fontSize=8, fontName='Helvetica-Bold', textColor=GRAY)),
                     Paragraph(v['desc'], body)],
                    [Paragraph('Recommandation', ps('lbl', fontSize=8, fontName='Helvetica-Bold', textColor=GRAY)),
                     Paragraph(v['reco'], body)],
                ]
                dt = Table(details, colWidths=[3.5*cm, 13.5*cm])
                dt.setStyle(TableStyle([
                    ('VALIGN', (0,0),(-1,-1), 'TOP'),
                    ('TOPPADDING', (0,0),(-1,-1), 4),
                    ('BOTTOMPADDING', (0,0),(-1,-1), 4),
                    ('LEFTPADDING', (0,0),(-1,-1), 6),
                    ('BACKGROUND', (0,0),(0,-1), LGRAY),
                    ('BOX', (0,0),(-1,-1), 0.5, GRAY),
                    ('INNERGRID', (0,0),(-1,-1), 0.3, colors.HexColor('#e2e8f0')),
                    ('LINEBELOW', (0,-1),(-1,-1), 1, rc),
                ]))
                story.append(dt)
                story.append(Spacer(1, 8))

        # ── RECOMMANDATIONS ──
        story.append(Paragraph("3. RECOMMANDATIONS PRIORITAIRES", h1))
        story.append(HRFlowable(width="100%", thickness=1, color=ACCENT, spaceAfter=8))

        critiques = [v for v in self.vulns if v['severity'] == 'CRITIQUE']
        eleves    = [v for v in self.vulns if v['severity'] == 'ÉLEVÉ']
        moyens    = [v for v in self.vulns if v['severity'] == 'MOYEN']

        for group, label, color_hex in [
            (critiques, 'Immédiat — Vulnérabilités CRITIQUES', '#e63946'),
            (eleves,    'Court terme — Risques ÉLEVÉS',        '#f4a261'),
            (moyens,    'Moyen terme — Risques MOYENS',        '#facc15'),
        ]:
            if group:
                story.append(Paragraph(f"<b>{label}</b>",
                    ps('rp', fontSize=10, fontName='Helvetica-Bold',
                       textColor=colors.HexColor(color_hex), spaceBefore=8, spaceAfter=4)))
                for v in group:
                    story.append(Paragraph(
                        f"› <b>{v['host']}:{v['port']}</b> — {v['reco']}",
                        ps('bp', fontSize=8.5, fontName='Helvetica', textColor=DARK,
                           spaceAfter=3, leading=13, leftIndent=12, firstLineIndent=-10)
                    ))

        # Footer
        story.append(Spacer(1, 20))
        story.append(HRFlowable(width="100%", thickness=0.5, color=GRAY, spaceAfter=6))
        story.append(Paragraph(
            f"Rapport généré le {end_time.strftime('%d/%m/%Y à %H:%M:%S')} — "
            f"Durée du scan : {duration}s — "
            f"Vincent Degbe — vdegbe.github.io — vdegbe12@gmail.com",
            ps('ft', fontSize=7.5, fontName='Helvetica', textColor=GRAY, alignment=TA_CENTER)
        ))

        doc.build(story)
        self.log(f"\n  [+] Rapport PDF généré : {output_path}", 'green')

    def run(self, output_pdf):
        self.banner()
        self.scan()
        self.analyze_vulns()
        self.print_summary()
        self.generate_pdf(output_pdf)
        print(c(f"\n[✓] Audit terminé ! Rapport : {output_pdf}\n", 'green'))


# ══════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(
        description='Network Audit Tool — Vincent Degbe (vdegbe.github.io)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples:
  python3 audit_reseau.py -t 192.168.1.1
  python3 audit_reseau.py -t 192.168.1.0/24 --ports 22,80,443,3389
  python3 audit_reseau.py -t 10.0.0.0/24 --output mon_rapport.pdf
        """
    )
    parser.add_argument('-t', '--target',  required=True,
                        help='Cible : IP, plage CIDR (ex: 192.168.1.0/24) ou hostname')
    parser.add_argument('-p', '--ports',   default=None,
                        help='Ports à scanner (ex: 22,80,443) — défaut: ports à risque courants')
    parser.add_argument('-o', '--output',  default=None,
                        help='Nom du fichier PDF de sortie (défaut: audit_<target>_<date>.pdf)')
    parser.add_argument('-q', '--quiet',   action='store_true',
                        help='Mode silencieux (moins de verbosité)')

    args = parser.parse_args()

    output = args.output or f"audit_{args.target.replace('/', '_').replace('.', '-')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"

    auditor = NetworkAuditor(
        target=args.target,
        ports=args.ports,
        verbose=not args.quiet
    )
    auditor.run(output)


if __name__ == '__main__':
    main()
