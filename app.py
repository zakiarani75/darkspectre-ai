import os, json, threading, uuid, subprocess, re, socket
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file
from flask_cors import CORS

app = Flask(__name__)
app.secret_key = 'darkspectre-ai-2026'
CORS(app)

# Config
app.config['REPORTS_FOLDER'] = 'reports'
app.config['SCREENSHOTS_FOLDER'] = 'screenshots'
os.makedirs(app.config['REPORTS_FOLDER'], exist_ok=True)
os.makedirs(app.config['SCREENSHOTS_FOLDER'], exist_ok=True)

# In-memory storage
scans_db = {}
active_scans = {}

# ============ ROUTES ============
@app.route('/')
def index(): return render_template('index.html')

@app.route('/scan')
def scan_page(): return render_template('scan.html')

@app.route('/dashboard')
def dashboard(): return render_template('dashboard.html')

@app.route('/ai-analysis')
def ai_analysis(): return render_template('ai_analysis.html')

@app.route('/reports')
def reports(): return render_template('reports.html')

@app.route('/history')
def history(): return render_template('history.html', scans=list(scans_db.values()))

# ============ API: START SCAN ============
@app.route('/api/start-scan', methods=['POST'])
def start_scan():
    data = request.get_json()
    target = data.get('target', '').strip()
    if not target: return jsonify({'error': 'Target required'}), 400
    
    scan_id = str(uuid.uuid4())[:8]
    thread = threading.Thread(target=run_scan_bg, args=(scan_id, target))
    thread.daemon = True
    thread.start()
    return jsonify({'scan_id': scan_id, 'status': 'started'})

def run_scan_bg(scan_id, target):
    active_scans[scan_id] = {'target': target, 'status': 'running', 'progress': 0, 'message': 'Starting...'}
    try:
        clean_target = re.sub(r'https?://', '', target).split('/')[0]
        
        # STEP 1: Nmap
        active_scans[scan_id]['progress'] = 15
        active_scans[scan_id]['message'] = '🔍 Running Nmap port scan...'
        nmap_ports, nmap_services, nmap_vulns = run_nmap(clean_target)
        
        # STEP 2: WhatWeb
        active_scans[scan_id]['progress'] = 30
        active_scans[scan_id]['message'] = '🌐 Detecting web technologies...'
        techs = run_whatweb(clean_target)
        
        # STEP 3: Nikto
        active_scans[scan_id]['progress'] = 45
        active_scans[scan_id]['message'] = '🔎 Running Nikto web scan...'
        nikto_findings = run_nikto(clean_target)
        
        # STEP 4: Nuclei
        active_scans[scan_id]['progress'] = 60
        active_scans[scan_id]['message'] = '⚡ Running Nuclei template scanner...'
        nuclei_vulns = run_nuclei(clean_target)
        
        # STEP 5: AI Analysis
        active_scans[scan_id]['progress'] = 80
        active_scans[scan_id]['message'] = '🧠 Analyzing with AI...'
        
        all_ports = list(set(nmap_ports))
        all_services = list(set(nmap_services))
        all_vulns = nmap_vulns + nikto_findings + nuclei_vulns
        
        ai_results = ai_analyze(all_vulns, all_ports, all_services)
        
        # Generate report
        active_scans[scan_id]['progress'] = 90
        active_scans[scan_id]['message'] = '📄 Generating report...'
        
        results = {
            'target': target, 'scan_id': scan_id,
            'timestamp': datetime.now().isoformat(),
            'ports': all_ports, 'services': all_services,
            'vulnerabilities': all_vulns,
            'ai_analysis': ai_results,
            'technologies': techs,
            'risk_level': ai_results['risk_level'],
            'vulnerability_count': ai_results['total_vulnerabilities'],
            'recommendations': ai_results['recommendations']
        }
        
        # Save
        scans_db[scan_id] = results
        generate_html_report(results)
        
        active_scans[scan_id]['status'] = 'completed'
        active_scans[scan_id]['progress'] = 100
        active_scans[scan_id]['message'] = '✅ Scan complete!'
        active_scans[scan_id]['results'] = results
    except Exception as e:
        active_scans[scan_id]['status'] = 'error'
        active_scans[scan_id]['message'] = f'❌ Error: {str(e)}'

# ============ SCANNING FUNCTIONS ============
def run_nmap(target):
    ports, services, vulns = [], [], []
    try:
        out = subprocess.check_output(['nmap', '-sV', '--top-ports', '50', '-T4', target], timeout=180).decode()
        for line in out.split('\n'):
            m = re.match(r'^(\d+)/tcp\s+open\s+(\S+)', line)
            if m:
                p, s = int(m.group(1)), m.group(2)
                ports.append(p); services.append(s)
                if s.lower() in ['ftp','telnet']:
                    vulns.append({'name': f'Port {p} {s.upper()}', 'severity': 'High', 'type': 'Insecure Service',
                        'description': f'{s.upper()} is insecure', 'remediation': f'Disable {s.upper()} use SSH'})
        os_match = re.search(r'OS details:\s*(.+?)(?:\n|$)', out)
        if os_match: services.append(f"OS: {os_match.group(1).strip()}")
    except: pass
    return ports, services, vulns

def run_whatweb(target):
    try:
        out = subprocess.check_output(['whatweb', target, '--log-verbose=-'], timeout=30).decode()
        return [line.strip() for line in out.split('\n') if line.strip()][:5]
    except: return []

def run_nikto(target):
    findings = []
    try:
        out = subprocess.check_output(['nikto', '-h', target, '-ssl', '-Tuning', '123'], timeout=180).decode()
        for line in out.split('\n'):
            if '+ ' in line:
                findings.append({'name': 'Nikto Finding', 'severity': 'Medium', 'type': 'Web Issue',
                    'description': line.split('+ ',1)[1][:200], 'remediation': 'Review server configuration'})
    except: pass
    return findings

def run_nuclei(target):
    vulns = []
    try:
        out = subprocess.check_output(['nuclei', '-u', f'http://{target}', '-json', '-silent'], timeout=180).decode()
        for line in out.split('\n'):
            if not line.strip(): continue
            try:
                d = json.loads(line)
                info = d.get('info',{})
                vulns.append({'name': info.get('name','Finding'), 'severity': info.get('severity','medium').title(),
                    'type': 'Template', 'description': info.get('description','')[:200],
                    'remediation': info.get('remediation','Apply patch')})
            except: pass
    except: pass
    return vulns

# ============ AI ANALYSIS ENGINE ============
def ai_analyze(vulns, ports, services):
    dist = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
    recs = []
    high_risk_ports = {21:'FTP',23:'Telnet',135:'MSRPC',139:'NetBIOS',445:'SMB',3389:'RDP',3306:'MySQL',5432:'PostgreSQL',5900:'VNC',6379:'Redis',27017:'MongoDB'}
    medium_ports = {22:'SSH',25:'SMTP',53:'DNS',80:'HTTP',110:'POP3',143:'IMAP',443:'HTTPS'}
    
    # Classify vulns
    for v in vulns:
        sev = v.get('severity','Medium')
        if sev in dist: dist[sev] += 1
        recs.append({
            'vulnerability': v.get('name','Issue'),
            'severity': sev,
            'recommendation': v.get('remediation','Review and patch'),
            'priority': 'Immediate' if sev in ['Critical','High'] else 'Scheduled'
        })
    
    # Port analysis
    for p in ports:
        if p in high_risk_ports:
            dist['High'] += 1
            recs.append({'vulnerability':f'Port {p} ({high_risk_ports[p]})','severity':'High',
                'recommendation':f'Close port {p} if not needed', 'priority':'Immediate'})
        elif p in medium_ports:
            dist['Medium'] += 1
    
    # Score
    score = dist['Critical']*25 + dist['High']*15 + dist['Medium']*8 + dist['Low']*3
    score = min(100, score)
    
    risk = 'Critical' if score>=70 else 'High' if score>=40 else 'Medium' if score>=15 else 'Low'
    total = sum(dist.values())
    
    summary = f"Scan complete. Risk: {risk}. Found {total} issues. "
    if dist['Critical']: summary += f"{dist['Critical']} critical. "
    if dist['High']: summary += f"{dist['High']} high. "
    summary += f"Security score: {100-score}/100."
    
    return {
        'risk_level': risk, 'risk_score': score, 'security_score': 100-score,
        'total_vulnerabilities': total, 'vulnerability_distribution': dist,
        'recommendations': recs, 'summary': summary,
        'critical_findings': [r['vulnerability'] for r in recs if r['severity']=='Critical']
    }

# ============ REPORT GENERATION ============
def generate_html_report(results):
    sid = results['scan_id']
    target = results['target']
    risk = results['risk_level']
    vuln_count = results['vulnerability_count']
    recs = results.get('recommendations',[])
    ports = results.get('ports',[])
    services = results.get('services',[])
    ai = results.get('ai_analysis',{})
    
    html = f'''<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>DARKSPECTRE AI Report: {target}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Segoe UI',sans-serif;background:#0a0a1a;color:#e0e0e0}}
.container{{max-width:1200px;margin:0 auto;padding:20px}}
.header{{background:linear-gradient(135deg,#1a0533,#0d0221);padding:40px;border-bottom:3px solid #ff2d95;text-align:center}}
.header h1{{color:#ff2d95;font-size:2.5em}}
.header p{{color:#b388ff}}
.badge{{display:inline-block;padding:8px 25px;border-radius:20px;font-weight:bold;margin:10px 5px}}
.badge-critical{{background:#ff1744;color:#fff}}
.badge-high{{background:#ff9100;color:#000}}
.badge-medium{{background:#ffea00;color:#000}}
.badge-low{{background:#00e676;color:#000}}
.section{{background:linear-gradient(135deg,#1a0533,#12012e);border:1px solid #ff2d95;border-radius:15px;padding:25px;margin:20px 0}}
.section h2{{color:#ff2d95;margin-bottom:20px;border-bottom:1px solid #333;padding-bottom:10px}}
.vuln-item{{background:rgba(255,255,255,0.05);padding:15px;margin:10px 0;border-radius:10px;border-left:4px solid #ff2d95}}
.vuln-item.sev-critical{{border-left-color:#ff1744}}
.vuln-item.sev-high{{border-left-color:#ff9100}}
.vuln-item.sev-medium{{border-left-color:#ffea00}}
.vuln-item.sev-low{{border-left-color:#00e676}}
.vuln-item h3{{color:#b388ff}}
.remediation{{background:rgba(0,230,118,0.1);padding:12px;border-radius:8px;margin-top:10px;border-left:3px solid #00e676}}
.remediation strong{{color:#00e676}}
.stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:15px;margin:20px 0}}
.stat-card{{background:rgba(255,255,255,0.05);padding:20px;border-radius:12px;text-align:center}}
.stat-card h3{{color:#ff2d95;font-size:2em}}
.footer{{text-align:center;padding:20px;color:#555}}
</style></head><body>
<div class="header">
<h1>⚡ DARKSPECTRE AI</h1>
<p>Automated Cybersecurity Intelligence Report</p>
<span class="badge badge-{risk.lower()}">{risk.upper()}</span>
<p style="margin-top:15px;color:#b388ff">Target: {target}</p>
<p style="color:#888">Report ID: {sid} | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
</div>
<div class="container">
<div class="stats">
<div class="stat-card"><h3>{vuln_count}</h3><p>Vulnerabilities</p></div>
<div class="stat-card"><h3>{risk}</h3><p>Risk Level</p></div>
<div class="stat-card"><h3>{len(ports)}</h3><p>Open Ports</p></div>
<div class="stat-card"><h3>{len(services)}</h3><p>Services</p></div>
</div>'''
    
    # Vulnerabilities
    if recs:
        html += '<div class="section"><h2>🔴 Vulnerabilities & Recommendations</h2>'
        for r in recs:
            sev = r.get('severity','Medium').lower()
            html += f'<div class="vuln-item sev-{sev}"><h3>{r.get("vulnerability","Issue")}</h3>'
            html += f'<p>Severity: <strong>{r.get("severity","Medium")}</strong></p>'
            html += f'<div class="remediation"><p><strong>Fix:</strong> {r.get("recommendation","N/A")}</p></div></div>'
        html += '</div>'
    
    # AI Summary
    if ai:
        html += f'<div class="section"><h2>🧠 AI Analysis</h2><p style="line-height:1.8">{ai.get("summary","")}</p>'
        html += '<div class="stats">'
        for sev, cnt in ai.get('vulnerability_distribution',{}).items():
            html += f'<div class="stat-card"><h3>{cnt}</h3><p>{sev}</p></div>'
        html += '</div></div>'
    
    # Ports
    if ports:
        html += '<div class="section"><h2>🔌 Open Ports</h2><ul>'
        for p in sorted(set(ports)):
            html += f'<li style="padding:5px 0">Port {p}/tcp</li>'
        html += '</ul></div>'
    
    html += '<div class="footer"><p>DARKSPECTRE AI — Cybersecurity Intelligence<br>Author: Zakia Rani</p></div></div></body></html>'
    
    fp = os.path.join(app.config['REPORTS_FOLDER'], f'report_{sid}.html')
    with open(fp,'w',encoding='utf-8') as f: f.write(html)

# ============ API: STATUS / RESULTS / HISTORY ============
@app.route('/api/scan-status/<sid>')
def scan_status(sid):
    if sid in active_scans:
        return jsonify(active_scans[sid])
    if sid in scans_db:
        return jsonify({'status':'completed','progress':100,'message':'Done','target':scans_db[sid]['target']})
    return jsonify({'error':'Not found'}),404

@app.route('/api/scan-results/<sid>')
def scan_results(sid):
    if sid in scans_db: return jsonify(scans_db[sid])
    return jsonify({'error':'Not found'}),404

@app.route('/api/all-scans')
def all_scans():
    return jsonify([{'scan_id':s,'target':d['target'],'timestamp':d['timestamp'],
        'risk_level':d['risk_level'],'vulnerabilities':d['vulnerability_count']} for s,d in scans_db.items()])

@app.route('/api/analytics')
def analytics():
    total = len(scans_db)
    risks = {'Low':0,'Medium':0,'High':0,'Critical':0}
    vulns = 0; ports_set = set(); services_list = []
    for d in scans_db.values():
        r = d.get('risk_level','Low')
        if r in risks: risks[r] += 1
        vulns += d.get('vulnerability_count',0)
        for p in d.get('ports',[]): ports_set.add(p)
        services_list.extend(d.get('services',[]))
    return jsonify({'total_scans':total,'total_vulnerabilities':vulns,'risk_distribution':risks,'unique_ports':len(ports_set)})

@app.route('/api/live-analytics')
def live_analytics():
    risks = {'Low':0,'Medium':0,'High':0,'Critical':0}
    timeline = []
    for s, d in scans_db.items():
        r = d.get('risk_level','Low')
        if r in risks: risks[r] += 1
        timeline.append({'date':d['timestamp'][:10],'vulnerabilities':d['vulnerability_count'],'target':d['target'][:20]})
    return jsonify({'risk_distribution':risks,'timeline':timeline[-7:],'total_scans':len(scans_db)})

@app.route('/api/download-report/<sid>/<fmt>')
def download_report(sid, fmt):
    ext = 'html' if fmt == 'html' else 'html'
    fp = os.path.join(app.config['REPORTS_FOLDER'], f'report_{sid}.{ext}')
    if os.path.exists(fp):
        return send_file(fp, as_attachment=True, download_name=f'DARKSPECTRE_Report_{sid}.{ext}')
    return jsonify({'error':'Not found'}),404

@app.route('/api/delete-scan/<sid>', methods=['DELETE'])
def delete_scan(sid):
    if sid in scans_db: del scans_db[sid]
    if sid in active_scans: del active_scans[sid]
    return jsonify({'message':'Deleted'})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
