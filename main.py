#!/usr/bin/env python3
"""
SSL Watcher Pro - Real Email Notifications 💀
Monitor SSL certs and get real email alerts with PDF attachments.
"""

from flask import Flask, render_template, request, jsonify, send_file
import ssl
import socket
from datetime import datetime
import threading
import time
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from typing import Dict, List, Any
import json
from io import BytesIO
import os

app = Flask(__name__)

# Configuration
SMTP_CONFIG = {
    'email': 'example@gmail.com',
    'password': '**** **** **** ****',
    'server': 'smtp.gmail.com',
    'port': 587
}

# Email list file
EMAIL_JSON_FILE = 'emails.json'

# In-memory storage
domains = []
notifications_sent = {}

def load_emails() -> List[str]:
    """Load email addresses from JSON file"""
    try:
        if os.path.exists(EMAIL_JSON_FILE):
            with open(EMAIL_JSON_FILE, 'r') as f:
                data = json.load(f)
                return data.get('emails', [])
        return []
    except Exception as e:
        print(f"Error loading emails: {e}")
        return []

def save_emails(emails: List[str]):
    """Save email addresses to JSON file"""
    try:
        with open(EMAIL_JSON_FILE, 'w') as f:
            json.dump({'emails': emails}, f, indent=2)
    except Exception as e:
        print(f"Error saving emails: {e}")

def get_ssl_info(domain: str) -> Dict[str, Any]:
    """Get SSL certificate information for a domain"""
    try:
        # Clean the domain
        clean_domain = domain.replace('http://', '').replace('https://', '').replace('www.', '').split('/')[0]
        
        context = ssl.create_default_context()
        with socket.create_connection((clean_domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=clean_domain) as ssock:
                cert = ssock.getpeercert()
                expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days_until_expiry = (expiry_date - datetime.now()).days
                
                return {
                    'domain': domain,
                    'clean_domain': clean_domain,
                    'issuer': dict(x[0] for x in cert['issuer']),
                    'valid_from': cert['notBefore'],
                    'valid_to': cert['notAfter'],
                    'expiry_date': expiry_date.strftime('%Y-%m-%d'),
                    'days_until_expiry': days_until_expiry,
                    'status': 'valid' if days_until_expiry > 0 else 'expired',
                    'error': None
                }
    except Exception as e:
        return {
            'domain': domain,
            'clean_domain': domain,
            'error': str(e),
            'status': 'error',
            'days_until_expiry': None
        }

def generate_pdf_report() -> BytesIO:
    """Generate PDF report of all domains"""
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib import colors
        
        # Get current SSL info
        ssl_info_list = [get_ssl_info(domain) for domain in domains]
        
        # Create PDF in memory
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []
        
        # Title
        title = Paragraph("SSL Certificate Report", styles['Title'])
        story.append(title)
        story.append(Spacer(1, 12))
        
        # Date
        date_str = Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal'])
        story.append(date_str)
        story.append(Spacer(1, 20))
        
        # Table data
        table_data = [['Domain', 'Status', 'Days Left', 'Expiry Date', 'Issuer']]
        
        for info in ssl_info_list:
            if info.get('error'):
                status = 'Error'
                days_left = 'N/A'
                expiry_date = 'N/A'
                issuer = 'N/A'
            else:
                status = 'Valid' if info.get('days_until_expiry', 0) > 0 else 'Expired'
                days_left = str(info.get('days_until_expiry', 'N/A'))
                expiry_date = info.get('expiry_date', 'N/A')
                issuer = info.get('issuer', {}).get('organizationName', 'Unknown')[:20] + '...'
            
            table_data.append([
                info['domain'][:20] + ('...' if len(info['domain']) > 20 else ''),
                status,
                days_left,
                expiry_date,
                issuer
            ])
        
        # Create table
        table = Table(table_data)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(table)
        story.append(Spacer(1, 20))
        
        # Summary
        valid_count = sum(1 for info in ssl_info_list if info.get('status') == 'valid')
        expiring_count = sum(1 for info in ssl_info_list if info.get('days_until_expiry', 999) <= 30)
        error_count = sum(1 for info in ssl_info_list if info.get('status') == 'error')
        
        summary = Paragraph(
            f"<b>Summary:</b> {valid_count} valid, {expiring_count} expiring, {error_count} errors",
            styles['Normal']
        )
        story.append(summary)
        
        # Build PDF
        doc.build(story)
        buffer.seek(0)
        return buffer
        
    except Exception as e:
        print(f"Error generating PDF: {e}")
        return None

def send_email_notification(ssl_info: Dict[str, Any], pdf_buffer: BytesIO = None):
    """Send email notification with PDF attachment"""
    try:
        days_left = ssl_info['days_until_expiry']
        emails = load_emails()
        
        if not emails:
            print("❌ No email addresses configured")
            return
        
        # Create message
        msg = MIMEMultipart()
        msg['Subject'] = f"🚨 SSL Alert: {ssl_info['domain']} expires in {days_left} days!"
        msg['From'] = SMTP_CONFIG['email']
        msg['To'] = ', '.join(emails)
        
        # Email body
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .alert {{ background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; }}
                .info {{ margin: 10px 0; }}
                .domain {{ font-size: 18px; font-weight: bold; color: #d63031; }}
            </style>
        </head>
        <body>
            <div class="alert">
                <h2>🚨 SSL Certificate Expiry Alert</h2>
                <div class="info"><span class="domain">{ssl_info['domain']}</span> will expire soon!</div>
            </div>
            
            <div class="info"><strong>Domain:</strong> {ssl_info['domain']}</div>
            <div class="info"><strong>Days until expiry:</strong> {days_left}</div>
            <div class="info"><strong>Expiry date:</strong> {ssl_info['expiry_date']}</div>
            <div class="info"><strong>Issuer:</strong> {ssl_info['issuer'].get('organizationName', 'Unknown')}</div>
            <div class="info"><strong>Checked at:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
            
            <br>
            <div><em>This is an automated message from SSL Watcher Pro 💀</em></div>
        </body>
        </html>
        """
        
        msg.attach(MIMEText(html, 'html'))
        
        # Attach PDF if available
        if pdf_buffer:
            pdf_attachment = MIMEApplication(pdf_buffer.getvalue())
            pdf_attachment.add_header('Content-Disposition', 'attachment', 
                                    filename=f"ssl_report_{ssl_info['domain']}.pdf")
            msg.attach(pdf_attachment)
        
        # Send email
        with smtplib.SMTP(SMTP_CONFIG['server'], SMTP_CONFIG['port']) as server:
            server.starttls()
            server.login(SMTP_CONFIG['email'], SMTP_CONFIG['password'])
            server.sendmail(SMTP_CONFIG['email'], emails, msg.as_string())
            
        print(f"📧 Email sent to {len(emails)} recipients for {ssl_info['domain']}")
        
    except Exception as e:
        print(f"❌ Failed to send email: {e}")

def check_domains():
    """Check all domains and send notifications if needed"""
    for domain in domains:
        info = get_ssl_info(domain)
        
        # Send notifications for expiring certs
        if info['status'] == 'valid' and info['days_until_expiry'] <= 30:
            if domain not in notifications_sent or notifications_sent[domain] != info['days_until_expiry']:
                # Generate PDF report for this domain
                pdf_buffer = generate_pdf_report()
                send_email_notification(info, pdf_buffer)
                notifications_sent[domain] = info['days_until_expiry']

def background_checker():
    """Run SSL checks in the background"""
    while True:
        if domains:
            check_domains()
        time.sleep(3600)  # Check every hour

# Start background thread
checker_thread = threading.Thread(target=background_checker, daemon=True)
checker_thread.start()

@app.route('/')
def index():
    """Main dashboard"""
    ssl_info_list = []
    for domain in domains:
        ssl_info_list.append(get_ssl_info(domain))
    
    # Sort by days until expiry (soonest first)
    ssl_info_list.sort(key=lambda x: x.get('days_until_expiry', 999) if x.get('days_until_expiry') else 999)
    
    # Stats for dashboard
    stats = {
        'total': len(ssl_info_list),
        'valid': sum(1 for x in ssl_info_list if x.get('status') == 'valid'),
        'expiring': sum(1 for x in ssl_info_list if x.get('days_until_expiry', 999) <= 30),
        'errors': sum(1 for x in ssl_info_list if x.get('status') == 'error')
    }
    
    # Load emails for display
    emails = load_emails()
    
    return render_template('index.html', domains=domains, ssl_info=ssl_info_list, stats=stats, emails=emails)

@app.route('/add-domain', methods=['POST'])
def add_domain():
    """Add a domain to monitor"""
    domain = request.form.get('domain', '').strip()
    if domain and domain not in domains:
        domains.append(domain)
        # Immediately check and notify if expiring
        info = get_ssl_info(domain)
        if info.get('status') == 'valid' and info.get('days_until_expiry', 999) <= 30:
            pdf_buffer = generate_pdf_report()
            send_email_notification(info, pdf_buffer)
            notifications_sent[domain] = info['days_until_expiry']
    return jsonify({'success': True, 'domains': domains})

@app.route('/remove-domain', methods=['POST'])
def remove_domain():
    """Remove a domain from monitoring"""
    domain = request.form.get('domain', '').strip()
    if domain in domains:
        domains.remove(domain)
        if domain in notifications_sent:
            del notifications_sent[domain]
    return jsonify({'success': True, 'domains': domains})

@app.route('/add-email', methods=['POST'])
def add_email():
    """Add an email address to notification list"""
    email = request.form.get('email', '').strip().lower()
    emails = load_emails()
    if email and email not in emails:
        emails.append(email)
        save_emails(emails)
    return jsonify({'success': True, 'emails': emails})

@app.route('/remove-email', methods=['POST'])
def remove_email():
    """Remove an email address from notification list"""
    email = request.form.get('email', '').strip().lower()
    emails = load_emails()
    if email in emails:
        emails.remove(email)
        save_emails(emails)
    return jsonify({'success': True, 'emails': emails})

@app.route('/check-now', methods=['POST'])
def check_now():
    """Force immediate check of all domains"""
    results = []
    for domain in domains:
        results.append(get_ssl_info(domain))
    return jsonify({'success': True, 'results': results})

@app.route('/export-pdf')
def export_pdf():
    """Export PDF report"""
    pdf_buffer = generate_pdf_report()
    if pdf_buffer:
        return send_file(
            pdf_buffer,
            as_attachment=True,
            download_name=f"ssl_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
            mimetype='application/pdf'
        )
    return jsonify({'error': 'Failed to generate PDF'}), 500

@app.route('/test-email')
def test_email():
    """Test email functionality"""
    try:
        test_info = {
            'domain': 'example.com',
            'days_until_expiry': 15,
            'expiry_date': '2024-12-31',
            'issuer': {'organizationName': 'Test Issuer'}
        }
        pdf_buffer = generate_pdf_report()
        send_email_notification(test_info, pdf_buffer)
        return jsonify({'success': True, 'message': 'Test email sent to all configured addresses'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    print("🚀 SSL Watcher Pro starting on http://localhost:5000")
    print("📧 Real email notifications configured")
    print("📊 PDF reporting with attachments")
    print("📋 Email list management enabled")
    
    # Create emails.json if it doesn't exist
    if not os.path.exists(EMAIL_JSON_FILE):
        save_emails([])
        print("📝 Created emails.json file")
    
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
