# Domain Analyzer - Installation Guide

Complete guide for installing and deploying the Domain Analyzer web application on Linux systems.

**Developed by [Utopia Tech](https://www.utopiats.com)**

---

## Table of Contents
1. [System Requirements](#system-requirements)
2. [Installation Methods](#installation-methods)
3. [Quick Start (Development)](#quick-start-development)
4. [Production Deployment](#production-deployment)
5. [Configuration](#configuration)
6. [Troubleshooting](#troubleshooting)
7. [Maintenance](#maintenance)

---

## System Requirements

### Minimum Requirements
- **OS:** Ubuntu 20.04+ / Debian 11+ / CentOS 8+ / RHEL 8+
- **RAM:** 2GB minimum (4GB recommended for production)
- **CPU:** 2 cores minimum
- **Disk:** 5GB free space
- **Python:** 3.8 or higher
- **Network:** Internet access for DNS queries and WHOIS lookups

### Required System Packages
```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv git
```

For RHEL/CentOS:
```bash
sudo yum install -y python3 python3-pip git
```

---

## Installation Methods

Choose one based on your needs:
- **Method 1:** Quick Start (Development/Testing)
- **Method 2:** Production with Systemd
- **Method 3:** Docker Deployment (Coming Soon)

---

## Method 1: Quick Start (Development)

### Step 1: Clone the Repository

```bash
# Clone from GitHub
git clone https://github.com/arvage/domain-dns-analyzer.git
cd domain-dns-analyzer
```

### Step 2: Create Virtual Environment

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate
```

### Step 3: Install Dependencies

```bash
# Upgrade pip
pip install --upgrade pip

# Install required packages
pip install -r requirements.txt
```

### Step 4: Run the Application

```bash
# Development server (port 8000)
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# Or use the provided script
python run_server.py
```

### Step 5: Access the Application

Open your browser and navigate to:
```
http://YOUR_SERVER_IP:8000
```

---

## Method 2: Production Deployment

### Step 1: Initial Setup

```bash
# Create application user
sudo useradd -m -s /bin/bash domainanalyzer

# Switch to application user
sudo su - domainanalyzer

# Clone repository
git clone https://github.com/arvage/domain-dns-analyzer.git
cd domain-dns-analyzer

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

### Step 2: Create Systemd Service

Exit from domainanalyzer user and create service file:

```bash
exit  # Exit from domainanalyzer user
sudo nano /etc/systemd/system/domainanalyzer.service
```

Add the following content:

```ini
[Unit]
Description=Domain Analyzer - Utopia Tech
After=network.target

[Service]
Type=simple
User=domainanalyzer
Group=domainanalyzer
WorkingDirectory=/home/domainanalyzer/domain-dns-analyzer
Environment="PATH=/home/domainanalyzer/domain-dns-analyzer/venv/bin"
ExecStart=/home/domainanalyzer/domain-dns-analyzer/venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4

Restart=always
RestartSec=10

# Security
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/home/domainanalyzer/domain-dns-analyzer/static/uploads

[Install]
WantedBy=multi-user.target
```

### Step 3: Enable and Start Service

```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable service to start on boot
sudo systemctl enable domainanalyzer

# Start the service
sudo systemctl start domainanalyzer

# Check status
sudo systemctl status domainanalyzer
```

### Step 4: Configure Nginx Reverse Proxy

```bash
# Install Nginx
sudo apt install -y nginx

# Create Nginx configuration
sudo nano /etc/nginx/sites-available/domainanalyzer
```

Add the following content:

```nginx
server {
    listen 80;
    server_name your-domain.com www.your-domain.com;

    client_max_body_size 10M;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Timeouts for long-running DNS queries
        proxy_connect_timeout 300;
        proxy_send_timeout 300;
        proxy_read_timeout 300;
    }

    location /static {
        alias /home/domainanalyzer/domain-dns-analyzer/static;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }
}
```

Enable the site:

```bash
# Create symbolic link
sudo ln -s /etc/nginx/sites-available/domainanalyzer /etc/nginx/sites-enabled/

# Test configuration
sudo nginx -t

# Reload Nginx
sudo systemctl reload nginx
```

### Step 5: Setup SSL with Let's Encrypt (Recommended)

```bash
# Install Certbot
sudo apt install -y certbot python3-certbot-nginx

# Obtain SSL certificate
sudo certbot --nginx -d your-domain.com -d www.your-domain.com

# Auto-renewal is configured automatically
# Test renewal
sudo certbot renew --dry-run
```

### Step 6: Configure Firewall

```bash
# Allow HTTP and HTTPS
sudo ufw allow 'Nginx Full'

# Enable firewall if not already enabled
sudo ufw enable

# Check status
sudo ufw status
```

---

## Configuration

### Environment Variables

Create a `.env` file in the project root:

```bash
nano /home/domainanalyzer/domain-dns-analyzer/.env
```

Add configuration:

```env
# Application Settings
APP_ENV=production
DEBUG=False
MAX_DOMAINS_PER_REQUEST=1000
MAX_FILE_SIZE_MB=10

# Rate Limiting
RATE_LIMIT_REQUESTS_PER_MINUTE=30

# CORS (Restrict in production)
ALLOWED_ORIGINS=https://your-domain.com,https://www.your-domain.com

# Logging
LOG_LEVEL=INFO
LOG_FILE=/home/domainanalyzer/domain-dns-analyzer/logs/app.log
```

Update `app/main.py` to load environment variables:

```python
from dotenv import load_dotenv
import os

load_dotenv()

# Use environment variables
ALLOWED_ORIGINS = os.getenv('ALLOWED_ORIGINS', '*').split(',')
```

Install python-dotenv:
```bash
pip install python-dotenv
```

### Security Hardening

1. **Restrict CORS Origins:**
   Edit `app/main.py` and change:
   ```python
   allow_origins=["https://your-domain.com"]
   ```

2. **Setup Log Rotation:**
   ```bash
   sudo nano /etc/logrotate.d/domainanalyzer
   ```
   
   Add:
   ```
   /home/domainanalyzer/domain-dns-analyzer/logs/*.log {
       daily
       rotate 14
       compress
       delaycompress
       notifempty
       create 0644 domainanalyzer domainanalyzer
       sharedscripts
   }
   ```

3. **Setup Automatic Updates:**
   ```bash
   sudo apt install unattended-upgrades
   sudo dpkg-reconfigure --priority=low unattended-upgrades
   ```

---

## Monitoring

### View Logs

```bash
# Application logs
sudo journalctl -u domainanalyzer -f

# Nginx logs
sudo tail -f /var/log/nginx/access.log
sudo tail -f /var/log/nginx/error.log
```

### Monitor Service Status

```bash
# Check service status
sudo systemctl status domainanalyzer

# Check if running
ps aux | grep uvicorn
```

### Monitor System Resources

```bash
# Install monitoring tools
sudo apt install htop iotop

# Monitor CPU/RAM
htop

# Monitor disk I/O
sudo iotop
```

---

## Maintenance

### Update Application

```bash
# Switch to application user
sudo su - domainanalyzer

# Navigate to project
cd domain-dns-analyzer

# Pull latest changes
git pull origin main

# Activate virtual environment
source venv/bin/activate

# Update dependencies
pip install -r requirements.txt --upgrade

# Exit user
exit

# Restart service
sudo systemctl restart domainanalyzer
```

### Backup

```bash
# Create backup script
sudo nano /home/domainanalyzer/backup.sh
```

Add content:
```bash
#!/bin/bash
BACKUP_DIR="/backup/domainanalyzer"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p $BACKUP_DIR

# Backup application
tar -czf $BACKUP_DIR/app_$DATE.tar.gz \
    /home/domainanalyzer/domain-dns-analyzer

# Keep only last 7 days
find $BACKUP_DIR -name "app_*.tar.gz" -mtime +7 -delete
```

Make executable and add to cron:
```bash
sudo chmod +x /home/domainanalyzer/backup.sh

# Add to crontab (daily at 2 AM)
sudo crontab -e
# Add line: 0 2 * * * /home/domainanalyzer/backup.sh
```

### Clean Old Reports

```bash
# Create cleanup script
sudo nano /home/domainanalyzer/cleanup.sh
```

Add content:
```bash
#!/bin/bash
# Delete reports older than 7 days
find /home/domainanalyzer/domain-dns-analyzer/static/uploads -name "*.xlsx" -mtime +7 -delete
```

Make executable and add to cron:
```bash
sudo chmod +x /home/domainanalyzer/cleanup.sh

# Add to crontab (daily at 3 AM)
sudo crontab -e
# Add line: 0 3 * * * /home/domainanalyzer/cleanup.sh
```

---

## Troubleshooting

### Service Won't Start

```bash
# Check service status
sudo systemctl status domainanalyzer

# Check logs
sudo journalctl -u domainanalyzer -n 50

# Common issues:
# 1. Port already in use
sudo lsof -i :8000

# 2. Permission issues
sudo chown -R domainanalyzer:domainanalyzer /home/domainanalyzer/domain-dns-analyzer

# 3. Missing dependencies
sudo su - domainanalyzer
cd domain-dns-analyzer
source venv/bin/activate
pip install -r requirements.txt
```

### DNS Queries Failing

```bash
# Test DNS resolution
nslookup example.com
dig example.com

# Check DNS servers
cat /etc/resolv.conf

# Test from Python
python3 -c "import dns.resolver; print(dns.resolver.resolve('google.com', 'A'))"
```

### High Memory Usage

```bash
# Check memory
free -h

# Reduce workers in systemd service
sudo nano /etc/systemd/system/domainanalyzer.service
# Change: --workers 2 (instead of 4)

# Restart
sudo systemctl daemon-reload
sudo systemctl restart domainanalyzer
```

### Permission Denied Errors

```bash
# Fix uploads directory permissions
sudo chown -R domainanalyzer:domainanalyzer /home/domainanalyzer/domain-dns-analyzer/static/uploads
sudo chmod 755 /home/domainanalyzer/domain-dns-analyzer/static/uploads
```

---

## Performance Tuning

### For High Traffic

1. **Increase workers:**
   ```bash
   sudo nano /etc/systemd/system/domainanalyzer.service
   # Change: --workers 8
   ```

2. **Enable Nginx caching:**
   ```nginx
   proxy_cache_path /var/cache/nginx levels=1:2 keys_zone=my_cache:10m max_size=1g inactive=60m;
   
   location / {
       proxy_cache my_cache;
       proxy_cache_valid 200 5m;
       # ... rest of config
   }
   ```

3. **Optimize DNS resolver:**
   Consider running local DNS cache (dnsmasq)

---

## Support

For issues or questions:
- **Website:** https://www.utopiats.com
- **Email:** support@utopiats.com
- **GitHub Issues:** https://github.com/arvage/domain-dns-analyzer/issues
- **GitHub Repository:** https://github.com/arvage/domain-dns-analyzer

---

## License

See [LICENSE](LICENSE) file for details.

---

**© 2025 Utopia Tech - All Rights Reserved**
