#!/usr/bin/env python3
"""
build_attack_feed.py
Runs daily via cron. Parses /var/log/honeypot/access.log,
deduplicates IPs, maps events/paths to display labels,
and writes /opt/kevsec-dashboard/data/attack_feed.json.
"""
import json, re, random, os, sys

LOG_FILE  = "/var/log/honeypot/access.log"
OUT_FILE  = "/opt/kevsec-dashboard/data/attack_feed.json"
MAX_IPS   = 500  # cap so the file stays small

_PATH_LABELS = {
    "wp-login":      "WP_BRUTEFORCE",
    "wp-admin":      "WP_BRUTEFORCE",
    "wordpress":     "WP_SCAN",
    "phpmyadmin":    "DB_PROBE",
    "admin":         "ADMIN_PANEL",
    "cpanel":        "CPANEL_PROBE",
    "jenkins":       "JENKINS_PROBE",
    "gitlab":        "GITLAB_PROBE",
    "grafana":       "GRAFANA_PROBE",
    "portainer":     "DOCKER_PROBE",
    "actuator":      "SPRING_PROBE",
    "solr":          "SOLR_PROBE",
    "telescope":     "LARAVEL_PROBE",
    "nagios":        "NAGIOS_PROBE",
    "zabbix":        "ZABBIX_PROBE",
    "jupyter":       "JUPYTER_PROBE",
    ".env":          "ENV_PROBE",
    ".git":          "GIT_PROBE",
    "xmlrpc":        "XMLRPC_BF",
    "backup":        "BACKUP_PROBE",
    "shell":         "SHELL_PROBE",
    "exec":          "SHELL_PROBE",
    "v1.41":         "DOCKER_API",
    "api/v1":        "K8S_API",
    "meta-data":     "AWS_IMDS",
    "vault":         "VAULT_PROBE",
    ".ssh":          "SSH_KEY_PROBE",
    "config.json":   "CONFIG_PROBE",
    "server-status": "APACHE_STATUS",
    "webmail":       "WEBMAIL_PROBE",
    "owa":           "OWA_PROBE",
    "exchange":      "OWA_PROBE",
}

_EVENT_TAGS = {
    "TARPIT":       "TRAPPED",
    "LOGIN_ATTEMPT":"BANNED",
    "TRAP_CREDS":   "BANNED",
    "ELASTIC":      "BANNED",
    "K8S":          "BANNED",
    "DOCKER":       "BANNED",
    "VAULT":        "BANNED",
    "SSH_KEY":      "BANNED",
    "AWS":          "BANNED",
    "ENV_FILE":     "TRAPPED",
    "GIT_CONFIG":   "TRAPPED",
    "BACKUP":       "TRAPPED",
    "SHELL":        "TRAPPED",
    "TELESCOPE":    "TRAPPED",
    "XMLRPC":       "TRAPPED",
    "CONFIG":       "TRAPPED",
    "SERVER_STATUS":"BANNED",
    "MONITORING":   "BANNED",
    "SUSPICIOUS":   "BLOCKED",
    "UNKNOWN":      "BLOCKED",
}

_IP_RE = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}$')

def classify(event, path):
    tag = "BLOCKED"
    for key, t in _EVENT_TAGS.items():
        if key in event.upper():
            tag = t
            break
    label = "BOT_CRAWL"
    for key, lbl in _PATH_LABELS.items():
        if key in path.lower():
            label = lbl
            break
    return tag, label

def build():
    if not os.path.exists(LOG_FILE):
        print(f"[build_attack_feed] log not found: {LOG_FILE}", file=sys.stderr)
        sys.exit(1)

    entries = []
    seen = set()
    with open(LOG_FILE) as f:
        for line in f:
            parts = [p.strip() for p in line.split("|")]
            if len(parts) < 4:
                continue
            _, event, ip, path = parts[0], parts[1], parts[2], parts[3]
            # skip IPv6 and already-seen IPs
            if not ip or not _IP_RE.match(ip) or ip in seen:
                continue
            seen.add(ip)
            tag, label = classify(event, path)
            entries.append({"ip": ip, "tag": tag, "type": label})
            if len(entries) >= MAX_IPS:
                break

    random.shuffle(entries)
    os.makedirs(os.path.dirname(OUT_FILE), exist_ok=True)
    with open(OUT_FILE, "w") as f:
        json.dump({"feed": entries, "count": len(entries)}, f)
    print(f"[build_attack_feed] wrote {len(entries)} IPs to {OUT_FILE}")

if __name__ == "__main__":
    build()
