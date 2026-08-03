#!/bin/bash

echo "================================="
echo " Linux Security Audit Toolkit"
echo "================================="

echo ""
echo "[+] Current User:"
whoami

echo ""
echo "[+] System Information:"
uname -a

echo ""
echo "[+] Logged in Users:"
who

echo ""
echo "[+] Running Services:"
systemctl --type=service --state=running

echo ""
echo "[+] Open Network Ports:"
ss -tuln

echo ""
echo "[+] Recent Login Activity:"
last -n 5

echo ""
echo "[+] Firewall Status:"
ufw status 2>/dev/null || echo "UFW not installed"

echo ""
echo "================================="
echo " Security Audit Completed"
echo "================================="
