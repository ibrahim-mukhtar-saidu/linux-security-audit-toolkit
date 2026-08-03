#!/bin/bash

echo "========================================"
echo " Linux Security Audit Toolkit"
echo "========================================"
echo

echo "Current User:"
whoami
echo

echo "Hostname:"
hostname
echo

echo "Kernel Version:"
uname -r
echo

echo "Running Services (first 10):"
systemctl list-units --type=service --state=running | head -10
echo

echo "Open Network Ports:"
ss -tuln
echo

echo "Logged-in Users:"
who
echo

echo "Recent Login Activity:"
last | head -5
echo

echo "Firewall Status:"
if command -v ufw > /dev/null; then
sudo ufw status
else
echo "UFW not installed"
fi

echo
echo "Audit Complete."
