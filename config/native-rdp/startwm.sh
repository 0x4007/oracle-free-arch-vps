#!/bin/sh
# Use existing Xfce in the RDP user's session; do not alter VNC or global DPI.
exec /usr/bin/dbus-run-session -- /usr/bin/startxfce4
