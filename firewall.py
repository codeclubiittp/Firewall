from systemd import journal
import re
import pyufw as ufw

j = journal.Reader()
j.this_boot()
j.log_level(journal.LOG_INFO)
j.add_match(_SYSTEMD_UNIT="ssh.service")
ip_add = set()

for attempt in j:
    message = attempt['MESSAGE']
    if message.startswith('Failed'):
        ip_add.update(re.findall(r'\b(?:\d{1,3}\.)}3|\d{1,3}\b', message))

for ip in ip_add:
    ufw.add("deny from " + ip)