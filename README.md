# Linux Hardening Lab

I built this lab to get hands-on experience with Linux security and understand how different controls work in practice. I wanted to go beyond installing tools and following commands by testing what they actually allow or block, investigating the logs, and learning how to fix problems without disabling the protection.

I set up a Rocky Linux server and used Kali Linux as the test machine. I started by checking which services were running and disabling the ones the server did not need. I then tested firewall rules, investigated a SELinux access denial, and configured Fail2Ban to temporarily block repeated failed SSH login attempts.

For each test, I checked the results in the terminal and relevant logs, then verified that normal access could be restored. This write-up explains
the changes I made, what happened during testing, and the limits of what I demonstrated.

## Overview

I worked through the lab one change at a time so I could understand what each change affected. Installing a tool or seeing a service marked as running was only the starting point. I also needed to check what happened when I tested it. For each part of the lab, I followed the same approach:

1. Check the current settings and confirm what was working.
2. Make a specific change.
3. Test it and record the result.
4. Check the relevant settings and logs to understand what happened.
5. Where the test deliberately blocked access, check that access could be restored.

The work covered disabling unnecessary services, allowing HTTP access from the Kali machine through a specific firewall rule, testing how SELinux file labels affect Apache's access to web content, and using Fail2Ban to temporarily restrict SSH access after repeated failed logins.

## Lab environment and scope

All testing was limited to owned virtual machines.

| Component | Role or recorded configuration |
| --- | --- |
| Rocky Linux | 9.8 (Blue Onyx), target server |
| Kali Linux | Authorised test client |
| VMware | Virtualisation and host-only test network |
| Rocky hostname | `linux-hardening-01` |
| Rocky interface/address | `ens160`, `192.168.42.128/24` during controlled tests |
| Kali interface/address | `eth0`, `192.168.42.129/24` during controlled tests |
| Apache | Static HTTP test service |
| firewalld | Network-access restrictions |
| SELinux | Process and file-type enforcement |
| Fail2Ban | Authentication-failure detection and temporary SSH restrictions |

The addresses were observed values, not a documented static-address plan. Temporary NAT connectivity was used for package downloads. Host-only networking included the host; it was not isolation from the host itself. VMware console access remained available for administration during connection-restriction tests.

Suricata preparation was later separated into another project. No IDS detection, SQL injection, XSS protection, or successful exploitation is claimed here.

## 1. Establishing the baseline

Before making changes, I checked the operating system, account, hostname, interfaces, SELinux mode, firewall configuration, and listening sockets.

```bash
cat /etc/rocky-release
hostnamectl
whoami
ip -br address
getenforce
sudo firewall-cmd --get-active-zones
sudo firewall-cmd --zone=public --list-all
sudo ss -tulnp
```

The baseline showed SELinux enforcing and the `public` firewall zone associated with `ens160`. SSH listened on TCP 22, Avahi had UDP 5353 sockets, and CUPS listened on loopback TCP 631. The firewall service list contained `cockpit`, `dhcpv6-client`, and `ssh`.

I distinguished firewall allowances from listening applications. An allowance does not prove an application is running, and a listening socket alone does not establish remote reachability. The baseline socket snapshot did not show a TCP 9090 listener despite the Cockpit allowance.

## 2. Reducing unnecessary services

Automatic discovery and printing were not required for the server's intended role. I stopped and disabled the relevant services and activation units:

```bash
sudo systemctl disable --now avahi-daemon.socket avahi-daemon.service
sudo systemctl disable --now cups.socket cups.path cups.service
```

After reboot, I checked the unit states and listening sockets:

```bash
systemctl is-active avahi-daemon.service avahi-daemon.socket cups.service cups.socket cups.path
sudo ss -tulnp
```

All five targeted units remained inactive. The Avahi UDP 5353 and CUPS TCP 631 sockets were absent, while SSH remained listening. CUPS had originally been loopback-bound: removing it reduced unnecessary functionality, not a demonstrated remotely exposed printing service.

> Screenshot to add: post-reboot Avahi/CUPS unit states and the corresponding socket check.

I also removed the unused Cockpit allowance from runtime and permanent firewall configurations:

```bash
sudo firewall-cmd --zone=public --remove-service=cockpit
sudo firewall-cmd --permanent --zone=public --remove-service=cockpit
sudo firewall-cmd --zone=public --list-services
sudo firewall-cmd --permanent --zone=public --list-services
```

Both service lists then returned `dhcpv6-client ssh`. This removed a firewall allowance; it did not uninstall Cockpit.

## 3. Testing source-specific HTTP access

Apache served a static page for the access-control experiments. The first HTTP request from Kali failed. Before changing the firewall, I confirmed Apache was listening on port 80 and checked the active zone:

```bash
sudo ss -lntp 'sport = :80'
sudo firewall-cmd --get-active-zones
```

I added a runtime HTTP allowance for Kali's address rather than a general HTTP service allowance:

```bash
sudo firewall-cmd --zone=public --add-rich-rule='rule family="ipv4" source address="192.168.42.129/32" service name="http" accept'
```

Repeating the request from Kali returned `HTTP/1.1 200 OK` and the intended page:

```bash
curl --noproxy "*" --max-time 5 -i http://192.168.42.128/
```

The inspected runtime zone contained the source-specific rule without a general HTTP service or explicit port allowance.

> Screenshot to add: public-zone runtime configuration containing the Kali-specific HTTP rule, accompanied by the successful Kali request.

This demonstrated access from the designated client. An unapproved source was not tested. Final permanent-rule and reload evidence remains incomplete, so I do not claim independently verified persistence for this HTTP allowance. The rule also depends on Kali retaining the specified address.

## 4. SELinux enforcement and recovery

The record contains two separate exercises: an initial loopback test using `selinux-test.html` with an intentional `samba_share_t` label, and a later Kali-to-Rocky test using `selinux-probe.txt` with an intentional `default_t` label. They are not one combined experiment. The remote probe is the main sequence below.

### Establish normal access

I created harmless test content, set permissions to `0644`, and applied the policy-defined label:

```bash
printf '%s\n' 'SELinux controlled access test.' | sudo tee /var/www/html/selinux-probe.txt
sudo chmod 0644 /var/www/html/selinux-probe.txt
sudo restorecon -v /var/www/html/selinux-probe.txt
```

The probe had type `httpd_sys_content_t`, Apache ran in `httpd_t`, and SELinux was enforcing. Kali retrieved the probe successfully with `200 OK`.

### Introduce and investigate a controlled mismatch

I changed only the probe's SELinux type:

```bash
sudo chcon -t default_t /var/www/html/selinux-probe.txt
```

The same HTTP request then returned `403 Forbidden`, while ordinary permissions remained `0644`. I investigated rather than assume the response proved SELinux was responsible:

```bash
getenforce
ls -lZ /var/www/html/selinux-probe.txt
sudo ausearch -m AVC -c httpd -ts recent -i
```

| Audit field | Recorded result |
| --- | --- |
| Process/source domain | `httpd`, `httpd_t` |
| Target | `/var/www/html/selinux-probe.txt` |
| Target type | `default_t` |
| Denied permission | `getattr` |
| System call/result | `newfstatat`, `EACCES` |
| Enforcement | `permissive=0` |

> Screenshot to add: the matching AVC records, probe label, and enforcing state.

These records tied the failure to enforced SELinux metadata-access denials against the exact probe. The recorded permission was `getattr`, not a file-content read. The two audit events were denied operations, not evidence of two separate attacks.

### Restore access without weakening SELinux

```bash
sudo restorecon -v /var/www/html/selinux-probe.txt
ls -lZ /var/www/html/selinux-probe.txt
getenforce
```

The type returned to `httpd_sys_content_t`. Kali again received `200 OK` and the original text, and final checks confirmed SELinux remained enforcing.

> Screenshot to add: recovered HTTP response and restored file context with SELinux enforcing.

The verified sequence was normal access, an audited denial after intentional mislabelling, then recovery through correct labelling. No permissive-mode workaround or custom allow policy was required.

## 5. Fail2Ban SSH protection

The SSH baseline showed port 22, password and public-key authentication enabled, keyboard-interactive authentication disabled, `PermitRootLogin` reported as `without-password`, and `MaxAuthTries` set to six per connection. Root password login was prohibited, but all root SSH access was not disabled. The per-connection limit was separate from Fail2Ban's source-based ban mechanism.

Fail2Ban was installed with firewalld integration and systemd journal support. The lab configuration was:

```ini
[sshd]
enabled = true
backend = systemd
filter = sshd
port = 22
banaction = firewallcmd-rich-rules[zone=public]
maxretry = 5
findtime = 10m
bantime = 5m
ignoreip = 127.0.0.1/8 ::1
```

This block is reconstructed from the recorded setup, not a current-state export. Runtime queries confirmed `maxretry = 5`, `findtime = 600`, and `bantime = 300`.

### Detect one controlled failure

After checking the server's host-key fingerprint and starting counters, I generated a deliberately incorrect password attempt from Kali with one password prompt:

```bash
ssh -o HostKeyAlgorithms=ssh-ed25519 \
    -o PreferredAuthentications=password \
    -o PubkeyAuthentication=no \
    -o NumberOfPasswordPrompts=1 \
    -o ConnectTimeout=5 roc@192.168.42.128
```

I inspected the server-side evidence:

```bash
sudo journalctl -u sshd --since "5 minutes ago" --no-pager
sudo fail2ban-client status sshd
```

The journal recorded a failed password for `roc` from `192.168.42.129`. Fail2Ban reported one detected failure and no active ban. A separate pre-authentication timeout was not treated as another confirmed password failure.

> Screenshot to add: matching SSH journal event and Fail2Ban's single-failure status.

### Verify enforcement

After further bounded manual failures, Fail2Ban listed Kali as banned. The firewall contained:

```text
rule family="ipv4" source address="192.168.42.129" port port="22" protocol="tcp" reject type="icmp-port-unreachable"
```

A fresh Kali SSH connection returned:

```text
ssh: connect to host 192.168.42.128 port 22: Connection refused
```

> Screenshot to add: active ban, corresponding firewall rule, and Kali's refused connection.

The banned-IP entry, matching firewall rule, and fresh connection result together demonstrated enforcement. The restriction targeted SSH from Kali, not every service. The separate HTTP allowance remained configured; HTTP availability during the ban was not tested.

The cumulative `Total failed` value was six. That does not change the configured threshold of five or establish the exact sequence of threshold crossing.

### Verify automatic expiry and recovery

After automatic expiry, the jail showed no active bans, the SSH rejection rule was absent, and the unrelated HTTP allowance remained. A legitimate SSH login succeeded, with no manual unban reported.

> Screenshot to add: post-expiry jail/firewall checks and the successful legitimate SSH login.

The configured ban duration was 300 seconds. Exact elapsed duration was not measured using timestamped Ban and Unban records.

## Results

| Area | Demonstrated result |
| --- | --- |
| Service reduction | Targeted Avahi/CUPS units and sockets remained inactive after reboot |
| Firewall | Cockpit allowance removed; Kali-specific runtime HTTP access demonstrated |
| SELinux | Enforced denial correlated with audit evidence; correct labelling restored access |
| Fail2Ban | Detection, SSH restriction, connection rejection, automatic removal, and recovery observed |

## Limitations and follow-up

- This was a controlled lab, not a comprehensive security audit or production-hardening certification.
- Permanent HTTP-rule and reload evidence remains incomplete; an unapproved HTTP source was not tested.
- Exact Fail2Ban ban duration and a complete reboot-and-retest of its enforcement were not measured.
- The recorded Apache ServerName warning has no completed correction documented.
- Later Suricata preparation left Rocky reporting a NAT address in the working record. The final live topology must be checked rather than assumed to match the earlier host-only tests.
- Suricata was installed during later preparation, but live monitoring was not verified and is outside this project's completed scope. Its final service and boot-enablement state need a separate closeout check.
- IPv6 policy coverage, distributed authentication attacks, and web-application vulnerabilities were not comprehensively assessed.

## Lessons learned

- Inventory services, activation units, sockets, and bindings before deciding what to remove.
- Separate runtime behaviour from persistence claims.
- Correlate an HTTP failure with the exact process, file, and audit event.
- Correct the misconfiguration rather than disabling the security control.
- Treat detection, enforcement, and recovery as separate validation steps.
- Preserve console administration during deliberate connection restrictions.
- Make conclusions no broader than the evidence supports.

## Evidence and publication status

This narrative was assembled from the lab's working notes, captured terminal outputs, and screenshots. The screenshot insertion notes are editorial placeholders, not missing-image links. Selected, privacy-reviewed images will be embedded in this README before public publication.

The commands document this lab's procedures; they are not an automated installer and should not be applied blindly to another system.
