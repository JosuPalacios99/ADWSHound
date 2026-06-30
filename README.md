<div align="center">

# ADWSHound

**A BloodHound collector that enumerates Active Directory over
[ADWS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adws/) (TCP/9389) — not LDAP.**

Same data as SharpHound, but the directory queries ride **ADWS / SOAP on 9389**
instead of LDAP (389/636): quieter, and past LDAP-focused controls.

<br>

![Python](https://img.shields.io/badge/python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Transport](https://img.shields.io/badge/transport-ADWS%20TCP%2F9389-1f6feb?style=for-the-badge)
![Output](https://img.shields.io/badge/BloodHound%20CE-schema%20v6-5b2c6f?style=for-the-badge)
![Built on](https://img.shields.io/badge/built%20on-SoaPy-444?style=for-the-badge)

</div>

<br>

<table>
<tr>
<td width="50%" valign="top">

### What it does

- **ADWS transport** — directory enumeration over
  WS-Enumeration (SOAP/NBFS on 9389). No LDAP.
- **SharpHound-equivalent output** — BloodHound CE
  v6 JSON/ZIP: users, groups, computers, OUs,
  containers, GPOs, trusts, ADCS, ACLs/DCSync.
- **Forest-aware** — `--searchforest` and recursive
  trust walking.

</td>
<td width="50%" valign="top">

### How it gets in

- **NTLM · Pass-the-Hash · Kerberos** end-to-end
  (no NTLM on the wire with `-k`).
- **OPSEC dials** — connection reuse, LDAP filter
  obfuscation, throttle/jitter, tiered footprint.
- **Runs from Linux** — resolves target hostnames
  through the DC's DNS automatically.

</td>
</tr>
</table>

<div align="center">

[How it works](#how-it-works) &nbsp;·&nbsp;
[Requirements](#requirements) &nbsp;·&nbsp;
[Usage](#usage) &nbsp;·&nbsp;
[Methods](#collection-methods) &nbsp;·&nbsp;
[Flags](#flags) &nbsp;·&nbsp;
[OPSEC](#opsec-tiers) &nbsp;·&nbsp;
[ACLs](#acl-collection-the-sd_flags-control) &nbsp;·&nbsp;
[Forest](#forest--multi-domain) &nbsp;·&nbsp;
[Output](#output) &nbsp;·&nbsp;
[Architecture](#architecture) &nbsp;·&nbsp;
[Credits](#credits--soapy)

</div>

---

## How it works

Each directory query is a WS-Enumeration exchange to
`net.tcp://DC:9389/ActiveDirectoryWebServices/Windows/Enumeration`: an `Enumerate` (filter +
attributes → EnumerationContext) followed by `Pull` messages that stream results. ADWSHound
parses the SOAP/NBFS responses back into the SharpHound object model and writes BloodHound v6 JSON.

> [!NOTE]
> ADWS replaces the **LDAP directory queries only**. Remote *computer*-targeted methods
> (Sessions, LoggedOn, LocalGroup, UserRights, host checks, CA/DC registry) still use SMB/MSRPC
> over **445** via impacket. Pure-ADWS collection means avoiding those methods — see [OPSEC tiers](#opsec-tiers).

---

## Requirements

```text
Python 3.10+
impacket>=0.11.0        # SMB/MSRPC, SID/SD parsing, NTLM/Kerberos primitives
pycryptodomex>=3.19.0
pyasn1>=0.5.0
dnspython>=2.4.0        # SRV-based DC auto-discovery + target hostname resolution
pyzipper>=0.3.6         # AES-encrypted ZIP output (--zippassword)
```

> Optional: `lxml` — more robust XML recovery for malformed ADWS responses.

```bash
pip install -r requirements.txt
```

---

## Usage

```bash
# Default collection
python3 adwshound.py -d domain.local -u user -p password --dc 10.0.0.1

# Everything
python3 adwshound.py -c All -d domain.local -u user -p password --dc 10.0.0.1

# Pass-the-hash
python3 adwshound.py -c Default -d domain.local -u user --hashes :NTHASH --dc 10.0.0.1

# Most-opsec (ADWS only, no host/SMB) — also exercises ACL/DCSync
python3 adwshound.py -d domain.local -u user -p pass --dc 10.0.0.1 \
  -c Group,ACL,Container,ObjectProps,Trusts --opsec --skipportcheck \
  --throttle 1000 --jitter 40

# Kerberos — ADWSHound requests the TGT from the creds itself (no prior kinit)
python3 adwshound.py -c All -d domain.local -u user -p pass -k \
  --dc 10.0.0.1 --dc-host dc01.domain.local
```

---

## Collection methods

`-c` takes comma-separated, case-insensitive methods (or a preset). **Users, Computers and Domains
are always collected.**

| Method | Collects | Beyond ADWS |
|---|---|---|
| `Default` | Group, LocalGroup, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, ObjectProps, UserRights | DC SMB + all computers |
| `DCOnly` | Group, LocalGroup, GPOLocalGroup, LoggedOn, Trusts, ACL, Container, ObjectProps, UserRights | DC SMB only |
| `All` | Everything below | DC + computers + CA |
| `ComputerOnly` | LocalGroup, Session, LoggedOn, RDP, DCOM, PSRemote, UserRights, WebClientService, SmbInfo, NTLMRegistry | Computers |
| `Group` | Group memberships | ADWS |
| `ACL` | ACEs from nTSecurityDescriptor (needs the SD_FLAGS control — handled) | ADWS |
| `Container` | OUs, containers, GPO links, DN hierarchy (ContainedBy/ChildObjects) | ADWS |
| `ObjectProps` | Extended object properties | ADWS |
| `Trusts` | Domain trusts | ADWS |
| `SPNTargets` | Kerberoastable MSSQL SPN targets | ADWS |
| `LocalGroup`/`LocalAdmin` · `RDP` · `DCOM` · `PSRemote` | Local group members (SAMR) | Computers (445) |
| `Session` · `LoggedOn` · `UserRights` | NetSessionEnum · registry+NetWkstaUserEnum · LSA | Computers (445) |
| `GPOLocalGroup` | Local groups from GPO XML (SYSVOL) | DC (445) |
| `CertServices` | ADCS: RootCA, AIACA, EnterpriseCA, NTAuthStore, CertTemplate, IssuancePolicy | ADWS + CA registry/HTTP |
| `CARegistry` · `DCRegistry` · `LdapServices` | CA registry (ESC6/role-sep/EA) · DC registry (Zerologon) · LDAP signing/CBT | CA/DC (445) |
| `SmbInfo` · `WebClientService` · `NTLMRegistry` | host checks | Computers (445) |

---

## Flags

<details open>
<summary><b>Connection</b></summary>

```text
-d/--domain                    Domain FQDN (auto from local FQDN if omitted)
--dc/--domaincontroller        DC IP/FQDN (auto via _ldap._tcp SRV if omitted)
-u/--ldapusername              Username
-p/--ldappassword              Password (prompted if omitted and no --hashes)
--hashes LM:NT                 Pass-the-hash
-k/--kerberos                  Kerberos for ADWS + remote SMB/MSRPC collectors
--aesKey HEX                   AES key for Kerberos (implies -k)
--dc-host FQDN                 KDC/DC hostname for Kerberos tickets
--nameserver/--dns-server IP   DNS for resolving target hostnames (default: the DC)
```
</details>

<details>
<summary><b>Collection</b></summary>

```text
-c/--CollectionMethods         Methods (default: Default)
--stealth                      Strip remote-computer methods; DC-only ADWS + GPOLocalGroup
--searchforest                 Enumerate all forest domains (crossRef)
--recursedomains               Follow domain trusts recursively, collecting each trusted domain
--excludedcs                   Exclude DCs from computer-targeted collection
--computerfile FILE            Restrict remote collection to listed computers
--collectallproperties         Request all LDAP attributes (*) instead of curated set
--skipportcheck                Skip TCP:445 probe before remote collection
--skipregistryloggedon         Skip registry-based logged-on enumeration
--opsec                        Hex-escape LDAP filter values (alpha; numbers/names unchanged)
--no-reuse                     One ADWS connection per query (default: reuse one)
```
</details>

<details>
<summary><b>Output &amp; Performance</b></summary>

```text
Output:  --outputdirectory DIR · --outputprefix PREFIX · --nozip · --zippassword PASS · --prettyprint
Perf:    -t/--threads N · --throttle MS · --jitter PCT
Misc:    -v/-vv · --version
```
</details>

---

## OPSEC tiers

From least to most noisy:

| Tier | Command | Footprint |
|:--:|---|---|
| **1** | `-c Group,ACL,Container,ObjectProps,Trusts --opsec --skipportcheck` | ADWS 9389 only. **Zero SMB.** |
| **2** | `-c DCOnly --stealth --opsec` | + SMB 445 to DC (GPO XML from SYSVOL) |
| **3** | `-c Default --opsec` | + SMB/registry/LSA to every computer |
| **4** | `-c All --opsec` | + RDP/DCOM/PSRemote SAMR, ADCS CA registry, host checks |

**`--opsec`** hex-escapes LDAP filter assertion **values** (attribute names unchanged — ADWS needs
readable names; pure-numeric values left as-is since AD won't match escaped digits; `*` preserved).
It defeats SIEM signatures matching raw filter substrings; it does not hide that an ADWS
enumeration is happening.

**`--throttle MS` / `--jitter PCT`** space out ADWS pull batches with random jitter.

---

## ACL collection (the SD_FLAGS control)

AD/ADWS omits `nTSecurityDescriptor` from results unless the **LDAP_SERVER_SD_FLAGS** control
(OID `1.2.840.113556.1.4.801`, value `0x7` = Owner&#124;Group&#124;DACL, no SACL) is sent. ADWSHound carries
it on the **Pull** message (matching SoaPy). ACE rights are mapped to BloodHound CE edge names:

`GenericAll`, `GenericWrite`, `WriteDacl`, `WriteOwner`, `Owns`, `AllExtendedRights`,
`ForceChangePassword`, `GetChanges` / `GetChangesAll` / `GetChangesInFilteredSet` (→ **DCSync**),
`AddMember`, `AddAllowedToAct`, `AddKeyCredentialLink`, `WriteSPN`, `WriteGPLink`,
`WriteAccountRestrictions`, `ReadLAPSPassword`, `ReadGMSAPassword`, `Enroll`, `AutoEnroll`,
`ManageCA`, `ManageCertificates`.

> [!TIP]
> Parser correctness: full-mask `GenericAll`, INHERIT_ONLY ACEs skipped, unrecognised specific
> extended rights are **not** turned into `AllExtendedRights`, owner emitted as `Owns`.
> Tier Zero / high-value is **not** emitted per object — BloodHound CE computes it post-ingest
> from membership + ACL edges (same as SharpHound 2.x).

---

## Forest / multi-domain

- **`--searchforest`** — all domains in the **same forest** via `crossRef` (one-level).
- **`--recursedomains`** — reads `trustedDomain` objects and **walks trusts recursively**, collecting
  each reachable trusted domain (covers external/forest trusts). Works without `Trusts` in `-c`.

Both dedupe via a visited-set (lowercased FQDNs) to avoid loops on bidirectional trusts. Each
domain needs valid creds there and a reachable DC (9389); unreachable domains are logged & skipped.

---

## Output

One JSON file per object type (`*_users.json`, `*_groups.json`, …, ADCS types), `meta.version = 6`,
zipped by default (`--nozip` to skip, `--zippassword` for AES). All files are written **after**
containment/GPO wiring so `ContainedBy`, `ChildObjects`, `Links` and `GPOChanges` are populated.

---

## Architecture

```text
adwshound.py                  CLI + collection pipeline (write-after-wiring, forest BFS)
adwshound/
  transport/client.py         ADWS client: reuse, RootDSE discovery, OPSEC, fault-retry
  vendor/                     Vendored SoaPy ADWS stack (NMF/NNS/encoder/SOAP) + SD-control Pull
  collectors/                 users, computers, groups, domains, ous, containers, gpos, trusts,
                              acls, spns, sessions, local_groups, logged_on, user_rights, adcs,
                              computer_extras, registry_utils, base
  resolvers/cache.py          SID/GUID/DN → TypedPrincipal cache (incl. FSPs)
  schema/types.py             BloodHound v6 dataclasses + CollectionMethod bitmask
  output/                     writer (v6 JSON) + zipper (AES)
  opsec.py                    LDAP filter value obfuscation
```

---

## Credits / SoaPy

The ADWS protocol implementation (MS-NMF, MS-NNS, NBFS/NBFSE encoder, SOAP templates) is vendored
and adapted from **[SoaPy](https://github.com/logangoins/SoaPy)** by Logan Goins / IBM X-Force.
SoaPy is the reference for stealthy ADWS interaction from Linux; ADWSHound reuses its transport and
adds the BloodHound collection layer (ACLs via the SD_FLAGS Pull control, RootDSE discovery,
connection reuse, full SharpHound-equivalent object/edge collection). All credit for the ADWS
transport groundwork to the SoaPy authors.

**References:**
[SoaPy](https://github.com/logangoins/SoaPy) ·
[SOAPHound](https://github.com/FalconForceTeam/SOAPHound) ·
[SharpHound](https://github.com/SpecterOps/SharpHound) ·
[impacket getTGT.py](https://github.com/fortra/impacket/blob/master/examples/getTGT.py) ·
[MS-NNS (GSS) auth](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nns/)

---

<div align="center">
<sub>For authorized security testing only — stay within your engagement scope.</sub>
</div>
