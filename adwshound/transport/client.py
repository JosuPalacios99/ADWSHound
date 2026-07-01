import re
import logging
import threading
from base64 import b64decode
from uuid import UUID, uuid4
from xml.etree import ElementTree
from typing import Optional

# XML 1.0 valid character ranges (XML spec §2.2):
#   #x9 | #xA | #xD | [#x20-#xD7FF] | [#xE000-#xFFFD] | [#x10000-#x10FFFF]
_INVALID_XML_CHARS = re.compile(
    "[\x00-\x08\x0B\x0C\x0E-\x1F\x7F\uD800-\uDFFF￾￿]"
)

# Numeric character references (&#NN; / &#xNN;) — SoaPy may emit refs that
# point to code points illegal in XML 1.0 (e.g. &#1;), which ElementTree
# rejects with "reference to invalid character number".
_NUMERIC_CHAR_REF = re.compile(r"&#(?:x([0-9a-fA-F]+)|([0-9]+));")


def _is_valid_xml_char(cp: int) -> bool:
    """True if code point is a legal XML 1.0 character."""
    return (cp in (0x9, 0xA, 0xD)
            or 0x20 <= cp <= 0xD7FF
            or 0xE000 <= cp <= 0xFFFD
            or 0x10000 <= cp <= 0x10FFFF)


def _strip_invalid_char_refs(s: str) -> str:
    """Drop numeric char refs that resolve to illegal XML 1.0 code points."""
    def _repl(m: "re.Match") -> str:
        cp = int(m.group(1), 16) if m.group(1) else int(m.group(2))
        return m.group(0) if _is_valid_xml_char(cp) else ""
    return _NUMERIC_CHAR_REF.sub(_repl, s)


from adwshound.vendor.adws import ADWSConnect, NTLMAuth, KerberosAuth, ADWSError
from adwshound.vendor.soap_templates import LDAP_QUERY_FSTRING, NAMESPACES

log = logging.getLogger(__name__)


class EnumerateFaultError(Exception):
    """ADWS returned a SOAP EnumerateFault (e.g. InvalidProperty) for a query."""


def _is_noise_dn(dn: str) -> bool:
    """Return True for DNs that SharpHound explicitly skips (system noise objects)."""
    lower = dn.lower()
    if "cn=domainupdates,cn=system" in lower:
        return True
    if "cn=policies,cn=system" in lower and (lower.startswith("cn=user") or lower.startswith("cn=machine")):
        return True
    return False


# Attribute names whose raw bytes we need for downstream processing (not decoded to string)
_BINARY_KEEP_BYTES = {
    "nTSecurityDescriptor",
    "msDS-AllowedToActOnBehalfOfOtherIdentity",
    "msDS-GroupMSAMembership",  # gMSA password readers security descriptor
    "cACertificate",
    "securityIdentifier",
    "crossCertificatePair",
    "pKIExpirationPeriod",
    "pKIOverlapPeriod",
}

# Windows FileTime epoch offset in seconds
_WIN_EPOCH_DELTA = 11_644_473_600

# Large-integer timestamp attribute names
_WIN_TIMESTAMP_ATTRS = frozenset({
    "accountExpires", "lastLogoff", "badPasswordTime",
    "lastLogon", "pwdLastSet", "lastLogonTimestamp", "whenChanged",
    "ms-Mcs-AdmPwdExpirationTime", "msLAPS-PasswordExpirationTime",
})


def _tag_localname(elem: ElementTree.Element) -> str:
    tag = elem.tag
    return tag.split("}")[-1] if "}" in tag else tag


def _win_filetime_to_epoch(v: str) -> int:
    val = int(v)
    if val == 0 or val == 0x7FFFFFFFFFFFFFFF:
        return -1
    return int(val / 10_000_000 - _WIN_EPOCH_DELTA)


def _parse_value(name: str, syntax: str, raw: str) -> object:
    """Convert a single ADWS raw string value to a Python-native type."""
    if name in _BINARY_KEEP_BYTES:
        return b64decode(raw)

    if name == "objectGUID":
        return str(UUID(bytes=b64decode(raw)))

    if syntax == "SidString":
        from impacket.ldap.ldaptypes import LDAP_SID
        return LDAP_SID(data=b64decode(raw)).formatCanonical()

    if name in _WIN_TIMESTAMP_ATTRS:
        return _win_filetime_to_epoch(raw)

    if syntax == "GeneralizedTimeString":
        from pyasn1.type.useful import GeneralizedTime
        dt = GeneralizedTime(raw).asDateTime
        return int(dt.timestamp())

    if syntax in ("IntegerString", "LargeIntegerString"):
        try:
            return int(raw)
        except ValueError:
            return raw

    if syntax == "BooleanString":
        return raw.upper() == "TRUE"

    # Default: plain string (UnicodeString, DNString, PrintableString, …)
    return raw


def _throttle(throttle_ms: int, jitter_pct: int) -> None:
    if throttle_ms <= 0:
        return
    import time, random
    delay = throttle_ms
    if jitter_pct > 0:
        jitter = delay * jitter_pct / 100
        delay += random.uniform(-jitter, jitter)
    time.sleep(max(0, delay) / 1000.0)


def parse_adws_results(results: ElementTree.Element) -> list[dict]:
    """Convert ADWSConnect.pull() ElementTree into list of attribute dicts.

    Each dict has:
      - "_type": localname of the AD object element (e.g. "user", "computer")
      - one key per LDAP attribute; value is scalar for single-valued attributes,
        list for multi-valued ones.
    """
    NS = NAMESPACES
    objects: list[dict] = []

    for item in results.findall(".//ad:value/../..", namespaces=NS):
        obj: dict = {"_type": _tag_localname(item)}

        for part in item.findall(".//ad:value/..", namespaces=NS):
            if "LdapSyntax" not in part.attrib:
                continue  # synthetic / computed attribute

            attr_name = _tag_localname(part)
            syntax = part.attrib["LdapSyntax"]
            raw_vals = [
                v.text for v in part.findall("ad:value", NS)
                if v.text is not None
            ]

            parsed = [_parse_value(attr_name, syntax, r) for r in raw_vals]

            if len(parsed) == 1:
                obj[attr_name] = parsed[0]
            elif len(parsed) > 1:
                obj[attr_name] = parsed
            # skip empty

        objects.append(obj)

    return objects


class _ExtendedADWSConnect(ADWSConnect):
    """ADWSConnect subclass that:
    - supports custom base DN for config/schema NC queries
    - sanitises XML responses before parsing (strips invalid XML 1.0 chars)
    """

    def _handle_str_to_xml(self, xmlstr: str) -> ElementTree.Element | None:
        # Pass 1: strip forbidden XML 1.0 code points (raw + numeric refs)
        clean = _strip_invalid_char_refs(_INVALID_XML_CHARS.sub("", xmlstr))
        try:
            return ElementTree.fromstring(clean)
        except ElementTree.ParseError:
            pass

        # Pass 2: escape bare '<' and '&' that SoaPy emits unescaped from
        # AD attribute values (e.g. description="R&D", "filter < 0")
        # — '&' not followed by a valid entity ref → &amp;
        # — '<' not followed by a valid tag opener   → &lt;
        # XML only predefines 5 named entities; any other '&name;'
        # (e.g. &copy; &nbsp; &reg; in a description) is "undefined" to
        # ElementTree, so only those 5 + numeric refs count as valid here.
        recovered = re.sub(
            r"&(?!(?:#[0-9]+|#x[0-9a-fA-F]+|amp|lt|gt|quot|apos);)",
            "&amp;",
            clean,
        )
        recovered = re.sub(r"<(?![A-Za-z_/!?])", "&lt;", recovered)
        try:
            return ElementTree.fromstring(recovered)
        except ElementTree.ParseError:
            pass

        # Pass 3: lxml with recovery mode (catches almost any malformed XML)
        try:
            from lxml import etree as _lxml
            parser = _lxml.XMLParser(recover=True, encoding="utf-8")
            root = _lxml.fromstring(
                recovered.encode("utf-8", errors="replace"),
                parser,
            )
            if root is not None:
                clean_xml = _lxml.tostring(root, encoding="unicode")
                try:
                    return ElementTree.fromstring(clean_xml)
                except ElementTree.ParseError:
                    # lxml recovered but output still not accepted by ElementTree
                    # Build an ElementTree from lxml directly
                    import io
                    return ElementTree.parse(
                        io.StringIO(clean_xml)
                    ).getroot()
        except ImportError:
            pass
        except Exception as exc:
            log.debug("lxml recovery failed: %s", exc)

        # Give up — delegate to parent (preserves SOAP fault messages)
        return super()._handle_str_to_xml(recovered)

    def pull_with_base(
        self,
        query: str,
        attributes: list[str],
        base_dn: str,
    ) -> ElementTree.Element:
        fAttributes = "".join(
            f"<ad:SelectionProperty>addata:{a}</ad:SelectionProperty>\n"
            for a in attributes
        )
        # The SD_FLAGS control that makes AD return nTSecurityDescriptor is carried on
        # the Pull message (LDAP_PULL_FSTRING), not here.
        query_vars = {
            "uuid": str(uuid4()),
            "fqdn": self._fqdn,
            "query": query,
            "attributes": fAttributes,
            "baseobj": base_dn,
        }

        self._nmf.send(LDAP_QUERY_FSTRING.format(**query_vars))
        resp = self._nmf.recv()
        et = self._handle_str_to_xml(resp)

        enum_ctx_elem = et.find(".//wsen:EnumerationContext", NAMESPACES)
        if enum_ctx_elem is None:
            # No context → either a legitimately empty result or a SOAP fault
            # (e.g. InvalidProperty when a requested attribute is not in schema).
            fault = et.find(".//soapenv:Fault", NAMESPACES)
            if fault is not None:
                short = et.find(".//ad:ShortError", NAMESPACES)
                inv = et.find(".//ad:InvalidProperty", NAMESPACES)
                detail = "EnumerateFault"
                if inv is not None:
                    detail = f"InvalidProperty{(': ' + inv.text) if inv.text else ''}"
                elif short is not None and short.text:
                    detail = short.text
                raise EnumerateFaultError(detail)
            return ElementTree.Element("wsen:Items")

        enum_ctx = enum_ctx_elem.text
        ElementTree.register_namespace("wsen", NAMESPACES["wsen"])
        results: ElementTree.Element = ElementTree.Element("wsen:Items")
        more = True
        while more:
            batch_et, more = self._pull_results(
                remoteName=self._fqdn, nmf=self._nmf, enum_ctx=enum_ctx
            )
            for item in batch_et.findall(".//wsen:Items", namespaces=NAMESPACES):
                results.append(item)
            if more:
                _throttle(
                    getattr(self, "_throttle_ms", 0),
                    getattr(self, "_jitter_pct", 0),
                )

        return results


class ADWSClient:
    """High-level ADWS client for BloodHound-style AD enumeration.

    Wraps SoaPy's ADWSConnect, exposes search() and search_config_nc()
    that return list[dict] with decoded attribute values.
    """

    def __init__(
        self,
        dc_ip: str,
        domain: str,
        username: str,
        password: Optional[str] = None,
        hashes: Optional[str] = None,
        opsec: bool = False,
        throttle_ms: int = 0,
        jitter_pct: int = 0,
        reuse: bool = True,
        kerberos: bool = False,
        kdc_host: Optional[str] = None,
    ):
        # Kerberos uses a TGT from the ccache ($KRB5CCNAME) — no password needed.
        if not kerberos and not password and not hashes:
            raise ValueError("Provide password or NT hash (LM:NT or :NT), or use Kerberos")

        self.dc_ip = dc_ip
        self.domain = domain.upper()
        self.username = username
        self.base_dn = ",".join(f"DC={p}" for p in domain.lower().split("."))
        self.config_dn = f"CN=Configuration,{self.base_dn}"
        self.schema_dn = f"CN=Schema,{self.config_dn}"
        self.opsec = opsec
        self.throttle_ms = throttle_ms
        self.jitter_pct = jitter_pct

        # When True, one authenticated pull connection is reused across all
        # queries (one NTLM/Kerberos handshake per run instead of one per query).
        self.reuse = reuse
        self._pull_conn: _ExtendedADWSConnect | None = None
        # Serialises access to the shared reused connection: remote collectors
        # issue ADWS sub-queries (SID/hostname lookups) from worker threads, and
        # one NBFS/NNS stream can't be read/written concurrently (garbage
        # NMFUnknownRecord / broken pipe otherwise).
        self._pull_lock = threading.Lock()
        # Lazily-loaded set of valid schema attribute names (for fault recovery)
        self._valid_attrs: set[str] | None = None

        # Normalise hashes: accept ":NT" or "LM:NT" formats
        if hashes and ":" in hashes:
            hashes = hashes.split(":")[-1]

        if kerberos:
            self._auth = KerberosAuth(kdc_host=kdc_host)
        else:
            self._auth = NTLMAuth(password=password, hashes=hashes)

    def _new_pull_conn(self) -> _ExtendedADWSConnect:
        conn = _ExtendedADWSConnect(
            fqdn=self.dc_ip,
            domain=self.domain.lower(),
            username=self.username,
            auth=self._auth,
            resource="Enumeration",
        )
        conn._throttle_ms = self.throttle_ms
        conn._jitter_pct  = self.jitter_pct
        return conn

    def _get_pull_conn(self) -> _ExtendedADWSConnect:
        """Return the connection to use for a query.

        With reuse enabled, a single authenticated connection is created lazily
        and shared. With reuse disabled, a fresh connection is made each call.
        """
        if not self.reuse:
            return self._new_pull_conn()
        if self._pull_conn is None:
            self._pull_conn = self._new_pull_conn()
        return self._pull_conn

    def _drop_pull_conn(self) -> None:
        """Tear down the reused connection so the next query rebuilds it."""
        conn, self._pull_conn = self._pull_conn, None
        if conn is not None:
            try:
                conn._nmf._sock.close()
            except Exception:
                pass

    def _do_pull(self, flt: str, attributes: list[str], base_dn: str):
        """Send one enumeration; rebuild the reused connection once on transport error."""
        if not self.reuse:
            return self._new_pull_conn().pull_with_base(flt, attributes, base_dn)
        # Hold the lock across the whole exchange (enumerate + pulls + any
        # rebuild) so concurrent callers never share the single NBFS stream.
        with self._pull_lock:
            try:
                return self._get_pull_conn().pull_with_base(flt, attributes, base_dn)
            except EnumerateFaultError:
                raise  # server-side query fault, not a transport problem — don't rebuild
            except Exception as exc:
                log.warning("Reused ADWS connection failed (%s); rebuilding and retrying once", exc)
                self._drop_pull_conn()
                return self._get_pull_conn().pull_with_base(flt, attributes, base_dn)

    def _pull(self, ldap_filter: str, attributes: list[str], base_dn: str):
        """Run one enumeration.

        Reuses the shared connection (rebuild-once on transport error). If ADWS
        rejects the query with an EnumerateFault (typically InvalidProperty — a
        requested attribute absent from the schema, e.g. LAPS attrs on a domain
        without LAPS), drop the unknown attributes (resolved against the schema)
        and retry once, so one bad attribute can't zero out an entire object type.
        """
        flt = self._apply_opsec(ldap_filter)
        try:
            return self._do_pull(flt, attributes, base_dn)
        except EnumerateFaultError as fault:
            self._ensure_valid_attrs()
            filtered = self._filter_attrs(attributes)
            if filtered != attributes:
                log.warning("ADWS rejected query (%s); retrying without unknown attrs: %s",
                            fault, sorted(set(attributes) - set(filtered)))
                return self._do_pull(flt, filtered, base_dn)
            log.warning("ADWS EnumerateFault (%s) and no unknown attrs to drop", fault)
            return ElementTree.Element("wsen:Items")

    def _ensure_valid_attrs(self) -> None:
        """Lazy-load the set of valid schema attribute names (lowercased).

        Only triggered when a query faults, so normal runs pay nothing.
        """
        if self._valid_attrs is not None:
            return
        self._valid_attrs = set()  # mark attempted (avoid repeat storms)
        try:
            flt = self._apply_opsec("(objectClass=attributeSchema)")
            rows = parse_adws_results(self._do_pull(flt, ["lDAPDisplayName"], self.schema_dn))
            names: set[str] = set()
            for r in rows:
                v = r.get("lDAPDisplayName")
                if isinstance(v, list):
                    names.update(x.lower() for x in v if x)
                elif v:
                    names.add(v.lower())
            if names:
                self._valid_attrs = names
                log.info("Loaded %d schema attributes for selection filtering", len(names))
        except Exception as exc:
            log.debug("Schema attribute load failed (%s); filtering disabled", exc)

    # Selection properties always kept (core identity / SD), never filtered out.
    _CORE_ATTRS = {"objectsid", "objectguid", "ntsecuritydescriptor",
                   "distinguishedname", "samaccountname", "cn", "objectclass"}

    def _filter_attrs(self, attrs: list[str]) -> list[str]:
        """Drop requested attributes not present in the schema (case-insensitive)."""
        if attrs == ["*"] or not self._valid_attrs:
            return attrs
        kept = [a for a in attrs
                if a.lower() in self._valid_attrs or a.lower() in self._CORE_ATTRS]
        return kept or attrs

    def close(self) -> None:
        """Close the reused connection, if any."""
        self._drop_pull_conn()

    def discover_contexts(self) -> bool:
        """Resolve naming contexts authoritatively from RootDSE.

        Overwrites base_dn / config_dn / schema_dn with the values reported by the
        DC (WS-Transfer Get on the RootDSE object), so collection works even when
        the DN can't be derived from the domain string (single-label domains,
        non-standard DNs, a mistyped -d). Best-effort: on any failure the existing
        domain-derived values are kept and the run proceeds.
        """
        from adwshound.vendor.soap_templates import LDAP_ROOT_DSE_FSTRING
        from uuid import uuid4
        conn = None
        try:
            conn = _ExtendedADWSConnect(
                fqdn=self.dc_ip, domain=self.domain.lower(),
                username=self.username, auth=self._auth, resource="Resource",
            )
            conn._nmf.send(LDAP_ROOT_DSE_FSTRING.format(uuid=str(uuid4()), fqdn=self.dc_ip))
            et = conn._handle_str_to_xml(conn._nmf.recv())

            def _ctx(attr: str) -> str | None:
                el = et.find(f".//addata:{attr}/ad:value", NAMESPACES) if et is not None else None
                return el.text.strip() if el is not None and el.text else None

            default_nc = _ctx("defaultNamingContext")
            config_nc  = _ctx("configurationNamingContext")
            schema_nc  = _ctx("schemaNamingContext")
            if default_nc:
                self.base_dn = default_nc
            self.config_dn = config_nc or f"CN=Configuration,{self.base_dn}"
            self.schema_dn = schema_nc or f"CN=Schema,{self.config_dn}"
            log.info("RootDSE naming contexts: base=%s config=%s schema=%s",
                     self.base_dn, self.config_dn, self.schema_dn)
            return bool(default_nc)
        except Exception as exc:
            log.debug("RootDSE discovery failed (%s); using domain-derived DNs", exc)
            return False
        finally:
            if conn is not None:
                try:
                    conn._nmf._sock.close()
                except Exception:
                    pass

    def test_connection(self) -> bool:
        try:
            conn = self._get_pull_conn()
            _ = conn.pull(query="(objectClass=domain)", attributes=["cn"])
            return True
        except Exception as exc:
            log.error("ADWS connection test failed: %s", exc)
            self._drop_pull_conn()
            return False

    def _throttle_sleep(self) -> None:
        if self.throttle_ms <= 0:
            return
        import time, random
        delay = self.throttle_ms
        if self.jitter_pct > 0:
            jitter = delay * self.jitter_pct / 100
            delay += random.uniform(-jitter, jitter)
        delay = max(0, delay)
        log.debug("Throttle sleep %.0f ms", delay)
        time.sleep(delay / 1000.0)

    def _apply_opsec(self, ldap_filter: str) -> str:
        if not self.opsec:
            return ldap_filter
        from adwshound.opsec import obfuscate_filter
        obfuscated = obfuscate_filter(ldap_filter)
        log.debug("OPSEC filter: %s → %s", ldap_filter, obfuscated)
        return obfuscated

    def search(
        self,
        ldap_filter: str,
        attributes: list[str],
    ) -> list[dict]:
        """Query default naming context (domain root)."""
        log.debug("ADWS search filter=%s attrs=%s", ldap_filter, attributes)
        results = self._pull(ldap_filter, attributes, self.base_dn)
        return [r for r in parse_adws_results(results) if not _is_noise_dn(r.get("distinguishedName", ""))]

    def search_config_nc(
        self,
        ldap_filter: str,
        attributes: list[str],
    ) -> list[dict]:
        """Query Configuration naming context."""
        log.debug("ADWS config NC search filter=%s", ldap_filter)
        results = self._pull(ldap_filter, attributes, self.config_dn)
        return parse_adws_results(results)

    def search_schema_nc(
        self,
        ldap_filter: str,
        attributes: list[str],
    ) -> list[dict]:
        """Query Schema naming context."""
        log.debug("ADWS schema NC search filter=%s", ldap_filter)
        results = self._pull(ldap_filter, attributes, self.schema_dn)
        return parse_adws_results(results)

    def get_domain_sid(self) -> Optional[str]:
        """Return the domain SID."""
        objs = self.search("(objectClass=domain)", ["objectSid"])
        for obj in objs:
            if "objectSid" in obj:
                return obj["objectSid"]
        return None
