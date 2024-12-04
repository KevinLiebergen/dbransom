from collections import defaultdict
from collections import Counter
from dateutil.parser import parse as time_parse
from filtering import filter_event
import json
import logging
import os
import re
import sys
import tldextract
from wide_scanner import WideScannerDB

# Set logging
log = logging.getLogger(__name__)

# Imports
script_dir = os.path.dirname(os.path.abspath(__file__))

output_path = os.path.join(script_dir, "../output")

# Check if the directory exists, if not, create it
if not os.path.exists(output_path):
    os.makedirs(output_path)


def get_db(event) -> str:
    software = ""
    if "elasticsearch" in event.plugin.lower():
        software = "ElasticSearch"
    elif "mysql" in event.plugin.lower():
        if event.software[0] \
                and ("mariadb" in event.software[0].lower()
                     or "mariadb" in event.software[1].lower()):
            software = "MariaDB"
        elif "mysql_honeypot" in event.plugin.lower():
            software = "Honeypot"
        else:
            software = "MySQL"
    return software


def get_features(s):
    width = 3
    s = s.lower()
    s = re.sub(r'[^\w]+', '', s)
    return [s[i:i + width] for i in range(max(len(s) - width + 1, 1))]


def ips_with_fqdns(ips_fqdn_ctr):
    """ Print IPs with more than one FQDN """
    log.info("IPs with more than one FQDN:")
    for ip, fqdns in ips_fqdn_ctr.items():
        if len(fqdns) > 1:
            log.info("\t{}: {}".format(ip, fqdns))


def print_os_distribution(os_ctr: Counter, n_events: int):
    """ Print Operating System distribution sorted """
    num_os = sum(os_ctr.values())
    num_no_os = n_events - num_os
    if n_events != 0:
        perc_no_os = round((num_no_os / n_events) * 100, 2)
        perc_os = round((num_os / n_events) * 100, 2)
    else:
        perc_no_os = 0
        perc_os = 0

    log.info("Events with no OS: {:,} ({}%)".format(num_no_os, perc_no_os))

    log.info("Events with OS: {:,} ({}%)".format(num_os, perc_os))

    ctr_other = 0
    for operating_system, ctr in sorted(os_ctr.items(),
                                        key=lambda val: val[1],
                                        reverse=True):

        if operating_system == 'Linux' or operating_system == 'Windows':
            log.info("\t{}: {:,} ({}%)"
                     "".format(operating_system,
                               ctr,
                               round((ctr / n_events) * 100, 2)))
        else:
            ctr_other += ctr
    if ctr_other > 0:
        log.info("\tOther: {:,} ({}%)"
                 "".format(ctr_other,
                           round((ctr_other / n_events) * 100, 2)))


def check_belong_esxi(text: str):
    return "200 OK" in text and "How to Restore Your Files" in text


class LeakIXHostEvent:
    """ Wrapper for LeakIXEvent, get the last event from historical """
    def __init__(self, event_host_dict, normalize=True):
        # JSON event
        self.event_host_dict = event_host_dict
        self.services = list()
        self.leaks = list()

        self.last_event = LeakIXEvent(self.event_host_dict,
                                      normalize=normalize)

    def get_last_event(self, normalize=True):
        """ """
        if self.event_host_dict.get('Services'):
            # Get newest index
            latest_index = 0
            latest_time = "2000-01-01T00:00:00.000000000Z"
            for index, key in enumerate(self.event_host_dict.get('Services')):
                if (latest_time < key.get('time')) and \
                        check_belong_esxi(key.get('summary')):
                    latest_index = index
                    latest_time = self.event_host_dict.get('Services')[index].get('time')

            return LeakIXEvent(self.event_host_dict.get('Services')[latest_index], normalize=normalize)

        elif self.event_host_dict.get('Leaks'):
            return LeakIXEvent(self.event_host_dict, normalize=normalize)
        else:
            log.error("[+] Error processing {}".format(self.event_host_dict))
            sys.exit(0)

    def get_services(self):
        """ Get services objects """
        for service in self.event_host_dict.get('Services'):
            event = LeakIXEvent(service)
            self.services.append(event)

    def get_leaks(self):
        """ Get leaks objects """
        for leak in self.event_host_dict.get('Leaks'):
            event = LeakIXEvent(leak)
            self.leaks.append(event)


class LeakIXEvent:
    """ A LeakIX infected event """
    def __init__(self, event_dict, normalize=True):
        # JSON event
        self.event_dict = event_dict

        # Set of Notes class
        self.notes = set()

        if self.ransom_notes:
            self.load_notes(normalize=normalize)
        elif check_belong_esxi(self.summary):
            self.load_summary_note()

    def load_summary_note(self):
        """ Load HTML code from the summary field """
        from grouping import Note

        note = self.summary
        self.notes.add(Note(note))

    def load_notes(self, normalize=True):
        """ Create and save Note class """
        from grouping import Note

        for note in self.ransom_notes:
            self.notes.add(Note(note, normalize=normalize))

    @property
    def event_fingerprint(self):
        """ Event fingerprint """
        return self.event_dict.get('event_fingerprint')

    @property
    def iocs(self):
        """ Ransom notes IOCs """
        iocs_event = set()
        if self.notes:
            for note in self.notes:
                for ioc in note.iocs:
                    iocs_event.add(ioc)
            return iocs_event
        return None

    @property
    def time(self):
        """ Return event timestamp as a datetime """
        time = self.event_dict.get('time')
        if time:
            return time_parse(time)
        return None

    @property
    def ip(self):
        """ Return event IP address """
        return self.event_dict.get('ip')

    @property
    def port(self):
        """ Return event port """
        return self.event_dict.get('port')

    @property
    def fqdn(self):
        """ Return event fqdn """
        return self.event_dict.get('host', None)

    @property
    def domain(self):
        """ Return event domain """
        extracted = tldextract.extract(self.fqdn)
        return "{}.{}".format(extracted.domain, extracted.suffix)

    @property
    def db(self):
        return get_db(self)

    @property
    def plugin(self):
        """ Return event plugin """
        return self.event_dict.get('event_source')

    @property
    def plugin_version(self):
        """ Return event plugin version """
        service = self.event_dict.get('service')
        if not service:
            return None
        software = service.get('software')
        if not software:
            return None
        version = software.get('version')
        if not version or version == 'Cloudproxy':
            return None

        return version

    @property
    def protocol(self):
        """ Return event protocol """
        return self.event_dict['protocol']

    @property
    def asn(self):
        """ Return event IP Autonomous System Number """
        net_dict = self.event_dict.get('network', None)
        if not net_dict:
            return None
        return net_dict.get('asn', None)

    @property
    def net(self):
        """ Return event IP network """
        net_dict = self.event_dict.get('network', None)
        if not net_dict:
            return None
        return net_dict.get('network', None)

    @property
    def country_code(self):
        """ Return event IP country ISO code """
        geoip_dict = self.event_dict.get('geoip', None)
        if not geoip_dict:
            return None
        return geoip_dict.get('country_iso_code', None)

    @property
    def country_name(self):
        """ Return event IP country name """
        geoip_dict = self.event_dict.get('geoip', None)
        if not geoip_dict:
            return None
        return geoip_dict.get('country_name', None)

    @property
    def tags(self):
        """ Return event tag list """
        tag_l = self.event_dict.get('tags', None)
        if tag_l is None:
            return []
        return tag_l

    @property
    def software(self):
        """ Return event software as (program,version) """
        service_dict = self.event_dict.get('service', None)
        if not service_dict:
            return None, None
        sw_dict = service_dict.get('software', None)
        if not sw_dict:
            return None, None
        program = sw_dict.get('name', None)
        version = sw_dict.get('version', None)
        return program, version

    @property
    def certificate(self):
        """ Return event certificate dictionary """
        ssl_dict = self.event_dict('ssl', None)
        if not ssl_dict:
            return None
        return ssl_dict.get('certificate', None)

    @property
    def ransom_notes(self):
        """ Return event ransom notes list """
        leak_dict = self.event_dict.get('leak', None)
        if leak_dict is None:
            return []
        dataset_dict = leak_dict.get('dataset', None)
        if dataset_dict is None:
            return []
        notes = dataset_dict.get('ransom_notes', [])
        if notes is None:
            return []
        return notes

    @property
    def distro(self):
        """ Return operating system """
        service_dict = self.event_dict.get('service', None)
        if not service_dict:
            return None
        software = service_dict.get('software', None)
        if not software:
            return None
        distro = software.get('os', None)
        if not distro or distro == ' ':
            return None
        return distro

    @property
    def summary(self):
        """ Return summary request """
        return self.event_dict.get('summary')

    @property
    def table(self):
        """ Return database and table names only if we can assign it.
        1 ransom note -> 1 table"""

        if get_db(self) == "MySQL" or get_db(self) == "MariaDB":
            regex = r'Found table (.*) with'

        elif get_db(self) == "ElasticSearch":
            regex = r'Found index (.*) with'

        if self.summary:
            tables = re.findall(regex, self.summary, re.IGNORECASE)
        else:
            tables = []

        return tables

    @property
    def infer_os(self):
        """ Infer distribution by operating system """
        macos_regex = "(macos|Mac OS X|osx)"
        windows_regex = "(Windows|Win)"
        linux_regex = "(Linux|Debian|Ubuntu|openEuler|EulerOS|CentOS|Fedora|openSUSE|el6|el7|el8| \d*\.\d*)"

        android_regex = "Android"
        freebsd_regex = "FreeBSD"
        solaris_regex = "Solaris"
        openbsd_regex = "OpenBSD"
        unix_regex = "Unix"
        cpanel_regex = "cPanel"

        if not self.distro:
            distro = None
        elif re.search(unix_regex, self.distro, re.IGNORECASE):
            distro = "Unix"
        elif re.search(cpanel_regex, self.distro, re.IGNORECASE):
            distro = "cPanel"
        elif re.search(freebsd_regex, self.distro, re.IGNORECASE):
            distro = "FreeBSD"
        elif re.search(solaris_regex, self.distro, re.IGNORECASE):
            distro = "Solaris"
        elif re.search(openbsd_regex, self.distro, re.IGNORECASE):
            distro = "OpenBSD"
        elif re.search(android_regex, self.distro, re.IGNORECASE):
            distro = "Android"
        elif re.search(macos_regex, self.distro, re.IGNORECASE):
            distro = "macOS"
        elif re.search(windows_regex, self.distro, re.IGNORECASE):
            distro = "Windows"
        elif re.search(linux_regex, self.distro, re.IGNORECASE):
            distro = "Linux"
        else:
            distro = None

        return distro

    def json(self):
        """ Return event in JSON format """
        data = {'leakix': self.event_dict}

        set_iocs = list()
        if self.iocs:
            for ioc in self.iocs:
                set_iocs.append((ioc.name, ioc.value))
        data['iocs'] = list(set_iocs)

        return json.dumps(data, sort_keys=False)


class LeakIXDB(WideScannerDB):
    """ LeakIX events database """
    def __init__(self, filepath: list = None, plugin: str = None,
                 normalize=True):
        super().__init__()

        # Index IP -> event set
        self.ip_idx = {}

        # Index domain -> event set
        self.domain_idx = {}

        # Fields stats
        self.n_events = 0
        self.ip_ctr = Counter()
        self.os_ctr = Counter()
        self.version_ctr = Counter()
        self.table_ctr = defaultdict(Counter)
        self.port_ctr = Counter()
        self.fqdn_ctr = Counter()
        self.ips_w_fqdn = defaultdict(set)
        self.asn_ctr = Counter()
        self.cc_ctr = Counter()
        self.cname_ctr = Counter()
        self.cc_service_ips = defaultdict(lambda: defaultdict(set))
        self.events_ransom_notes = 0

        # False Positives part
        self.unique_fp_ransom_notes = set()
        self.fp_ransom_notes = list()
        self.fp_events = 0

        # Load LeakIX events if passed
        if filepath:
            log.info("[+] Normalizing notes: {}".format(normalize))
            self.load_from_file(filepath, plugins=plugin, normalize=normalize)

        # Clustering
        from grouping import Clustering

        self.clustering = Clustering(nhash_note=self.nhash_note,
                                     normalized_nhash=self.normalized_nhash_raw_nhash)

    def load_from_file(self, filepath: list, plugins: str = None,
                       normalize=True):
        """ Read lines and save features """
        for file in filepath:
            log.info("[+] Loading {}".format(file))
            # Open JSON file
            fd_in = open(file, 'r', encoding='utf-8')

            n_line = 0
            # Load in memory events stats
            for n_line, line in enumerate(fd_in, 1):
                if n_line % 100 == 0:
                    sys.stdout.write("\r    [+] {:,} line read".format(n_line))

                event_dict = json.loads(line)
                # LeakIx dataset have 2 data types, host and plugin data
                leakix_event = LeakIXHostEvent(event_dict, normalize=normalize)

                # Not include duplicate reports from other datasets months
                updated_event = filter_event(leakix_event.last_event)
                if updated_event and updated_event.notes:
                    self.add_event(updated_event)

            sys.stdout.write("\r    [+] {:,} line read\n".format(n_line))
            # Close the file
            fd_in.close()

    def add_event(self, event):
        """ Add given event to database """
        self.events.add(event)

        # Update IP address index
        if event.ip is not None:
            self.ip_idx.setdefault(event.ip, set()).add(event)
        # Update note hash index
        for note in event.notes:

            # Add note_hash -> Event
            self.nhash_idx.setdefault(note.hash_text, set()).add(event)
            # Add note_hash -> Note
            self.nhash_note[note.hash_text] = note
            self.normalized_nhash_raw_nhash[note.hash_normalized_text].add(note.hash_text)
            self.norm_notes.add(note.normalized_text)

    def print_stats(self):
        """ Print statistics """
        self.stats_by_plugin()
        self.union_plugins()

    def stats_by_plugin(self):
        """ Extract stats split by plugin """
        stats = dict()

        version_name = 'version_distr.csv'
        full_name = os.path.join(output_path, version_name)

        fd_version = open(full_name, 'w')
        log.info("[+] Saving version distribution in {}".format(full_name))
        fd_version.write("event_ts,sw,version\n")

        # Extract stats
        for event in self.events:

            stats.setdefault(event.db, dict()).setdefault('events', set()).add(event)

            earliest_event = stats.setdefault(event.db, dict()).setdefault('earliest', event.time)
            if earliest_event and \
                    event.time and \
                    event.time < earliest_event:
                stats.get(event.db)['earliest'] = event.time

            if event.ip is not None:
                stats.setdefault(event.db, dict()).\
                    setdefault('ip', set()).add(event.ip)

            if event.port is not None:
                stats.setdefault(event.db, dict()).\
                    setdefault('port', set()).add(event.port)

            if event.fqdn and event.fqdn != event.ip and event.fqdn != '':
                stats.setdefault(event.db, dict()).\
                    setdefault('fqdn', set()).add(event.fqdn)

                stats.setdefault(event.db, dict()).\
                    setdefault('domains_ctr', Counter())[event.domain] += 1

                stats.setdefault(event.db, dict()).\
                    setdefault('ip_w_fqdn', dict()).\
                    setdefault(event.ip, set()).add(event.fqdn)

            if event.asn:
                stats.setdefault(event.db, dict()).\
                    setdefault('asn', set()).add(event.asn)

            if event.country_code:
                stats.setdefault(event.db, dict()).\
                    setdefault('ccs', set()).add(event.country_code)

            if event.infer_os:
                stats.setdefault(event.db, dict()).\
                    setdefault('os_ctr', Counter())[event.infer_os] += 1

            if event.plugin_version:
                stats.setdefault(event.db, dict()).\
                    setdefault('version_ctr', Counter())[event.plugin_version]\
                    += 1

                if "-" in event.plugin_version:
                    version = event.plugin_version.split("-")[0]
                else:
                    version = event.plugin_version

                if event.time:
                    fd_version.write("{},{},{}\n".format(event.time.date(),
                                                         event.db,
                                                         version)
                                     )

            if event.notes:
                stats.setdefault(event.db, dict()).\
                    setdefault('events_w_notes', set()).add(event)

                for note in event.notes:
                    stats.setdefault(event.db, dict()).\
                        setdefault('ransom_notes', set()).add(note.text)

                    stats.setdefault(event.db, dict()).\
                        setdefault('normalized_ransom_notes', set()).add(note.hash_normalized_text)

                    # Extract IOCs
                    for ioc in note.iocs:
                        stats.setdefault(event.db, dict()).\
                            setdefault('iocs', defaultdict(set))[ioc.name].add(ioc.value)
                    # Extract BTC amounts
                    if note.btc_amounts:
                        for amount in note.btc_amounts:
                            stats.setdefault(event.db, dict()).\
                                setdefault('btc_amounts', set()).add(amount[1])

        self.export_tables_distr()

        # Print
        for plugin, features in stats.items():
            # Print stats calculated previously
            log.info("-" * 50)
            log.info("[+] Plugin: {}".format(plugin))
            log.info("Earliest event: {}".format(features.get('earliest')))
            log.info("Events: {:,}".format(len(features.get('events'))))
            log.info("IPs: {:,}".format(len(features.get('ip', []))))

            v_ctr = features.get('version_ctr')
            if v_ctr:
                e_versions = sum(v_ctr.values())
            else:
                e_versions = 0
            log.info("Events with versions: {}".format(e_versions))

            if features.get('ip_w_fqdn'):
                log.info("IPs with FQDNs: {:,}".format(
                    len(features.get('ip_w_fqdn'))))
            log.info("Ports: {:,}".format(len(features.get('port', []))))

            if features.get('fqdn'):
                log.info("FQDNs: {:,}".format(len(features.get('fqdn'))))

            limit = 5
            if features.get('domains_ctr'):
                log.info("Subdomains ({}):".format(limit))
                subdomains_sorted = sorted(features.get('domains_ctr').items(),
                                           key=lambda val: val[1],
                                           reverse=True)
                for n_subdomain, subdomain in enumerate(subdomains_sorted):
                    if n_subdomain == limit:
                        break
                    log.info("\t{}: {:,}".format(subdomain[0], subdomain[1]))

            log.info("ASNs: {:,}".format(len(features.get('asn', []))))
            log.info("CCs: {:,}".format(len(features.get('ccs', []))))
            log.info("Events with note: {:,}"
                     .format(len(features.get('events_w_notes', []))))
            log.info("Notes: {:,}".format(len(features.get('ransom_notes', []))))
            log.info("Normalized notes: {:,}".format(len(features.get('normalized_ransom_notes', []))))

            # btc_addresses = self.extract_specific_ioc('bitcoin')
            log.info("BTC Addresses: {:,}".format(len(features.get('iocs').get('bitcoin', []))))
            log.info("N. BTC amounts: {:,}".format(
                len(features.get('btc_amounts', []))))
            log.info("Min BTC amount: {}"
                     "".format(min(features.get('btc_amounts'), default=0)))
            log.info("Max BTC amount: {}"
                     "".format(max(features.get('btc_amounts'), default=0)))

            if features.get('note_fps'):
                log.info("Notes False Positives: {:,}".format(
                    len(features.get('note_fps'))))

            # OS
            if features.get('os_ctr'):
                print_os_distribution(features.get('os_ctr'),
                                      len(features.get('events')))

    def export_tables_distr(self):

        for db, ctr in self.table_ctr.items():
            table_fname = 'tables_events_{}.tsv'.format(db)
            output_file_path = os.path.join(output_path, table_fname)

            table_fd = open(output_file_path, 'w')
            log.info("[+] Saving in {}".format(output_file_path))
            table_fd.write("table\tn_events\n")

            for table, ntimes in sorted(ctr.items(),
                                        key=lambda val: val[1],
                                        reverse=True):
                table_fd.write("{}\t{}\n".format(table, ntimes))

    def extract_stats(self):
        """ Stats regardless plugin type """

        for event in self.events:
            # IP
            if event.ip:
                self.ip_ctr[event.ip] += 1
            # Port
            if event.port is not None:
                self.port_ctr[int(event.port)] += 1
            # FQDN
            if event.fqdn and event.fqdn != event.ip:
                self.fqdn_ctr[event.fqdn] += 1
                self.ips_w_fqdn[event.ip].add(event.fqdn)
            # ASN
            if event.asn:
                self.asn_ctr[int(event.asn)] += 1
            # Country Codes
            if event.country_code:
                self.cc_ctr[event.country_code] += 1

            # Country Names
            if event.country_name:
                self.cname_ctr[event.country_name] += 1

                # Distribution per country of services IPs
                self.cc_service_ips[event.country_name][event.plugin].add(event.ip)

            # OS
            if event.infer_os:
                self.os_ctr[event.infer_os] += 1

            # Version
            if event.plugin_version:
                self.version_ctr[event.plugin_version] += 1

            # Tables and indices databases
            for table in event.table:
                self.table_ctr[event.db][table] += 1

            # Events with ransom notes
            if event.notes:
                self.events_ransom_notes += 1

            for note in event.notes:
                # Add notes
                self.notes.add(note.text)
                # Update IOCs
                self.iocs.update(note.iocs)
                # BTC amounts
                if note.btc_amounts:
                    for amount in note.btc_amounts:
                        self.btc_amounts_ctr[amount[1]] += 1

        fname = 'length_distr.csv'
        output_file_path = os.path.join(output_path, fname)
        log.info("[+] Saving in {}".format(output_file_path))
        distr_fd = open(output_file_path, 'w')
        distr_fd.write("nhash,lang,nchars,nwords\n")

        for nhash, note in self.nhash_note.items():
            nchars = len(note.text)
            nwords = len(note.text.split(' '))
            distr_fd.write("{},{},{},{}\n".format(nhash,
                                                  note.language_note,
                                                  nchars,
                                                  nwords))

    def union_plugins(self):
        """ Stats from all events """
        log.info("=" * 50)

        log.info("Events: {:,}".format(len(self.events)))
        log.info("IPs: {:,}".format(len(self.ip_ctr)))
        log.info("Ports: {:,}".format(len(self.port_ctr)))
        log.info("IPs with FQDN: {:,}".format(len(self.ips_w_fqdn)))
        log.info("FQDNs: {:,}".format(len(self.fqdn_ctr)))
        log.info("ASNs: {:,}".format(len(self.asn_ctr)))
        log.info("CCs: {:,}".format(len(self.cc_ctr)))

        # CC -> IPs distribution
        self.print_cc_ips_distribution()

        # ASNs -> IPs distribution
        self.print_asn_ips_distribution()

        e_versions = sum(self.version_ctr.values())
        try:
            perc = round((e_versions / len(self.events)) * 100, 2)
        except ZeroDivisionError:
            perc = 0
        log.info("Events with DB version: {:,} / {:,} ({}%)"
                 "".format(e_versions, len(self.events), perc))
        log.info("Events with note: {:,}".format(self.events_ransom_notes))

        log.info("Ransom notes: {:,}".format(len(self.notes)))
        log.info("Normalized ransom notes: {:,}"
                 "".format(len(self.normalized_nhash_raw_nhash)))
        log.info("Languages notes distribution:")

        for key, value in self.lang_distribution().items():
            log.info("\t{}: {}".format(key, value))

        notes_lang = sum(self.lang_distribution().values())
        log.info("Notes with languages: {:,}".format(notes_lang))

        log.info("Notes without languages: {:,}".format(len(self.notes)-notes_lang))

        log.info("False Positive Ransom notes: {:,}".format(
            len(self.fp_ransom_notes)))
        log.info("False positives events: {:,}".format(self.fp_events))

        btc_addresses = self.extract_specific_ioc('bitcoin')
        log.info("BTC Addresses: {:,}".format(len(btc_addresses)))

        log.info("N. BTC amounts: {:,}".format(len(self.btc_amounts_ctr)))
        log.info("Events with notes: {:,}".format(self.events_ransom_notes))

        # OS
        print_os_distribution(self.os_ctr, len(self.events))

        # Print IPs > 1 FQDN
        ips_with_fqdns(self.ips_w_fqdn)

        # Email domain -> emails collected distribution
        self.email_domain_distr()

        # Country code -> Plugin DB: IPs
        self.cc_plugin()

    def cc_plugin(self):
        """ Write country code -> plugin database -> n. IPs"""

        fname = 'cc_plugin_ips.txt'
        output_file_path = os.path.join(output_path, fname)
        log.info("[+] Saving in {}".format(output_file_path))
        cc_plugin_fd = open(output_file_path, 'w')

        # Sort self.cc_service_ips by length of ips
        flattened = [(outer_key, inner_key, inner_set)
                     for outer_key, inner_dict in self.cc_service_ips.items()
                     for inner_key, inner_set in inner_dict.items()]

        sorted_flattened = sorted(flattened, key=lambda x: len(x[2]),
                                  reverse=True)

        self.cc_service_ips = {}
        for outer_key, inner_key, inner_set in sorted_flattened:
            if outer_key not in self.cc_service_ips:
                self.cc_service_ips[outer_key] = {}
            self.cc_service_ips[outer_key][inner_key] = inner_set

        for cc, services in self.cc_service_ips.items():
            cc_plugin_fd.write("{}\n".format(cc))
            for service, ips in services.items():
                cc_plugin_fd.write("    {}: {}\n".format(service, len(ips)))

    def print_cc_ips_distribution(self):
        """ Print CC -> IPs distribution """
        fname = "cc_ips.txt"
        output_file_path = os.path.join(output_path, fname)
        output_fpath_fd = open(output_file_path, 'w')

        output_fpath_fd.write("CCs-IPs\n")
        cc_ips = defaultdict(set)

        for event in self.events:
            cc_ips[event.country_code].add(event.ip)

        for cc, ips in sorted(cc_ips.items(),
                              key=lambda p: len(p[1]),
                              reverse=True):
            output_fpath_fd.write("  {}: {:,}\n".format(cc, len(ips)))

    def print_asn_ips_distribution(self):
        """ Print ASNs -> IPs distribution """
        filename = "asn_ips.tsv"
        output_file_path = os.path.join(output_path, filename)
        log.info("[+] Saving in {}".format(output_file_path))
        file_fd = open(output_file_path, "w")

        file_fd.write("ASNs\tIPs\n")
        asn_ips = defaultdict(set)

        for event in self.events:
            asn_ips[event.asn].add(event.ip)

        for n_asn, (asn, ips) in enumerate(sorted(asn_ips.items(),
                                                  key=lambda p: len(p[1]),
                                                  reverse=True)):
            file_fd.write("{}\t{:,}\n".format(asn, len(ips)))

    def lang_distribution(self):
        """ Language distribution"""
        lang_ctr = Counter()
        for notes in self.nhash_note.values():
            lang_ctr[notes.language_note] += 1

        return lang_ctr

    def email_domain_distr(self):
        """ Email domain -> Emails collected  """
        ioc_ctr = defaultdict(set)

        for note in self.nhash_note.values():
            for ioc in note.iocs:
                ioc_ctr[ioc.name].add(ioc.value)

        email_ctr = defaultdict(set)
        if ioc_ctr.get('email'):
            for email in ioc_ctr.get('email'):
                name, domain = email.split('@', 2)
                email_ctr[domain].add(name)

        log.info("Email domains:")

        for domain, name in sorted(email_ctr.items(), key=lambda p: len(p[1]),
                                   reverse=True):
            log.info("\t{}: {:,}".format(domain, len(name)))

        log.info("=" * 50)

    def export_notes_fps(self):
        """ Export false positives notes """
        # Open output file
        filepath = "leakix_fps.txt"
        output_file_path = os.path.join(output_path, filepath)

        log.info("[+] Saving false positive notes in {}"
                 "".format(output_file_path))
        fd_out = open(output_file_path, 'w', encoding='utf-8')

        for note in self.fp_ransom_notes:
            fd_out.write("{}\n".format(note.text.replace("\n", "\\n").\
                            replace("\r", "\\r").\
                            replace("\t", "\\t")))

    def export_notes_no_fps(self):
        """ Export notes with no false positives in ransom notes """

        ifile = "hash_ports_events.csv"
        hash_ports_file_path = os.path.join(output_path, ifile)
        ifile_fd = open(hash_ports_file_path, 'w', encoding='utf-8')
        log.info("[+] Saving true positives notes in {}"
                 "".format(hash_ports_file_path))

        filepath = "tp_notes_leakix.csv"
        output_file_path = os.path.join(output_path, filepath)
        log.info("[+] Saving true positives notes in {}"
                 "".format(output_file_path))
        fd_out = open(output_file_path, 'w', encoding='utf-8')

        fd_out.write("{}|{}\n".format('sha2_description', 'description'))

        # Load in memory events stats
        for event in self.events:
            if event.ransom_notes:
                for note in event.notes:

                    formatted = note.text.replace("\n", "\\n").\
                        replace("\r", "\\r").replace("\t", "\\t")

                    fd_out.write("{}|'{}'\n".format(note.hash_text,
                                                    formatted))

                    ifile_fd.write("{},{}\n".format(note.hash_text,
                                                    event.port))

    def export_events_no_fps(self):
        """ Export events with no false positives in ransom notes,
        if note not exists export anyway """
        # Open output file
        filepath = "tp_leakix.jsonl"
        output_file_path = os.path.join(output_path, filepath)
        log.info("[+] Saving events LeakIX filtered in {}".format(output_file_path))
        fd_out = open(output_file_path, 'w', encoding='utf-8')

        # Load in memory events stats
        for event in self.events:
            fd_out.write("{}\n".format(json.dumps(event.event_dict,
                                                  sort_keys=False)))

    def export_json(self, filepath: str):
        """ Export database as a JSON file """
        with open(filepath, "w") as fd:
            for event in self.events:
                fd.write("%s\n" % event.json())
        fd.close()
