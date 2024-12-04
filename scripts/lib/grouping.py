import csv
from collections import Counter
from collections import defaultdict
from datetime import datetime
from hashlib import sha256
from iocsearcher.searcher import Searcher
import json
import logging
from note import Note
from note import number_regex
from note import list_id
from note import number_id
import os
import re
import sys


csv.field_size_limit(sys.maxsize)


# Imports
script_dir = os.path.dirname(os.path.abspath(__file__))
# To create attribution graph
attribution_dir = os.path.join(script_dir,
                               '../../../../attribution/framework/')
sys.path.append(attribution_dir)


threshold_parts = 4

searcher = Searcher()

# Set logging
log = logging.getLogger(__name__)


def create_maps_nhash(notes, simhash_idx):
    from simhash import Simhash

    smap = {}

    # Iterate on notes, adding ransom notes to index
    for note in notes:
        # Hash note
        note_hash = note.hash_normalized_text

        if not note_hash in smap:
            # Add to Simhash index
            simhash = Simhash(get_features(note.normalized_text))
            simhash_idx.add(note_hash, simhash)

            # Add simhash to map
            smap[note_hash] = (simhash, note.normalized_text)
    return smap


def build_sim_clusters(smap, simhash_idx) -> (dict, dict):
    """ Build similarity clusters """

    log.info("    [+] Building clusters")
    ctr = 0
    cluster_map = {}  # CID -> note_hash
    note_map = {}  # note_hash -> CID

    for note_hash, (simhash, note) in smap.items():
        log.debug("Processing %s" % note_hash)
        # Get near duplicates
        near_dups = simhash_idx.get_near_dups(simhash)
        log.debug("  Found %d near dups" % (len(near_dups) - 1))

        elems = set(near_dups)
        for rhash in near_dups:
            cid = note_map.get(rhash, None)
            log.debug("  rhash: %s cid: %s" % (rhash, str(cid)))
            if cid is not None:
                elems.update(cluster_map.get(cid, set()))
            cluster_map.pop(cid, None)

        ctr += 1
        cluster_map[ctr] = elems
        for rhash in elems:
            note_map[rhash] = ctr

    return cluster_map, note_map


def get_features(s):
    width = 3
    s = s.lower()
    s = re.sub(r'[^\w]+', '', s)
    return [s[i:i + width] for i in range(max(len(s) - width + 1, 1))]

class Component:
    def __init__(self, event_dict: dict):
        # JSON component
        self.event_dict = event_dict

    @property
    def component(self) -> int:
        """ Return component number """
        return self.event_dict.get('component')

    @property
    def nodes(self) -> int:
        """ Return number of nodes """
        return self.event_dict.get('nodes')

    @property
    def n_tagged(self) -> str:
        """ Return number of tagged addresses """
        return self.event_dict.get('ntagged')

    @property
    def tagged(self) -> set:
        """ Return  tagged addresses """
        tagged = set()
        for btc_address, tags in self.event_dict.get('tagged').items():
            tagged.add((btc_address.replace('btc:', ''), tags))
        return tagged

    @property
    def n_seeds(self) -> int:
        """ Return component number """
        return self.event_dict.get('nseeds')

    @property
    def seeds(self) -> set:
        """ Return list of BTC address / seeds """
        addresses = set()
        for address in self.event_dict.get('seeds'):
            addresses.add(address.replace('btc:', ''))
        return addresses


class ComponentDB:
    """ BTC exploration clustering """
    def __init__(self, filepath: str):
        # Component ID -> Component
        self.components = {}
        self.load_from_file(filepath)

    def load_from_file(self, filepath: str):
        """ Read lines and save features """
        log.info("[+] Loading {}".format(filepath))
        # Open JSON file
        fd_in = open(filepath, 'r', encoding='utf-8')

        n_line = 0
        # Load in memory events stats
        for n_line, line in enumerate(fd_in, 1):
            if n_line % 10_000 == 0:
                sys.stdout.write("\r  [+] {:,} line read".format(n_line))
            line = json.loads(line)
            event = Component(line)
            self.components[event.component] = event

        sys.stdout.write("\r  [+] {:,} line read\n".format(n_line))
        # Close the file
        fd_in.close()


class MICluster:
    def __init__(self, event_dict: dict):
        # JSON component
        self.event_dict = event_dict

    @property
    def mi_cluster(self) -> int:
        """ Return MI cluster """
        return self.event_dict.get('mi-cluster')

    @property
    def csize(self) -> int:
        """ Return number of cluster size """
        return self.event_dict.get('csize')

    @property
    def owner(self) -> str:
        """ Return owner tag """
        return self.event_dict.get('owner')

    @property
    def ctag(self) -> str:
        """ Return cluster tag """
        return self.event_dict.get('ctag')

    @property
    def service(self) -> str:
        """ Return service tags """
        return self.event_dict.get('service')

    @property
    def height(self) -> str:
        """ Return block heigh """
        return self.event_dict.get('height')

    @property
    def n_seeds(self) -> int:
        """ Return number of seeds """
        return self.event_dict.get('nseeds')

    @property
    def seeds(self) -> set:
        """ Return list of BTC address / seeds """
        addresses = set()
        for address in self.event_dict.get('seeds').keys():
            addresses.add(address)
        return addresses

    @property
    def n_addrs(self) -> str:
        """ Return number of tagged addresses """
        return self.event_dict.get('naddrs')

    @property
    def addrs(self) -> set:
        """ Return  tagged addresses """
        tagged = set()
        for btc_address, tags in self.event_dict.get('addrs').items():
            tagged.add((btc_address, tags))
        return tagged

    @property
    def seeds_tx_ts_min(self):
        """ Return  min transaction timestamp """
        return self.event_dict.get('seeds_tx_ts_min')

    @property
    def seeds_tx_ts_max(self):
        """ Return  max transaction timestamp """
        return self.event_dict.get('seeds_tx_ts_max')


class MIClusterDB:
    """ Multi-input clustering """
    def __init__(self, filepath: str):
        # MI Cluster ID -> MI Cluster
        self.miclusters = {}
        self.seeds = set()

        self.load_from_file(filepath)

    def load_from_file(self, filepath: str):
        """ Read lines and save features """
        log.info("[+] Loading {}".format(filepath))
        # Open JSON file
        fd_in = open(filepath, 'r', encoding='utf-8')

        n_line = 0
        # Load in memory events stats
        for n_line, line in enumerate(fd_in, 1):
            if n_line % 10_000 == 0:
                sys.stdout.write("\r  [+] {:,} line read".format(n_line))
            line = json.loads(line)
            event = MICluster(line)
            self.miclusters[event.mi_cluster] = event
            self.seeds.update(event.seeds)

        sys.stdout.write("\r  [+] {:,} line read\n".format(n_line))
        # Close the file
        fd_in.close()


class Cluster:
    """ Cluster by similarity """

    def __init__(self,
                 cid=None,
                 iocs_ctr=None,
                 nhash_note=None,
                 mi_clusters=None,
                 jsonized: dict = None,
                 normalize=True):
        if jsonized:
            self.load_from_dict(jsonized, normalize=normalize)
        else:
            # Cluster ID
            self.cid = cid

            # IOCs ctr
            if iocs_ctr is None:
                self.iocs_ctr = defaultdict(Counter)
                self.iocs_set = set()
            else:
                self.iocs_ctr = iocs_ctr

            # Index note_hash -> Note
            if nhash_note is None:
                self.nhash_note = dict()
            else:
                self.nhash_note = nhash_note

            self.normalized_nhash_raw_nhash = defaultdict(set)

            # Note similarity clusters
            self.ns_cluster = dict()
            if cid:
                self.ns_cluster[cid] = ""
            # Set NS clusters
            self.new_ns_cluster = set()
            # Longest common substring
            self.lcsbstr = str()
            # Longest common prefix
            self.lcp = str()
            # Longest common subsequence
            self.lcsub = str()

            self.lcs_ns_cluster = set()

            if mi_clusters:
                self.mi_clusters = mi_clusters
            else:
                self.mi_clusters = set()

    @property
    def length_notes(self):
        """ Return the number of notes of the cluster """
        return len(self.nhash_note)

    def length_events(self, nhash_idx):
        """ Return the number of events of the cluster """
        return len(self.get_events(nhash_idx))

    def load_from_dict(self, cluster: dict, normalize=True):
        """ Load Cluster from dict """
        self.cid = cluster.get('CID')
        self.lcp = cluster.get('LCP')
        self.lcsbstr = cluster.get('LCS')
        self.ns_cluster = set(cluster.get('ns_cluster'))
        # self.iocs = set()
        self.iocs_ctr = defaultdict(Counter)

        # nhash_note
        self.nhash_note = dict()
        for note_event in cluster.get('notes'):
            # Create Note object
            note = Note(note_event.get('text'), normalize=normalize)
            self.add_note(note)

    def create_note(self, text_note: str, hash_note=None, normalize=True):
        """ Create Note object with text note """
        note = Note(text_note, normalize=normalize)
        self.add_note(note, hash_note)  # Check hash note accepts arg

    def add_note(self, note: Note, hash_note=None):
        """ Link Hash note with text note """
        if hash_note and hash_note != note.hash_normalized_text:
            log.error("[+] {} hash note does not match with {}."
                      "".format(hash_note, note.hash_normalized_text))

        self.nhash_note[note.hash_text] = note
        self.normalized_nhash_raw_nhash[note.hash_normalized_text].add(note.hash_text)

        self.extract_iocs(note)

    def extract_iocs(self, note: Note):
        """ Given note, add IOCs to class """
        for ioc in note.iocs:
            if ioc.name == "bitcoin" or ioc.name == "email" \
                    or ioc.name == "onionAddress" or ioc.name == "monero":
                self.iocs_set.add(ioc.value)
            self.iocs_ctr[ioc.name][ioc.value] += 1

    def longest_common_prefix(self):
        """ Longest common prefix """
        # Convert to list
        my_str = list()
        for note in self.nhash_note.values():
            my_str.append(note.normalized_text)
        # Compute
        if my_str:
            prefix = my_str[0]
            for word in my_str:
                if len(prefix) > len(word):
                    prefix, word = word, prefix

                while len(prefix) > 0:
                    if word[:len(prefix)] == prefix:
                        break
                    else:
                        prefix = prefix[:-1]
            self.lcp = prefix

    def longest_common_substring(self):
        """ Given a list of ransom notes for a cluster, return the longest
        common substring """
        substr = ''
        # Convert to list
        data = list()
        for note in self.nhash_note.values():
            data.append(note.normalized_text)
        # Compute
        if len(data[0]) > 0:
            if len(data) > 1:
                for i in range(len(data[0])):
                    for j in range(len(data[0]) - i + 1):
                        if j > len(substr) and all(
                                data[0][i:i + j] in x for x in data):
                            substr = data[0][i:i + j]
            else:
                substr = data[0]

        self.lcsbstr = substr

    def longest_common_subsequence(self):
        """ Longest Common subsequence """
        import pylcs

        list_notes = list()
        delimiter = '[...]'
        final_subsequence = ''
        first = ''
        for n_note, note in enumerate(self.nhash_note.values(), 1):
            if n_note == 1:
                first = note.normalized_text
            else:
                list_notes.append(note.normalized_text)

        if not list_notes:
            self.lcsub = first
        else:
            subsequence = first
            for n_note, note in enumerate(list_notes, 1):
                previous_idx = -1
                subsequence_generated = ''
                res = pylcs.lcs_sequence_idx(subsequence, note)

                for index in res:
                    if index != -1:
                        if previous_idx + 1 == index:
                            subsequence_generated += note[index]
                        else:
                            subsequence_generated += '{}{}'.format(delimiter,
                                                                   note[index])
                    previous_idx = index

                subsequence = subsequence_generated

            parts = subsequence.split('{}'.format(delimiter))
            for n_part, part in enumerate(parts, 1):
                if len(part) >= threshold_parts:
                    final_subsequence += "{}{}".format(part, delimiter)

                if len(part) < threshold_parts and n_part == len(parts):
                    final_subsequence += "{}".format(delimiter)

            self.lcsub = final_subsequence[:-len(delimiter)]

    @property
    def n_lcsub(self):
        return len(self.lcsub.split('[...]'))

    def get_list_regex(self) -> set:
        """ Given LC Subsequence, replace [...] by .+ and IOCs by its regex """
        full_regex = set()
        subsq_free = re.sub('<[A-Z]+>', '', self.lcsub)
        subsq_free = re.sub(re.escape('[...]'), '', subsq_free)

        if len(subsq_free) < 10:
            for ns in self.ns_cluster.values():
                full_regex.add(single_regex(ns))
        else:
            full_regex.add(single_regex(self.lcsub))

        return full_regex

    def cid_events(self, events, cid_events):

        cid_events_fd = open(cid_events, 'w')
        cid_events_fd.write("id,event\n")

        for event in events:
            cid_events_fd.write("{},{}\n".format(self.cid,
                                                 json.dumps(event.event_dict)))

    def json_large(self, nhash_idx, miclustering, cid_events_fd=False):
        """ Return cluster in JSON format """
        events = self.get_events(nhash_idx)
        if cid_events_fd:
            self.cid_events(events, cid_events_fd)

        data = dict()

        data['CID'] = self.cid
        data['n_events'] = len(events)
        data['n_ips'] = len(self.get_ips(nhash_idx))
        data['cc_ips'] = self.cc_ips_ctr(events)
        data['n_ns_cluster'] = len(self.ns_cluster)
        data['ns_cluster'] = self.ns_cluster
        data['n_os'] = len(self.get_os(nhash_idx))
        data['os_ctr'] = self.get_os(nhash_idx)

        langs = self.get_languages()
        data['n_languages'] = len(langs)
        data['languages_ctr'] = langs
        data['n_btc_amounts'] = len(self.get_amounts())
        data['btc_amounts_ctr'] = self.get_amounts()
        data['n_seeds'] = len(self.get_seeds(miclustering,
                                             self.get_ioc_ctr('bitcoin')))
        data['seeds'] = self.get_seeds(miclustering, self.get_ioc_ctr('bitcoin'))

        data['n_addresses'] = len(self.get_ioc_ctr('bitcoin'))
        data['btc_ctr'] = self.get_ioc_ctr('bitcoin')

        data['n_emails'] = len(self.get_ioc_ctr('email'))
        data['emails_ctr'] = self.get_ioc_ctr('email')
        data['n_email_fqdn_ctr'] = len(self.get_email_domain_ctr())
        data['email_fqdn_ctr'] = self.get_email_domain_ctr()
        data['n_onions'] = len(self.get_ioc_ctr('onionAddress'))
        data['onions_ctr'] = self.get_ioc_ctr('onionAddress')

        data['n_monero'] = len(self.get_ioc_ctr('monero'))
        data['monero_ctr'] = self.get_ioc_ctr('monero')
        data['events_db_ctr'] = self.db_ctr(events)

        mi_clusters, min_tx_ts, max_tx_ts = self.get_mi_clusters(miclustering)

        min_event_ts, max_event_ts, event_days = self.get_time_active(events)
        data['min_event_ts'] = str(min_event_ts)[:19]
        data['max_event_ts'] = str(max_event_ts)[:19]

        data['min_tx_ts'] = min_tx_ts
        data['max_tx_ts'] = max_tx_ts

        min_ts = self.get_min(data['min_event_ts'], data['min_tx_ts'])
        max_ts = self.get_max(data['max_event_ts'], data['max_tx_ts'])
        data['min_ts'] = min_ts
        data['max_ts'] = max_ts

        data['days_active'] = self.get_days(min_ts, max_ts)
        data['n_notes'] = len(self.nhash_note)
        data['n_norm_notes'] = len(self.hash_notes_normalized())
        data['hash_notes_normalized_ctr'] = self.hash_notes_normalized()
        data['notes'] = self.get_notes(nhash_idx)

        return json.dumps(data, sort_keys=False, ensure_ascii=False)

    def get_days(self, min_time, max_time):
        """ Difference between max day and min day """
        if min_time != "None" and max_time != "None":
            days = (datetime.strptime(max_time[:10], "%Y-%m-%d") -
                    datetime.strptime(min_time[:10], "%Y-%m-%d")).days + 1
        else:
            days = 0
        return days

    def get_min(self, event_ts, tx_ts):
        """ Get min max timestamp """
        if tx_ts != '':
            min_ts = min(event_ts, tx_ts)
        else:
            min_ts = event_ts

        return min_ts

    def get_max(self, event_ts, tx_ts):
        """ Get max timestamp """
        if tx_ts != '':
            max_ts = max(event_ts, tx_ts)
        else:
            max_ts = event_ts

        return max_ts

    def get_email_domain_ctr(self):
        """ Get counter of disposable email domains by notes """
        email_ctr = Counter()
        for nhash, note in self.nhash_note.items():
            for ioc in note.iocs:
                if ioc.name == "email":
                    email_domain = ioc.value.split('@', 2)[-1]
                    email_ctr[email_domain] += 1

        return dict(sorted(email_ctr.items(), key=lambda x: (x[1], x[0]),
                           reverse=True))

    def get_service_ctr(self, miclustering):
        """ Return MI clusters CID that belong to Cluster
        by exploring seeds """
        miclusters_in_cluster = defaultdict(set)
        if miclustering:
            for address in self.get_ioc_ctr('bitcoin'):
                for cid_micluster, cluster in miclustering.miclusters.items():
                    if address in cluster.seeds:
                        if cluster.service == "exchange":
                            miclusters_in_cluster[cluster.ctag].add(cluster.mi_cluster)
        return {k: list(v) for k, v in miclusters_in_cluster.items()}

    def get_mi_clusters(self, miclustering):
        """ Return MI clusters CID that belong to Cluster
        by exploring seeds """
        min_tx_ts = "9999-12-31 23:59:59"
        max_tx_ts = "1000-01-01 00:00:01"

        miclusters_in_cluster = defaultdict(set)
        if miclustering:
            for address in self.get_ioc_ctr('bitcoin'):
                for cid_micluster, cluster in miclustering.miclusters.items():
                    if address in cluster.seeds:
                        miclusters_in_cluster[cid_micluster].add(address)

                        min_tx_ts = min(cluster.seeds_tx_ts_min, min_tx_ts)
                        max_tx_ts = max(cluster.seeds_tx_ts_max, max_tx_ts)
        if min_tx_ts == "9999-12-31 23:59:59":
            min_tx_ts = ""
        if max_tx_ts == "1000-01-01 00:00:01":
            max_tx_ts = ""

        # {k: list(v) for k, v in miclusters_in_cluster.items()}
        length_micluster = {k: len(v) for k, v in miclusters_in_cluster.items()}
        micluster_sorted = dict(sorted(length_micluster.items(),
                                       key=lambda x: (x[1], x[0]),
                                       reverse=True))

        return micluster_sorted, min_tx_ts, max_tx_ts

    def get_seeds(self, mi_clusters, btc_ctr) -> list:
        """ Get addresses with transactions """
        seeds = set()
        if mi_clusters:
            seeds = mi_clusters.seeds.intersection(btc_ctr.keys())

        return list(seeds)


    def db_ctr(self, events) -> dict:
        """ Distribution of plugins of the events """
        plugins_ctr = Counter()
        for event in events:
            try:
                plugins_ctr[event.db] += 1
            except AttributeError:
                pass

        return dict(sorted(plugins_ctr.items(), key=lambda x: (x[1], x[0]),
                           reverse=True))

    def cc_ips_ctr(self, events) -> dict:
        """ Distribution of CC per ips"""
        cc_ctr = defaultdict(set)
        for event in events:
            try:
                cc_ctr[event.country_code].add(event.ip)
            except AttributeError:
                pass
        # Get sizeof values
        cc_ctr_len = dict()
        for key, value in cc_ctr.items():
            cc_ctr_len[key] = len(value)
        # Sorted by value
        cc_ctr_sorted = dict(sorted(cc_ctr_len.items(),
                                    key=lambda x: x[1],
                                    reverse=True))
        return cc_ctr_sorted

    def db_versions_ctr(self, events) -> dict:
        """ Distr. of ddbb versions """
        version_ctr = Counter()
        for event in events:
            try:
                if event.plugin_version:
                    version_ctr[event.plugin_version] += 1
            except AttributeError:
                pass
        # Sorted by value
        version_ctr_sorted = dict(sorted(version_ctr.items(),
                                         key=lambda x: (x[1], x[0]),
                                         reverse=True))

        return version_ctr_sorted

    def languages_perc(self, langs):
        """ Extract percentage of languages """
        total_langs = sum(langs.values())
        lang_p = dict()
        for lang, num in langs.items():
            lang_p[lang] = round((num / total_langs) * 100, 2)

        return lang_p

    def ctr_address_reuse(self):
        """ Return address reuse """
        addresses = self.iocs_ctr.get('bitcoin')
        addresses_ctr = None
        if addresses:
            addresses_ctr = sorted(addresses.items(),
                                   key=lambda x: (x[1], x[0]),
                                   reverse=True)

        return addresses_ctr

    def address_reuse(self):
        """ Check if payment addresses are reused """
        addresses_ctr = self.ctr_address_reuse()
        if addresses_ctr:
            max_reuse = addresses_ctr[0][1]

            if max_reuse > 1:
                return True
        return False

    def get_time_active(self, events):
        """ Given event, get minimum, maximum, and days active """
        min_event, max_event = None, None
        for event in events:
            if (not min_event or (event.time is not None and event.time < min_event)):
                min_event = event.time
            if (not max_event or (event.time is not None and event.time > max_event)):
                max_event = event.time

        if max_event and min_event:
            days = (max_event - min_event).days + 1
        else:
            days = 0

        return min_event, max_event, days

    def hash_notes_normalized(self):
        """ Counter of hash note normalized -> n. notes """
        hashes_normalized = Counter()

        for nhash, note in self.nhash_note.items():
            hashes_normalized[note.hash_normalized_text] += 1

        return dict(sorted(hashes_normalized.items(),
                           key=lambda x: x[1],
                           reverse=True))

    def get_notes(self, nhash_idx):
        """ Get notes with Counter """
        notes = list()
        note_length = dict()

        for nhash, note in self.nhash_note.items():
            # Note -> n. events
            note_length[note] = len(nhash_idx.get(nhash))

        for note, n_events in sorted(note_length.items(),
                                     key=lambda x: x[1],
                                     reverse=True):
            set_iocs = set()
            for ioc in note.iocs:
                set_iocs.add((ioc.name, ioc.value))

            amounts = set()

            if note.btc_amounts:
                for amount in note.btc_amounts:
                    amounts.add(amount[1])

            notes.append({"hash_text": note.hash_text,
                          "hash_normalized_text": note.hash_normalized_text,
                          "normalized_text": note.normalized_text,
                          "events": n_events,
                          }
                         )

        return notes

    def get_ioc_ctr(self, name) -> dict:
        """ Get IOC distribution """
        iocs_dict = dict()
        if self.iocs_ctr.get(name):
            for name, value in self.iocs_ctr.get(name).items():
                iocs_dict[name] = value

        return dict(sorted(iocs_dict.items(), key=lambda x: (x[1], x[0]),
                           reverse=True))

    def get_ips(self, nhash_idx: dict) -> dict:
        """ Get IPs from cluster """
        ips = Counter()
        # Iterate Note hash -> Events
        for nhash, note in self.nhash_note.items():
            events = nhash_idx.get(nhash)
            for event in events:
                try:
                    ips[event.ip] += 1
                except AttributeError:
                    pass
        ips_sorted = dict(sorted(ips.items(), key=lambda x: (x[1]),
                                 reverse=True))

        return ips_sorted

    def get_events(self, nhash_idx: dict) -> set:
        """ Get events from cluster """
        events_set = set()
        for nhash, note in self.nhash_note.items():
            events = nhash_idx.get(nhash)
            for event in events:
                events_set.add(event)
        return events_set

    def get_os(self, nhash_idx: dict) -> dict:
        """ Return set of OS for cluster"""
        os_ctr = Counter()
        for nhash, note in self.nhash_note.items():
            events = nhash_idx.get(nhash)
            for event in events:
                try:
                    if event.infer_os:
                        os_ctr[event.infer_os] += 1
                except AttributeError:
                    pass

        return dict(sorted(os_ctr.items(), key=lambda x: (x[1], x[0]),
                           reverse=True))

    def get_amounts(self) -> dict:
        """ Return ransom amounts """
        amounts_ctr = Counter()
        for nhash, note in self.nhash_note.items():
            if note.btc_amounts:
                for amount in note.btc_amounts:
                    amounts_ctr[float(amount[1])] += 1
        return dict(sorted(amounts_ctr.items(),
                           key=lambda x: (x[1], x[0]),
                           reverse=True))

    def get_languages(self) -> dict:
        """ Return number of languages from ransom notes """
        languages_ctr = Counter()
        for nhash, note in self.nhash_note.items():
            if note.language_note:
                languages_ctr[note.language_note] += 1
        return dict(sorted(languages_ctr.items(), key=lambda x: (x[1], x[0]),
                           reverse=True))


class Clustering:
    """ Clustering """

    def __init__(self,
                 nhash_note=None,
                 normalized_nhash=None,
                 mi_clusters=None,
                 input_file=None,
                 input_file_json=None):
        # CID -> cluster
        self.clusters = dict()
        # Note hash -> Note
        self.nhash_note = {}

        # Multi-input clusters if provided
        self.mi_clusters = None

        # Index BTC address -> Cluster ID
        self.idx_btc_cid = dict()

        # Dict of note_hash -> Note
        if nhash_note is not None:
            self.nhash_note = nhash_note

        if normalized_nhash is not None:
            self.normalized_nhash_raw_nhash = normalized_nhash

        # MI clusters
        if mi_clusters is not None:
            self.mi_clusters = mi_clusters

    @staticmethod
    def get_intersection(cluster: Cluster, new_cluster: Cluster) -> set:
        """ Return BTC addresses, email addresses, and onion addresses
        in common """

        return cluster.iocs_set.intersection(new_cluster.iocs_set)

    def update_btc_idx(self):
        """ Update BTC address index """
        for cid, cluster in self.clusters.items():
            if cluster.iocs_ctr.get('bitcoin'):
                for btc in cluster.iocs_ctr.get('bitcoin'):
                    self.idx_btc_cid[btc] = cid

    def add_cluster(self, cluster: Cluster, simhash=False):
        """ Add cluster to clustering """

        cluster.longest_common_prefix()
        cluster.longest_common_substring()
        cluster.longest_common_subsequence()
        # If IR or BC, ns_cluster already implemented
        if simhash:
            cluster.ns_cluster[cluster.cid] = cluster.lcsub

        self.clusters[cluster.cid] = cluster

    def clusterize(self, cluster_by_note=False,
                   cluster_by_iocs=False,
                   cluster_by_mi=False,
                   cluster_by_exploration=False,
                   cluster_second_simhash=False,
                   threshold=None,
                   mi_clusters=None,
                   activate=True):
        """ Clusterize by note or iocs """
        if cluster_by_note:
            self.cluster_notes(threshold=threshold,
                               activate=activate)
        if cluster_by_iocs:
            self.cluster_iocs()
        if cluster_by_mi:
            self.cluster_mi(mi_clusters)
            self.mi_clusters = mi_clusters
        if cluster_second_simhash:
            self.cluster_lcs(threshold=10)
        if cluster_by_exploration:
            self.cluster_exploration(mi_clusters)
        # Update BTC Address -> Cluster ID index
        self.update_btc_idx()

    def cluster_notes(self,
                      threshold=6,
                      activate=True):
        """ Cluster events by ransom note similarity """
        from simhash import SimhashIndex

        # Create simhash index
        simhash_idx = SimhashIndex([], k=threshold)

        notes = list()
        for note in self.nhash_note.values():
            notes.append(note)

        # Maps note_hash -> (simhash,text)
        smap = create_maps_nhash(simhash_idx=simhash_idx, notes=notes)

        # Build clusters
        cluster_map = {}
        note_map = {}
        if activate:
            log.info("[+] Clustering by similarity, threshold: {}"
                     "".format(threshold))

            cluster_map, note_map = build_sim_clusters(smap=smap,
                                                       simhash_idx=simhash_idx)

            # Update map to CID -> Note
            log.info("    [+] Update map to CID -> note")
            for cid, elems in dict(sorted(cluster_map.items(),
                                          key=lambda x: len(x[1]),
                                          reverse=True)).items():
                cluster = Cluster(cid=cid)
                for nhash in elems:

                    for raw_note in self.normalized_nhash_raw_nhash.get(nhash):
                        note = self.nhash_note.get(raw_note)
                        cluster.add_note(note)

                self.add_cluster(cluster, simhash=True)
        else:
            log.info("[+] Clustering by simhash deactivated")

            for cid, (nhash, (simhash, text_note)) in enumerate(smap.items(), 1):
                cluster = Cluster(cid=cid)

                for raw_note in self.normalized_nhash_raw_nhash.get(nhash):
                    note = self.nhash_note.get(raw_note)
                    cluster.add_note(note)

                self.add_cluster(cluster, simhash=True)

        # Return maps
        return cluster_map, note_map, smap

    def cluster_iocs(self):
        """ Merge clusters that share same IOCs """
        log.info("[+] Clustering by IOCs reuse")

        new_clusters = list()

        # Iterate self.clusters
        for n_cluster, (cid, cluster) in enumerate(self.clusters.items(), 1):
            log.debug("    [+] Taking CID {}".format(cid))
            index_match = list()
            if n_cluster != 1:
                # For each cluster iterate merged cluster searching IOCs
                for index, new_cluster in enumerate(new_clusters):
                    log.debug("      [+] Searching intersection IOCS with {}"
                              "".format(new_cluster.cid))
                    union = self.get_intersection(cluster, new_cluster)
                    # If IOCs in common save the cluster index
                    if union:
                        log.debug(f"[+] Merging clusters IDs {new_cluster.cid}"
                                  f" (Size: {new_cluster.length_notes}, "
                                  f"language: {new_cluster.get_languages()})"
                                  f" in {cluster.cid} "
                                  f"(Size: {cluster.length_notes}, "
                                  f"language: {cluster.get_languages()})"
                                  f" Common IOCs: {union}")

                        index_match.append(index)

            # Merge clusters same IOCs
            merged_clusters = self.merge_clusters_iocs(new_clusters,
                                                       index_match,
                                                       cluster)
            # Remove previous clusters with same IOCs
            self.remove_common_clusters(new_clusters, index_match)
            # Add to output clusters
            new_clusters.append(merged_clusters)
        # Create self.clusters with list of clusters
        self.update_clusters(new_clusters)

    def cluster_mi(self, micluster_db: MIClusterDB):
        """ Merge clusters that BTC addresses are in same cluster from
        multi-input clustering """
        log.info("[+] Clustering by multi-input clustering")

        for n_cluster, micluster in micluster_db.miclusters.items():
            cids_to_merge = set()
            mi_cluster_set = set()
            # If more than two BTC addresses in same MI cluster, merge CIDs
            if len(micluster.seeds) > 1:
                for btc_address in micluster.seeds:
                    cid_address_belong = self.idx_btc_cid.get(btc_address)
                    if cid_address_belong:
                        cids_to_merge.add(cid_address_belong)

                # If seeds belong to same cluster, we can not cluster
                if len(cids_to_merge) > 1:
                    mi_cluster_set.add(micluster.mi_cluster)
                    # Merge clusters given a list of CIDs to merge
                    new_cluster = self.merge_clusters_cids(
                        cids_to_merge, mi_cluster_set)

                    log.info("[+] Merging component {} with seeds {}".
                             format(micluster.mi_cluster, micluster.seeds))

                    # Remove old clusters
                    self.remove_old_clusters(new_cluster.ns_cluster)

                    # Add new merged cluster to self.clusters
                    self.add_cluster(new_cluster)

    def remove_old_clusters(self, cids: set):
        """ Remove old clusters from self.clusters """
        for cid in cids:
            if self.clusters.get(cid):
                self.clusters.pop(cid)

    def merge_clusters_cids(self, cids: set, mi_cluster_set: set) -> Cluster:
        """ Merge clusters given CIDs from self.clusters """
        iocs_ctr = defaultdict(Counter)
        nhash_note = dict()
        ns_cluster = dict()

        cluster = Cluster(mi_clusters=mi_cluster_set)

        for cid in cids:

            common_cluster = self.clusters.get(cid)
            if not common_cluster:
                common_cluster = self.get_cluster_by_ns_cluster(cid)

            # Update IOCs ctr
            for name in common_cluster.iocs_ctr.keys():
                ctr = iocs_ctr.setdefault(name, Counter())
                ctr.update(common_cluster.iocs_ctr.get(name))

            # Update note hash -> Note
            nhash_note.update(common_cluster.nhash_note)
            # Update ns_cluster
            for parent, lcs in common_cluster.ns_cluster.items():
                ns_cluster[parent] = lcs

        # Assign CID to cluster
        cluster.cid = common_cluster.cid
        # Update IOCs ctr
        for name, values in iocs_ctr.items():
            ctr = cluster.iocs_ctr.setdefault(name, Counter())
            ctr.update(values)

        # Update note hash -> Note
        cluster.nhash_note.update(nhash_note)
        # Update ns_cluster
        for cid, lcs in ns_cluster.items():
            cluster.ns_cluster[cid] = lcs

        return cluster



    def get_cluster_by_ns_cluster(self, cid):
        """ Return cluster given parent CID """
        for single_cluster in self.clusters.values():
            for parent in single_cluster.ns_cluster:
                if parent == cid:
                    return single_cluster

    def update_clusters(self, out_clusters: list):
        """ Update clusters attribute with the merged clusters """
        self.clusters = dict()
        for cluster in out_clusters:
            self.add_cluster(cluster)

    def merge_clusters_iocs(self, out_clusters: list, index: list,
                            cluster: Cluster) -> Cluster:
        """ Return new merged cluster from cluster and list of clusters
        and index """
        if not index == list():
            # Cluster in common, add IOCs and nhash_note from previous clusters
            iocs_ctr = defaultdict(Counter)
            nhash_note = dict()
            ns_cluster = dict()
            iocs_set = set()

            for single_index in index:
                common_cluster = out_clusters[single_index]

                # Update iocs_ctr
                for name, values in common_cluster.iocs_ctr.items():
                    ctr = iocs_ctr.setdefault(name, Counter())
                    # Update Counters with IOCs type of each cluster
                    ctr.update(values)

                # Update IOCs set
                iocs_set.update(common_cluster.iocs_set)

                # Update note hash -> Note
                nhash_note.update(common_cluster.nhash_note)
                # NS cluster parent
                for parent, lcs in common_cluster.ns_cluster.items():
                    ns_cluster[parent] = lcs

            # Update IOCs
            for name, values in iocs_ctr.items():
                # Select IOC type from IOCs field of cluster
                ctr = cluster.iocs_ctr.setdefault(name, Counter())
                # Update the IOC counter with IOCs of other clusters
                ctr.update(values)

            # Update IOCs set
            cluster.iocs_set.update(iocs_set)

            # Add nhash_note from previous clusters to new one
            cluster.nhash_note.update(nhash_note)

            # NS cluster parent
            for nsc, lcs in ns_cluster.items():
                cluster.ns_cluster[nsc] = lcs

        return cluster

    def remove_common_clusters(self, out_clusters: list, index: list) -> list:
        """ Remove clusters with common IOCs to later add merged cluster,
         delete from last element to first to not alter order """
        if index:
            index.reverse()
            for single_index in index:
                del out_clusters[single_index]
        return out_clusters

    def add_to_output(self, out_clusters, new_cluster):
        """ Add to output clusters """
        return out_clusters.append(new_cluster)

    def print_clusters_csv(self, output_name: str,
                           include_singletons: bool = True,
                           nhash_idx = None):
        """ Save IOCs sorted by length """
        log.info("  [+] Saving CSV in {}".format(output_name))
        out_fd = open(output_name, 'w')
        out_fd.write("nhash,cid\n")

        for cluster in sorted(self.clusters.values(),
                              key=lambda x: (x.length_notes, x.length_events(nhash_idx)),
                              reverse=True):
            if include_singletons or (len(cluster.length) > 1):
                for hash_note, note in cluster.nhash_note.items():
                    out_fd.write("{},{}\n".format(hash_note, cluster.cid))

        out_fd.close()

    def print_clusters_json(self,
                            output_json,
                            nhash_idx,
                            cid_events=False,
                            include_singletons=True):
        """ Print clusters sorted by cluster size in JSON format """
        log.info("  [+] Saving in {}".format(output_json))
        log.info("  [+] Saving in {}".format(cid_events))

        out_fd = open(output_json, 'w')

        # Sort by number of notes
        for cluster in sorted(self.clusters.values(),
                              key=lambda x: (x.length_notes, x.length_events(nhash_idx)),
                              reverse=True):
            if include_singletons or (len(cluster.length_notes) > 1):
                out_fd.write("{}\n".format(cluster.json_large(nhash_idx,
                                                              self.mi_clusters,
                                                              cid_events
                                                              )))

        out_fd.close()


def longest_common_subsequence(list_notes):
    """ Longest Common subsequence """
    import pylcs

    delimiter = '[...]'
    final_subsequence = ''
    first = list_notes[0]
    list_notes.pop(0)

    if not list_notes:
        return first
    else:
        subsequence = first
        for n_note, note in enumerate(list_notes, 1):
            previous_idx = -1
            subsequence_generated = ''
            res = pylcs.lcs_sequence_idx(subsequence, note)

            for index in res:
                if index != -1:
                    if previous_idx + 1 == index:
                        subsequence_generated += note[index]
                    else:
                        subsequence_generated += '{}{}'.format(delimiter,
                                                               note[index])
                previous_idx = index

            subsequence = subsequence_generated

        parts = subsequence.split('{}'.format(delimiter))
        for n_part, part in enumerate(parts, 1):
            if len(part) >= threshold_parts:
                final_subsequence += "{}{}".format(part, delimiter)

            if len(part) < threshold_parts and n_part == len(parts):
                final_subsequence += "{}".format(delimiter)

        return final_subsequence[:-len(delimiter)]


def single_regex(text):
    """  """
    escaped = re.escape(text)
    replaced = '.{{{},}}'.format(threshold_parts)
    regex = escaped.replace(re.escape('[...]'), replaced)

    searcher.patterns['list'] = [re.compile(list_id, re.IGNORECASE)]
    searcher.patterns['token'] = [re.compile(number_id, re.IGNORECASE)]
    searcher.patterns['amount'] = [re.compile(number_regex, re.IGNORECASE)]

    for ioc_type in re.findall('<[A-Z]+>', regex):
        ioc_normalized = ioc_type[1:-1].lower()
        if ioc_normalized == 'onionaddress':
            regex_ioc = searcher.patterns.get('onionAddress')[1].pattern[
                        :16]
        else:
            regex_ioc = searcher.patterns.get(ioc_normalized)[0].pattern

        regex = regex.replace(ioc_type, regex_ioc)

    return '.*' + regex + '.*'
