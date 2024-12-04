from iocsearcher.searcher import Searcher
from collections import defaultdict
from collections import Counter
import logging
import sys
import os

searcher = Searcher()

# Output directory
script_dir = os.path.dirname(os.path.abspath(__file__))
output_dir = os.path.join(script_dir, '../output/')

# Set logging
log = logging.getLogger(__name__)

# Avoid log messages from specific modules below given log level
logging.getLogger("charset_normalizer").setLevel(logging.INFO)


class WideScannerDB:
    """ Parent class for LeakIX, Shodan, and Censys """
    def __init__(self):
        self.events = set()

        # Index note_hash -> event set
        self.nhash_idx = {}
        # Index note_hash -> Note
        self.nhash_note = {}
        self.normalized_nhash_raw_nhash = defaultdict(set)
        # BTC -> event set
        self.btc_idx = dict()

        # Related with ransom notes
        self.notes = set()
        self.norm_notes = set()
        self.iocs = set()
        self.btc_amounts_ctr = Counter()

    def __len__(self):
        return len(self.events)

    def get_reusable_btc_addresses(self, out_file: str):
        """ Save BTC addresses appearing in more than one IP """
        output_file = os.path.join(output_dir, out_file)

        log.info("[+] Saving in {}".format(output_file))
        fd_out = open(output_file, 'w')
        for btc_address, ips_dict in self.btc_idx.items():
            if len(ips_dict) > 1:
                for ip, events in ips_dict.items():
                    for event in events:
                        fd_out.write("{}\t{}:{}\t{}\t{}\t{}\n"
                                     "".format(btc_address,
                                               event.ip,
                                               event.port,
                                               event.isp,
                                               event.fqdn,
                                               event.timestamp))

    def save_btc_addresses(self, filepath_output):
        """ Export BTC addresses to file """
        out_file = os.path.join(output_dir, filepath_output)

        out_fd = open(out_file, 'w')
        log.info("[+] Saving BTC addresses in {}".format(out_file))

        for ioc in self.iocs:
            if ioc.name == 'bitcoin':
                out_fd.write("{}\n".format(ioc.value))

    def print_iocs(self):
        """ Print IOCs """
        iocs_ctr = defaultdict(set)
        # Iterate over events gathering IOC stats
        for ioc in self.iocs:
            iocs_ctr[ioc.name].add(ioc.value)

        sys.stdout.write('IOCs:\n')
        for ioc_name, values in sorted(iocs_ctr.items(),
                                       key=lambda p: len(p[1]),
                                       reverse=True):
            sys.stdout.write('  %s\t%d\n' % (ioc_name, len(values)))

        return iocs_ctr

    def export_iocs(self, filepath):
        """ Print IOCs """
        # self.export_features_tsv(filepath)
        self.export_tsv(filepath)

    def export_features_tsv(self, path):
        """ Export IOCs, amount, token, and list to TSV """
        filepath = os.path.join(path, "iocs.tsv")
        fd = open(filepath, 'w')
        log.info("[+] Saving IOCs in {}".format(filepath))
        fd.write("note_hash\tstart_offset\tlength\tstring\tioc_type\t"
                 "ioc_value\n")

        for nhash, note in self.nhash_note.items():
            # IOCs
            for raw_ioc in note.iocs:  # hash_text_raw_iocs:

                fd.write("{}\t{}\t{}\t{}\t{}\t{}\n".format(nhash,
                                                           raw_ioc[2],
                                                           len(raw_ioc[3]),
                                                           repr(raw_ioc[3]),
                                                           raw_ioc[0],
                                                           repr(raw_ioc[1]))
                         )

    def export_tsv(self, path):
        """ Export IOCs to TSV """
        filepath = os.path.join(path, 'notes.iocs')
        fd = open(filepath, 'w')
        log.info("[+] Saving IOCs in {}".format(filepath))

        iocs_ctr = defaultdict(set)
        # Iterate over events gathering IOC stats
        for ioc in self.iocs:
            iocs_ctr[ioc.name].add(ioc.value)

        for ioc_name, values in sorted(iocs_ctr.items(),
                                       key=lambda p: len(p[1]),
                                       reverse=True):
            for value in values:
                fd.write('{}\t{}\n'.format(ioc_name, value))

    def extract_specific_ioc(self, target=None):
        """ Extract specific IOC """
        iocs = set()
        for ioc in self.iocs:
            if target == ioc.name:
                iocs.add((ioc.name, ioc.value))
        return iocs
