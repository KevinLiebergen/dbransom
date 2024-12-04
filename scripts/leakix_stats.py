import argparse
import logging
import timeit
import sys
import os

# Imports
script_dir = os.path.dirname(os.path.abspath(__file__))

lib_dir = os.path.join(script_dir, 'lib/')
sys.path.append(lib_dir)

from leakix import LeakIXDB
from grouping import MIClusterDB

# To create attribution graph
attribution_dir = os.path.join(script_dir, '../../../attribution/framework/')
sys.path.append(attribution_dir)


# Default similarity threshold
default_threshold = 6

# Logging to file
output_dir = os.path.join(script_dir, 'output/')

log_name = os.path.join(output_dir, 'leakix_stats.logs')
sys.stdout.write("[+] Saving logs in {}\n".format(log_name))

logging.basicConfig(filename=log_name,
                    filemode='w',
                    level=logging.DEBUG)
# Logging to console
console = logging.StreamHandler()
logging.getLogger('').addHandler(console)

log = logging.getLogger(__name__)

# Avoid log messages from specific modules below given log level
logging.getLogger("simhash").setLevel(logging.CRITICAL)
logging.getLogger("searcher").setLevel(logging.INFO)
logging.getLogger("clustering").setLevel(logging.DEBUG)
logging.getLogger("iocsearcher").setLevel(logging.ERROR)
logging.getLogger("filelock").setLevel(logging.INFO)

# Default output file
default_iocs_out_file = os.path.join(output_dir, "iocs.clusters.jsonl")
nhash_cid_out_file = os.path.join(output_dir, "leakix_nhash_cid.csv")
default_mi_out_json_file = os.path.join(output_dir, "multi_input."
                                                    "clusters.jsonl")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog='LeakIX events summary')

    parser.add_argument('-i', help='LeakIX JSONL input.', required=False,
                        action='append')

    parser.add_argument('-nn', help='Not normalize notes.',
                        action='store_false')

    # Select if cluster by similarity or provide a similarity clustering file
    parser.add_argument('-cs', '--cluster-sim', action='store_true',
                        help='cluster events by ransom note similarity')

    parser.add_argument('-t', '--threshold', default=default_threshold,
                        type=int, help='similarity threshold')

    parser.add_argument('-d', '--deactivatesimhash', action='store_false',
                        help='Deactivate simhash')

    parser.add_argument('-csf', '--cluster-similarity-file',
                        help='Clustering by similarity note file')

    # Select if cluster by IOC or provide an IOC clustering file
    parser.add_argument('-ci', '--cluster-ioc', action='store_true',
                        help='cluster events by IOCs')

    # Cluster by exploration file
    parser.add_argument('-mic', '--mi-cluster',
                        help='cluster events that BTC addresses are in same '
                             'component.')

    args = parser.parse_args()

    start = timeit.default_timer()

    console.setLevel(logging.INFO)

    # Check that we have something to do
    if not args.i:
        log.info("Need to provide input file (-i)\n")
        sys.exit(1)

    if args.i:
        i_filepath = args.i
    else:
        i_filepath = []

    leakix = LeakIXDB(filepath=i_filepath, normalize=args.nn)

    leakix.export_events_no_fps()
    leakix.export_notes_no_fps()

    # Extract stats and IOCs and print stats
    leakix.extract_stats()
    leakix.print_stats()
    leakix.save_btc_addresses('leakix_btc.addresses')

    # Print and export IOCs
    ioc_ctr = leakix.print_iocs()
    leakix.export_iocs(output_dir)

    stop = timeit.default_timer()

    log.info("[+] Dataset read in {} mins".format(round((stop-start) / 60, 2)))

    # Load MI clustering file if provided
    if args.mi_cluster:
        mi_clusters = MIClusterDB(args.mi_cluster)
        leakix.clustering.mi_clusters = mi_clusters

    # Cluster by note similarity
    if args.cluster_sim:
        leakix.clustering.clusterize(cluster_by_note=True,
                                     threshold=args.threshold,
                                     activate=args.deactivatesimhash)

        leakix.clustering.print_clusters_csv(nhash_cid_out_file,
                                             nhash_idx=leakix.nhash_idx)

        # Default output file
        name_file = "leakix_{}_sim.clusters.jsonl".format(args.threshold)
        default_iocs_out_json_file = os.path.join(output_dir, name_file)

        nscid_events = os.path.join(output_dir, 'nscid_events.csv')

        leakix.clustering.print_clusters_json(output_json=default_iocs_out_json_file,
                                              nhash_idx=leakix.nhash_idx,
                                              cid_events=nscid_events
                                              )

    # Cluster by IOCs
    if args.cluster_ioc:
        leakix.clustering.clusterize(cluster_by_iocs=True)

        iocid_events = os.path.join(output_dir, 'iocid_events.csv')

        leakix.clustering.print_clusters_json(default_iocs_out_file,
                                              leakix.nhash_idx,
                                              cid_events=iocid_events
                                              )

    # Cluster by multi-input clustering
    if args.mi_cluster:
        mi_clusters = MIClusterDB(args.mi_cluster)
        leakix.clustering.clusterize(cluster_by_mi=True,
                                     mi_clusters=mi_clusters)

        micid_events = os.path.join(output_dir, 'micid_events.csv')

        leakix.clustering.print_clusters_json(default_mi_out_json_file,
                                              leakix.nhash_idx,
                                              cid_events=micid_events
                                              )
