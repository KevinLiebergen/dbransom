from iocsearcher.searcher import Searcher

searcher = Searcher()


def handle_iocs(raw_iocs):
    """ Wrapper to handle emails and iocs """
    for n_raw_ioc, raw_ioc in enumerate(raw_iocs):
        handle_email(n_raw_ioc, raw_ioc, raw_iocs)
        handle_url(n_raw_ioc, raw_ioc, raw_iocs)
    return raw_iocs


def handle_email(n_raw_ioc, raw_ioc, raw_iocs):
    """
    This dataset has a peculiarity in that there is no word boundary
    before many emails and they get often concatenated with
    leading bitcoin addresses.
    The case is so prevalent that we specially handle it
    """

    if raw_ioc[0] == 'email':

        btcs = searcher.search_raw(raw_ioc[3],
                                   targets=['bitcoin'])

        if btcs:
            for btc in btcs:
                # Update FPs adding BTC address in the email
                btc_offset = btc[2]
                btc_length = len(btc[1])
                start_mail = btc_offset + btc_length
                # Create new IOC of email
                ioc_formatted = searcher.search_raw(raw_ioc[1][start_mail:],
                                                    targets=['email'])[0]

                # Calculate offset and add new IOC to list
                listed = list(ioc_formatted)
                listed[2] = raw_ioc[2] + start_mail
                ioc_formatted = tuple(listed)

                raw_iocs.append(ioc_formatted)
                # Remove wrong IOC
                del raw_iocs[n_raw_ioc]


def handle_url(n_raw_ioc, raw_ioc, raw_iocs):
    """
    There is a http after the html, there are 2 URLs joined.
    The case is so prevalent that we specially handle it
    """
    # Fix 2 URLs joined
    if raw_ioc[0] == 'url' and "htmlhttp" in raw_ioc[3]:
        # Hardcode split in 2
        index = raw_ioc[1].index('htmlhttp')
        f_url = raw_ioc[1][:index + 4]
        f_ioc = searcher.search_raw(f_url, targets=["url"])[0]

        # Calculate offset
        listed = list(f_ioc)
        listed[2] = raw_ioc[2]
        ioc_formatted = tuple(listed)
        # Add new IOC to list
        raw_iocs.append(ioc_formatted)

        end_url = 'onion'
        end_s_url = raw_ioc[1].index(end_url)
        start_url = index + 4
        end_url = end_s_url + len(end_url)
        s_url = raw_ioc[1][start_url:end_url]

        s_ioc = searcher.search_raw(s_url, targets=['url'])[0]
        # Calculate new offset
        listed_url = list(s_ioc)
        listed_url[2] = listed[2] + start_url
        ioc_formatted = tuple(listed_url)

        raw_iocs.append(ioc_formatted)

        del raw_iocs[n_raw_ioc]
