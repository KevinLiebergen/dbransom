import re


def check_note_true_positive(note: str):
    """ Return True if note is true positive """
    check_ransom_note = r"hacked|backed|backup|BTC|onion|恢复|bitcoin|recover9001@protonmail.com|XMR"
    if re.search(check_ransom_note, note):
        if note[:4] == "1???":
            return False

        return True
    return False


def check_plugin(event, allow_plugins=None):
    """ Discard if plugin not in list """
    if allow_plugins is None:
        allow_plugins = ['ElasticSearchOpenPlugin',
                         'MysqlOpenPlugin',
                         'mysql_honeypot']

    if not event.plugin or (event.plugin in allow_plugins):
        return True
    else:
        return False


def remove_fn_notes(event):
    """ Return TP notes from event """
    # Exclude FP notes
    if event.notes:
        for note in event.notes.copy():
            if not check_note_true_positive(note.text):
                # Include only TP notes
                event.notes.remove(note)
    return event


def filter_event(event, allow_plugins=None):
    """
    By default, for dataset with infected true label.
    ElasticSearch and MySQL events have ransom notes,
    reason why we only read these plugins
    """
    if check_plugin(event, allow_plugins):
        return remove_fn_notes(event)
    return None
