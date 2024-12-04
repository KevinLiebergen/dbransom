from iocsearcher.ioc import Ioc


class FilterIocs:
    def __init__(self, iocs_note: set):
        self.iocs_note = iocs_note
        self.is_generic_ioc()

    def is_generic_ioc(self):
        """ Check if emails and URLs are false positives"""
        self.check_email()
        self.check_url()

    def check_email(self):
        """ Discard if email length > 27 """
        iocs_note_copy = self.iocs_note.copy()
        for ioc in self.iocs_note:
            if ioc.name == 'email' and len(ioc.value) > 27:
                iocs_note_copy.discard(ioc)
        self.iocs_note = iocs_note_copy

    def check_url(self):
        """ Check specific example and split if two URLs are together """
        iocs_note_copy = self.iocs_note.copy()
        for ioc in self.iocs_note:
            if 'browser.htmlhttp' in ioc.value:
                # Specific example with specific length
                first_url = ioc.value[:51]
                # Remove redundant part after .onion
                second_url = ioc.value[51:].split('.onion', 2)[0] + '.onion'
                iocs_note_copy.discard(ioc)
                iocs_note_copy.add(Ioc('url', first_url))
                iocs_note_copy.add(Ioc('onionAddress', second_url))

        self.iocs_note = iocs_note_copy
