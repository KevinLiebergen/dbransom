from collections import Counter
from collections import defaultdict
from iocsearcher.document import open_document
from iocsearcher.searcher import Searcher
from ioc_handler import handle_iocs
from hashlib import sha256
import json
from langdetect import detect
import logging
import os
import re

searcher = Searcher()

# Set logging
log = logging.getLogger(__name__)

# Regex of number with and without decimals
number_regex = '([0-9]+([.][0-9]+)?)'
btc_regex = '( )?(比特币|BTC|bitcoin|XMR)'
amount_regex = '(' + number_regex + btc_regex + ')'

# Regex list
list_id = "((\s?([0-9a-zA-Z#_\-\+?]+\s?)[,。.])+)"
list_reg = r"([:：]" + list_id + "\s)"

# Regex token
preceded_word = "(?:token|code|ID to)"
number_id = "([0-9a-zA-Z]+)"
token_reg = preceded_word + r"[:]?[ ]+[`'\"]?" + number_id + r"[`'\"]?\b"
dbcode_reg = "Your DBCODE is: ([A-Z0-9]{3,6})"

tokens = list()
tokens.append(token_reg)
#tokens.append(dbcode_reg)

disposable = ["mailinator.com",
              "mailnesia.com",
              "airmail.cc",
              "grr.la",
              "binkmail.com",
              "bobmail.info",
              "pokemail.net",
              "sharklasers.com",
              "chacuo.net"]


def transform_newlines(text):
    """ Transform newlines into spaces """
    # Newline into spaces
    pattern = "\n{1,}"
    new_text = re.sub(pattern, " ", text)
    # Replace '\t' with space
    pattern = "\t{1,}"
    new_text = re.sub(pattern, " ", new_text)
    # Replace many spaces with one space
    pattern = " {1,}"
    new_text = re.sub(pattern, " ", new_text)
    return new_text


class Note:
    """ Ransomware note class """

    def __init__(self,
                 text: str,
                 normalize=True):

        self.text = text
        self.hash_text = sha256(self.text.encode('utf-8')).hexdigest()

        self.normalized_text = ""

        # Extract IOCs from ransomware note text
        self.iocs = set()
        self.normalize_extract_iocs(normalize=normalize)
        self.sentences = []
        self.split_sentences()

        # Hash note
        self.hash_normalized_text = sha256(self.normalized_text.encode('utf-8')).hexdigest()

    @staticmethod
    def format_html_note(text):
        """ Save HTML to format it with IOC Searcher """
        # Create filename with SHA256
        sha256_note = sha256(text.encode()).hexdigest()
        filename = sha256_note + '.download'
        output_file = os.path.join('/tmp/', filename)
        with open(output_file, 'w', encoding="utf-8") as out:
            out.write('{}'.format(text))
        # Open and format document
        try:
            doc = open_document(output_file)
            text = doc.get_text()[0]
        except AttributeError:
            pass

        return text

    @property
    def btc_amounts(self):
        """ Extract BTC amounts given note """
        if re.findall(amount_regex, self.text, re.IGNORECASE):
            amount_w_btc = re.findall(amount_regex, self.text, re.IGNORECASE)
            return amount_w_btc
        return None

    @property
    def language_note(self):
        # For english hardcoded database names
        if "以下数据库已被删除" in self.text or "您需要支付" in self.text:
            return "zh-cn"

        if "?????????" in self.text:
            return None

        try:
            lang = detect(self.text)
        except:
            lang = None

        if lang != "en" and lang != "zh-cn":
            log.debug("Language note: {}. Text: {}".format(lang, self.text))
        return lang

    def split_sentences(self):
        """ Split by sentences by regex """
        # Split by special char
        chinese_dot = r"[。]"
        special_char = r"([.?!！\n][\s<]+)"
        # Split by indicator macro unless AMOUNT,
        # optionally followed by one or more spaces and an upper case letter
        indicators = r'(<(?!AMOUNT)[A-Z]*>\s+[A-Z])'
        dot_upper = r'[.][A-Z]'
        regex_sentence = chinese_dot + '|' + special_char + '|' + \
                         indicators + '|' + dot_upper

        previous_offset = 0
        for m in re.compile(regex_sentence).finditer(self.normalized_text):
            if '>' in m.group():
                offset = m.end() - 2
            # elif '<' in m.group():
            #     offset = m.start() + 1
            elif '。' in m.group():
                offset = m.start() + 1
            else:
                offset = m.start() + 1
            text = self.normalized_text[previous_offset:offset]
            self.sentences.append(text.strip())
            previous_offset = offset

        text = self.normalized_text[previous_offset:]
        self.sentences.append(text.strip())

    def extract_amount_from_all(self, amount):
        """ Extract btc word in chenese or english """
        return re.search(btc_regex, amount, re.IGNORECASE).group()

    def normalize_btc_amounts(self, text):
        # Normalize BTC amounts
        if self.btc_amounts:
            for amount in self.btc_amounts:
                # amount_normalized = "<AMOUNT>{}".format(amount[3])
                text = text.replace(amount[0],
                                    "<AMOUNT>{}{}".format(amount[3], amount[4])
                                    )
            return text

        return text

    def check_lists(self, text):
        """ Check list with regex """
        return re.findall(list_reg, text)

    def normalize_lists(self, text):
        # Normalize lists
        matches = self.check_lists(text)

        if matches:
            for match in matches:
                text = text.replace(match[1], " <LIST>")
        return text

    def check_tokens(self, text):
        """ Check if tokens """
        # Normalize tokens
        results = list()
        for reg in tokens:
            if re.findall(reg, text):
                results.append(re.findall(reg, text))

        return results

    def normalize_tokens(self, text):
        matches = self.check_tokens(text)
        if matches:
            for match in matches:
                text = text.replace(match[0], "<TOKEN>")
        return text

    def change_order(self, iocs_note):
        """ Append fqdn to list of IOCs and bitcoin at the beginning """
        # Extract tuples with "fqdn"
        # Sort by length, prioritize URL before ONION ADDRESS
        iocs_note = sorted(iocs_note, key=len, reverse=True)

        fqdn_tuples = [item for item in iocs_note if item.name == 'fqdn']

        # Remove these tuples from the original list
        iocs_note = [item for item in iocs_note if item.name != 'fqdn']

        # Append the fqdn tuples to the end of the list
        iocs_note.extend(fqdn_tuples)

        # Extract tuples with "bitcoin"
        bitcoin_tuples = [item for item in iocs_note if item.name == 'bitcoin']

        # Remove these tuples from the original list
        iocs_note = [item for item in iocs_note if item.name != 'bitcoin']

        # Add the bitcoin tuples to the beginning of the list
        iocs_note = bitcoin_tuples + iocs_note

        return iocs_note

    def extract_iocs(self, text, targets=None):
        """ Extract IOCs """
        raw_iocs = searcher.search_raw(text, targets=targets)
        raw_iocs = handle_iocs(raw_iocs)

        return raw_iocs

    def normalize_iocs(self, text):
        """ Normalize IOCs """
        iocs_ordered = self.change_order(self.iocs)

        # Normalize IOCs
        for ioc in iocs_ordered:
            if ioc.name == 'bitcoin':
                # Replace IOCs
                replaced = '<' + ioc.name.upper() + '>'
                text = text.replace(ioc.value, replaced)

        raw_iocs = searcher.search_raw(text, targets=None)

        for ioc in raw_iocs:
            self.iocs.add(searcher.create_ioc(ioc[0], ioc[3]))

        iocs_ordered = self.change_order(self.iocs)

        for ioc in iocs_ordered:
            self.iocs.add(ioc)
            # Replace IOCs
            replaced = '<' + ioc.name.upper() + '>'
            text = text.replace(ioc.value, replaced)

        return text

    def add_iocs(self, text, targets=None):
        """ Normalize IOCs """
        iocs_note = self.extract_iocs(text, targets)

        for ioc in iocs_note:
            # Transform to conventional IOC object
            self.iocs.add(searcher.create_ioc(ioc[0], ioc[3]))

    def get_longest_value(self, jsonized):
        """ Get key with longest value from the dict """
        longest_key_value = list(jsonized.keys())[0]
        for key, value in jsonized.items():
            if len(str(value)) > len(str(jsonized.get(longest_key_value))):
                longest_key_value = key

        return jsonized.get(longest_key_value)

    def longest_value_if_json(self, new_text):
        """ If JSON, get the ransom note """

        try:
            # If JSON, keep longest value
            jsonized = json.loads(new_text)

        except json.decoder.JSONDecodeError:
            return new_text
        except AttributeError:
            return new_text
        except ValueError:
            return new_text
        except SyntaxError:
            return new_text
        if isinstance(jsonized, int):
            return new_text

        def longest_field(longest, field):
            value_l = field.values() if type(field) is dict else field
            for value in value_l:
                # print(type(value))
                if (type(value) is dict) or (type(value) is list):
                    longest = longest_field(longest, value)
                elif type(value) is str:
                    l = len(value)
                    if l > longest[1]:
                        longest = (value, l)
            return longest

        new_text = longest_field(("", 0), jsonized)[0]
        return new_text

    def normalize_extract_iocs(self, normalize=True):
        """ Extract and replace IOCs from ransom notes using given Searcher """
        self.add_iocs(self.normalize_tokens(self.normalize_btc_amounts(self.text)))

        new_text = self.text

        if normalize:
            new_text = self.longest_value_if_json(new_text)

            new_text = transform_newlines(new_text)
            new_text = self.normalize_btc_amounts(new_text)
            new_text = self.normalize_tokens(new_text)
            new_text = self.normalize_iocs(new_text)
            new_text = self.normalize_lists(new_text)

        self.normalized_text = new_text

    @property
    def vuln_mentioned(self):
        """ CVEs mentioned in the note text """
        cves = 0
        for ioc in self.iocs:
            if ioc.name == 'cve':
                cves += 1
        return cves

    @property
    def disposable_emails(self) -> list:
        """ Disposable emails in note text """
        set_emails = set()
        for ioc in self.iocs:
            if ioc.name == 'email' and ioc.value.split('@')[1] in disposable:
                set_emails.add(ioc.value)

        return list(set_emails)

    @property
    def obfuscation_type(self):
        """ Based on the note text """
        import chardet

        obfuscations = list()
        str_detect = chardet.detect(str.encode(self.text))

        # Encoding obfuscation
        if str_detect.get('encoding') != 'ascii' \
                and str_detect.get('encoding') != 'utf-8' \
                and str_detect.get('encoding') != 'Windows-1252':
            obfuscations.append('unicode char')

        # BTC address split TODO refine
        if 'Part 1' in self.text:
            obfuscations.append('btc address')

        # Email address

        return obfuscations

    @property
    def payment_mechanism(self):
        """ Extract address dict from IOCs """
        n_payments = Counter()

        for ioc in self.iocs:
            if ioc.name == 'bitcoin':
                n_payments['bitcoin'] += 1
            elif ioc.name == 'bitcoincash':
                n_payments['bitcoincash'] += 1
            elif ioc.name == 'cardano':
                n_payments['cardano'] += 1
            elif ioc.name == 'dashcoin':
                n_payments['dashcoin'] += 1
            elif ioc.name == 'dogecoin':
                n_payments['dogecoin'] += 1
            elif ioc.name == 'ethereum':
                n_payments['ethereum'] += 1
            elif ioc.name == 'litecoin':
                n_payments['litecoin'] += 1
            elif ioc.name == 'monero':
                n_payments['monero'] += 1
            elif ioc.name == 'ripple':
                n_payments['ripple'] += 1
            elif ioc.name == 'tezos':
                n_payments['tezos'] += 1
            elif ioc.name == 'tronix':
                n_payments['tronix'] += 1
            elif ioc.name == 'webmoney':
                n_payments['webmoney'] += 1
            elif ioc.name == 'zcash':
                n_payments['zcash'] += 1

        return n_payments

    @property
    def contact_mechanism(self):
        """ Extract types of contact mechanisms """
        n_contacts = Counter()
        regex_iocs_keys = "\<[a-zA-Z]*\>"

        if self.language_note and self.language_note == "en":
            regex_contact = "(email (to )?(me|us))|(contact (to )?(me|us))|(write (to )?(me|us))|(visit)|(get in touch)"
        elif self.language_note and self.language_note == "zh-cn":
            regex_contact = ""
            log.debug("[+] Contact mechanism not implemented in "
                      "Chinese notes")
        else:
            regex_contact = ""

        for sentence in self.sentences:
            if re.search(regex_contact, sentence, re.IGNORECASE):
                for ioctype in re.findall(regex_iocs_keys,
                                          sentence,
                                          re.IGNORECASE):
                    n_contacts[ioctype] += 1

        return n_contacts

    @property
    def payment_address_obtaining(self):
        """ How do we obtain payment address """
        dict_iocs = defaultdict(set)
        for ioc in self.iocs:
            dict_iocs[ioc.name].add(ioc.value)

        if not dict_iocs:
            return 'No way to obtain payment address'

        if dict_iocs.get('bitcoin') or dict_iocs.get('monero'):
            return 'By blockchain_address'
        elif dict_iocs.get('email'):
            return 'By email'
        elif dict_iocs.get('onionAddress'):
            return 'By onion'
        elif dict_iocs.get('url'):
            return 'By URL'
        else:
            return 'No way to obtain payment address'
