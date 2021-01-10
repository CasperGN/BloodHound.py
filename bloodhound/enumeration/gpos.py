####################
#
# Copyright (c) 2018 Fox-IT
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
####################

import logging
import codecs
import json
from bloodhound.ad.utils import ADUtils, AceResolver
from bloodhound.ad.trusts import ADDomainTrust
from bloodhound.enumeration.acls import parse_binary_acl

class GPOEnumerator(object):
    """
    Class to enumerate GPOs in the domain.
    Contains the dumping functions which
    methods from the bloodhound.ad module.
    """
    def __init__(self, addomain, addc):
        """
        GPO enumeration. Enumerates all GPOs found within the domain.
        """
        self.addomain = addomain
        self.addc = addc

    def dump_gpos(self, gpos, filename='gpos.json'):
        """
        Dump GPOs. 
        """

        try:
            logging.debug('Opening file for writing: %s' % filename)
            out = codecs.open(filename, 'w', 'utf-8')
        except:
            logging.warning('Could not write file: %s' % filename)
            return

        # If the logging level is DEBUG, we ident the objects
        if logging.getLogger().getEffectiveLevel() == logging.DEBUG:
            indent_level = 1
        else:
            indent_level = None

        # Initialize json structure
        datastruct = {
            "gpos": gpos,
            "meta": {
                "type": "gpos",
                "count": len(gpos),
                "version":3
            }
        }

        json.dump(datastruct, out, indent=indent_level)

        logging.debug('Finished writing gpo info')
        out.close()

    def enumerate_gpos(self):
        gpos = []
        resolver = AceResolver(self.addomain, self.addomain.objectresolver)
        entries = self.addc.get_gpos()
        for entry in entries:
            gpo = {
                    "Properties": {
                        "highvalue": ADUtils.get_entry_property(entry, 'isCriticalSystemObject', default=False),
                        "name": ADUtils.get_entry_property(entry, 'displayName'),
                        "domain": '.'.join(str(ADUtils.get_entry_property(entry, 'distinguishedName')).split('DC')[1:]).translate({ord(c):'' for c in '=,'}),
                        "objectid": str(ADUtils.get_entry_property(entry, 'objectGUID')).translate({ord(c):'' for c in '}{'}),
                        "distinguishedname": ADUtils.get_entry_property(entry, 'distinguishedName'),
                        "description": None,
                        "gpcpath": ADUtils.get_entry_property(entry, 'gPCFileSysPath')
                    },
                    "ObjectIdentifier": str(ADUtils.get_entry_property(entry, 'objectGUID')).translate({ord(c):'' for c in '}{'}),
                    "Aces": []
            }

            _, aces = parse_binary_acl(gpo, 'gpo', ADUtils.get_entry_property(entry, 'nTSecurityDescriptor'), self.addc.objecttype_guid_map)
            gpo['Aces'] = resolver.resolve_aces(aces)
            gpos.append(gpo)
           
        self.dump_gpos(gpos)