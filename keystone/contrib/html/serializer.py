# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""
Dict <--> XML de/serializer.

The identity API prefers attributes over elements, so we serialize that way
by convention, with a few hardcoded exceptions.

"""

import collections
import re


def from_html(html):
    """Deserialize XML to a dictionary."""
    if html is None:
        return None
    data = {}
    for param in html.split('&'):
        tokens = param.split('=')
        if len(tokens) < 2:
            continue
        data[tokens[0]] = tokens[1]
    return {'form': data}


def list_to_html(d):
    out = "<ul>"
    for v in d:
        out += "<li>%s</li>\n" % item_to_html(v)
    out += "</ul>\n"
    return out


def item_to_html(v):
    if isinstance(v, collections.MutableMapping):
        out = dict_to_html(v)
    elif isinstance(v, list):
        out = list_to_html(v)
    elif v is None:
        out = ""
    else:
        out = str(v)
    return out


def key_value_to_html(k, v):
    out = "<dt>%s</dt>\n" % k
    out += "<dd>"
    out += item_to_html(v)
    out += "</dd>\n"
    return out


def href_as_html(k, v):
    return '<dt>link</dt><dd><a href=%s>%s</a></dd>' % (v, v)


def dict_to_html(d):
    out = "<dl>"
    for k, v in d.items():
        if k == 'href':
            out += href_as_html(k, v)
        else:
            out += key_value_to_html(k, v)
    out += "</dl>\n"
    return out


def to_html(d, xmlns=None):
    """Serialize a dictionary to XML."""
    if d is None:
        return None
    header = ('<!DOCTYPE html>' +
              '<html xmlns="http://www.w3.org/1999/xhtml"' +
              ' xml:lang="en" lang="en" dir="ltr">\n' +
              '<head></head>\n')
    body = '<body>' + dict_to_html(d) + '</body>\n'
    footer = '</html>\n'
    doc = header + body + footer
    return unicode(doc)
