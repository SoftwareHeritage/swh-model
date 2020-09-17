# Copyright (C) 2019 The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

from datetime import datetime
from random import choice, randint, random, shuffle
from typing import Dict, List

from pytz import all_timezones, timezone

from swh.model.hashutil import MultiHash

PROTOCOLS = ["git", "http", "https", "deb", "svn", "mock"]
DOMAINS = ["example.com", "some.long.host.name", "xn--n28h.tld"]
PATHS = [
    "",
    "/",
    "/stuff",
    "/stuff/",
    "/path/to/resource",
    "/path/with/anchor#id=42",
    "/path/with/qargs?q=1&b",
]
CONTENT_STATUS = ["visible", "hidden", "absent"]
MAX_DATE = 3e9  # around 2065


def gen_all_origins():
    for protocol in PROTOCOLS:
        for domain in DOMAINS:
            for urlpath in PATHS:
                yield {"url": "%s://%s%s" % (protocol, domain, urlpath)}


ORIGINS = list(gen_all_origins())


def gen_origins(n: int = 100) -> List:
    """Returns a list of n randomly generated origins suitable for using as
    Storage.add_origin() argument.

    """
    origins = ORIGINS[:]
    shuffle(origins)
    return origins[:n]


def gen_content():
    size = randint(1, 10 * 1024)
    data = bytes(randint(0, 255) for i in range(size))
    status = choice(CONTENT_STATUS)
    h = MultiHash.from_data(data)
    ctime = datetime.fromtimestamp(random() * MAX_DATE, timezone(choice(all_timezones)))
    content = {
        "data": data,
        "status": status,
        "length": size,
        "ctime": ctime,
        **h.digest(),
    }
    if status == "absent":
        content["reason"] = "why not"
        content["data"] = None
    return content


def gen_contents(n=20) -> List[Dict]:
    """Returns a list of n randomly generated content objects (as dict) suitable
    for using as Storage.content_add() argument.
    """
    return [gen_content() for i in range(n)]
