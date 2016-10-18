#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# Copyright (C) 2016 John Zhao
#
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.
#
# You should have received a copy of the GNU General Public License along
# with this program.  If not, see <http://www.gnu.org/licenses/>.

import sys
import shutil
import tempfile
import libtorrent as lt
from time import sleep


tempdir = tempfile.mkdtemp()
ses = lt.session()

magnet = 'magnet:?xt=urn:btih:0abdb5da58075be76bbccdbf65ac2ba40bd86314'

params = {
    'save_path': tempdir,
    'storage_mode': lt.storage_mode_t(2),
    'paused': False,
    'auto_managed': True,
    'duplicate_is_error': True
}

handle = lt.add_magnet_uri(ses, magnet, params)

print("Downloading Metadata (this may take a while)")

while (not handle.has_metadata()):
    try:
        sleep(1)
    except KeyboardInterrupt:
        print("Aborting...")
        ses.pause()
        print("Cleanup dir " + tempdir)
        shutil.rmtree(tempdir)
        sys.exit(0)

ses.pause()
torinfo = handle.get_torrent_info()
print torinfo
