# (C) Datadog, Inc. 2018
# All rights reserved
# Licensed under a 3-clause BSD style license (see LICENSE)
import os
from os import path


HERE = path.dirname(path.abspath(__file__))
FIXTURE_DIR = os.path.join(HERE, "fixtures/")

INSTANCE = {
    'servlet_url': 'http://hostname/wasPerfTool/servlet/perfservlet'
}