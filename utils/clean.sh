#!/bin/bash
# Copyright (C) 2010-2014 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

# I'm sure this can be done easier, but I'm not very familiar with bash
# scripting.. So, here we go. Also, this only works from "./cuckoo" and
# "./cuckoo/utils" directory, but it's still better than before.
if [[ $PWD/ = */utils/ ]]; then
    export PWD=${PWD:0:${#PWD}-6}
fi

rm -rf $PWD/db/ $PWD/log/ $PWD/storage/
find $PWD/ -name '*.pyc' -exec rm {} \;
#RAHMAN
#clean mysql tables
mysql --user="workbench" --password="k4hvd" --database="cuckoo" -e "DROP TABLE IF EXISTS errors; DROP TABLE IF EXISTS guests; DROP TABLE IF EXISTS machines; DROP TABLE IF EXISTS machines_tags; DROP TABLE IF EXISTS samples; DROP TABLE IF EXISTS tags; DROP TABLE IF EXISTS tasks; DROP TABLE IF EXISTS tasks_tags;"
