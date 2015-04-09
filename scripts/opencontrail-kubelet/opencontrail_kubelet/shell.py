#
# Copyright (c) 2015 Juniper Networks, Inc.
#

import subprocess
import logging

class Shell:
    # Run a shell command. Log the command run and its output.
    @staticmethod
    def run(str):
        logging.debug('sh: %s' % str)
        cmd = subprocess.check_output(str, shell=True)
        logging.debug('output: %s' % cmd.rstrip())
        return cmd
