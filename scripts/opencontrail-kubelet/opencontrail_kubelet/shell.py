#
# Copyright (c) 2015 Juniper Networks, Inc.
#

import subprocess
import logging


class Shell:
    # Run a shell command. Log the command run and its output.
    @staticmethod
    def run(cmd, ignore=False):
        logging.debug('sh: %s' % cmd)
        try:
            cmd = subprocess.check_output(cmd, shell=True)
        except:
            if not ignore:
                logging.error('command failed: %s' % cmd.rstrip())
                raise
        logging.debug('output: %s' % cmd.rstrip())
        return cmd
