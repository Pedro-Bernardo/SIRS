#!/usr/bin/env python
# -*- coding: utf-8 -*-

from ctf_gameserver.checker import BaseChecker, NOTWORKING, OK, TIMEOUT, NOTFOUND
from .client import Client

from .identitygenerator import get_user_name
import random
import string
import binascii

from git.exc import GitCommandError

class TheTangleChecker(BaseChecker):
    def place_flag(self):
        try:
            with Client(self._ip, 4563, self.logger) as c:
                account = -1
                while account == -1:   # While user already exists
                    username = get_user_name()
                    rng = random.SystemRandom()
                    password = ''.join(rng.choice(string.ascii_letters + string.digits + string.punctuation) for _ in range(50))
                    account = c.register(username, password)
                    if not account:
                        self.logger.error('Failed to register account')
                        return NOTWORKING
                flag = self.get_flag(self._tick)
                flag_ref = c.store(username, flag)
                if flag_ref:
                    self.store_yaml('data-{}'.format(self._tick), {
                        'username': username,
                        'password': password,
                        'account' : account,
                        'flag_ref': flag_ref,
                    })
                    return OK
                else:
                    self.logger.error('Failed to store flag')

        except GitCommandError:
            self.logger.exception("place flag")

        return NOTWORKING

    def check_flag(self, tick):
        data = self.retrieve_yaml('data-{}'.format(tick))
        # TODO
        if data is None or 'account' not in data:
            self.logger.debug("Could not retrieve account information")
            return NOTFOUND

        account = data['account']
        password = data['password']
        flag_ref = data['flag_ref']

        try:
            with Client(self._ip, 4563, self.logger) as c:
                res = c.retrieve(account, password, [flag_ref])
                if res and res == self.get_flag(tick):
                    return OK

                elif not res:
                    self.logger.error('Failed to retrieve data from the service')
                    return NOTFOUND
                else:
                    self.logger.error('Retrieved data is not the stored flag')
                    return NOTFOUND

        except (GitCommandError, binascii.Error):
            self.logger.exception("check flag")

        return NOTWORKING

    def check_service(self):
        try:
            with Client(self._ip, 4563, self.logger) as c:
                return OK

        except GitCommandError:
            self.logger.exception("check service")

        return NOTWORKING
