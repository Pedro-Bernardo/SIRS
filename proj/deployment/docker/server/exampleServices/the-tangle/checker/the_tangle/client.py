#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import tempfile
import shutil

from random import SystemRandom
from hashlib import sha256, sha1
from Crypto.PublicKey import RSA
from Crypto.Cipher.PKCS1_v1_5 import PKCS115_Cipher
from base64 import b64encode, b64decode
import string
from time import time, timezone, altzone, daylight, localtime

from .identitygenerator import get_full_name, get_email_address
from .pow import calc_pow

from git import Repo
from git.exc import GitCommandError
from git.util import Actor
from git.objects.util import altz_to_utctz_str

def git_object_hash(type, data):
    return sha1(type.encode() + b' ' + str(len(data)).encode() + b'\x00' + data)

def max_retries(nretries):
    def deco(func):
        def fun(*args, **kwargs):
            for i in range(nretries):
                res = func(*args, **kwargs)
                if res != None:
                    return res
            return False
        return fun
    return deco

class Client:
    def __init__(self, host, port, logger):
        self.host = host
        self.port = port
        self.logger = logger

    def __enter__(self):
        self.repo_path = tempfile.mkdtemp()
        self.repo = Repo.clone_from('http://' + self.host + ':' + str(self.port) + '/the-tangle/api', self.repo_path)
        pubkey_data = self.repo.git.show(self.repo.commit(self.repo.git.rev_list('HEAD', max_parents=0)).tree / 'key.pub')
        self.pubkey = RSA.importKey(pubkey_data)
        self.cipher = PKCS115_Cipher(self.pubkey)
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        shutil.rmtree(self.repo_path)

    def commit(self):
        # Calc tree hash
        treedata = b''
        for entry in sorted(os.listdir(self.repo_path)):
            if entry == '.git': continue
            with open(os.path.join(self.repo_path, entry)) as f:
                data_hash = git_object_hash('blob', f.read().encode()).digest()
                treedata += b'100644 ' + entry.encode() + b'\x00' + data_hash
        tree_hash = git_object_hash('tree', treedata).hexdigest()
        # Serialize commit
        commit_data  = b'tree ' + tree_hash.encode() + b'\n'
        commit_data += b'parent ' + self.repo.head.commit.hexsha.encode() + b'\n'
        # Random author
        author = Actor(get_full_name(), get_email_address())
        # Calc timestamp
        unix_time = int(time())
        is_dst = daylight and localtime().tm_isdst > 0
        offset = altzone if is_dst else timezone
        datetime = str(unix_time) + ' ' + altz_to_utctz_str(offset)
        commit_data += b'author ' + author.name.encode() + b' <' + author.email.encode() + b'> ' + datetime.encode() + b'\n'
        commit_data += b'committer ' + author.name.encode() + b' <' + author.email.encode() + b'> ' + datetime.encode() + b'\n'
        commit_data += b'\n'
        # Randomize commit message to feature proof-of-work
        msg = calc_pow(commit_data)
        return self.repo.index.commit(msg, author=author, committer=author, author_date=datetime, commit_date=datetime)

    def add_files(self, **kwargs):
        for filename, data in kwargs.items():
            with open(os.path.join(self.repo_path, filename), 'wb') as f:
                f.write(data.encode() if type(data) == str else data)
        self.repo.git.add(*kwargs.keys())

    @max_retries(30)
    def register(self, username, password, reset=True, push=True):
        if reset:
            self.repo.git.fetch()
            self.repo.git.reset('origin/master', hard=True)
        self.add_files(action='register', username=username, password=sha256(password.encode()).hexdigest())
        commit = self.commit()
        if push:
            try:
                self.repo.git.push()
            except GitCommandError as e:
                if "Updates were rejected because the remote contains work that you do" in e.stderr or "cannot lock ref" in e.stderr:
                    return None
                return -1 if 'User already exists' in e.stderr else False
        return commit.hexsha

    @max_retries(30)
    def store(self, username, data, reset=True, push=True):
        if reset:
            self.repo.git.fetch()
            self.repo.git.reset('origin/master', hard=True)
        self.add_files(action='store', username=username, data=b64encode(self.cipher.encrypt(username.encode() + b'\n' + data.encode())))
        commit = self.commit()
        if push:
            try:
                self.repo.git.push()
            except GitCommandError as e:
                if "Updates were rejected because the remote contains work that you do" in e.stderr:
                    return None
                return False
        return commit.hexsha

    @max_retries(30)
    def retrieve(self, account, password, ids, reset=True):
        if reset:
            self.repo.git.fetch()
            self.repo.git.reset('origin/master', hard=True)
        self.add_files(action='retrieve', account=account, password=password, ids='\n'.join(ids))
        self.commit()
        try:
            self.repo.git.push()
        except GitCommandError as e:
            if "Updates were rejected because the remote contains work that you do" in e.stderr:
                return None
            d = dict((pair[0], b64decode(pair[1]).decode()) for pair in filter(lambda x: len(x) == 2, (item.split(':') for item in e.stderr.split('remote: ')[1:-1])))
            if len(ids) == 1 and len(d) == 1:
                return d[ids[0]] if ids[0] in d else False
            for id in ids:
                if id not in d:
                    return False
            return d

if __name__ == "__main__":
    with Client('vulnbox-test.faust.ninja', 4563) as c:
        account = c.register('jojo3', 'p4ssw0rd')
        print(account)
        data_id = c.store('jojo3', 'FLAG{1234}')
        print(data_id)
        print(c.retrieve(account, 'p4ssw0rd', [data_id]))
