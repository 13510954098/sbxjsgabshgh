#!/usr/bin/env python3
"""Bounded subprocess bridge to extracted, pinned Animeko Kotlin parsers.
No network is performed by the JVM. HTTP remains in SafeFetcher.
"""
import json
import os
from pathlib import Path
import subprocess

UPSTREAM = 'cd0ad5ca8dc501fb06426d83870f49e7e3b0adef'
class EngineError(ValueError):
    pass

class Engine:
    def __init__(self, jar, java=None, timeout=12):
        self.jar = Path(jar).resolve(strict=True)
        self.java = java or (str(Path(os.environ['JAVA_HOME'])/'bin/java') if os.environ.get('JAVA_HOME') else 'java')
        self.timeout = timeout
        self.headers = {}
        self.calls = 0
        if self.call('health').get('upstream') != UPSTREAM:
            raise EngineError('engine version mismatch')

    def call(self, op, **kwargs):
        data = json.dumps({'op': op, **kwargs}, ensure_ascii=False).encode()
        if len(data) > 2 * 1024 * 1024:
            raise EngineError('engine input exceeds limit')
        # Do not inherit CI tokens, Java agents, or JAVA_TOOL_OPTIONS.
        env = {k: v for k, v in os.environ.items() if k in {'PATH','JAVA_HOME','LANG','LC_ALL','SYSTEMROOT'}}
        try:
            proc = subprocess.run([self.java, '-Dfile.encoding=UTF-8', '-Dstdout.encoding=UTF-8', '-Dstderr.encoding=UTF-8', '-Xmx192m', '-XX:MaxMetaspaceSize=128m',
                                   '-XX:ActiveProcessorCount=2', '-jar', str(self.jar)],
                                  input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  timeout=self.timeout, env=env, check=False)
        except (subprocess.TimeoutExpired, OSError) as exc:
            raise EngineError('engine timeout or unavailable') from exc
        self.calls += 1
        if proc.returncode or len(proc.stdout) > 2 * 1024 * 1024:
            raise EngineError('engine process failed')
        try:
            result = json.loads(proc.stdout)
        except (ValueError, TypeError) as exc:
            raise EngineError('invalid engine response') from exc
        if not isinstance(result, dict) or result.get('ok') is not True:
            raise EngineError('engine rejected config or input')
        return result['result']

    def subjects(self, data, config, base):
        return self.call('subjects', config=config, body=data.decode('utf-8-sig', errors='replace'), baseUrl=base)

    def episodes(self, data, config, base):
        return self.call('episodes', config=config, body=data.decode('utf-8-sig', errors='replace'), baseUrl=base)

    def match(self, urls, config):
        rows = self.call('match', config=config, urls=list(dict.fromkeys(urls))[:100])
        for row in rows:
            if row.get('kind') == 'video':
                self.headers[row['url']] = row.get('headers', {})
        return rows
