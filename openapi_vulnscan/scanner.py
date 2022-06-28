import argparse
import asyncio
import dataclasses
import sys
import typing
from contextlib import asynccontextmanager
from urllib.parse import quote_plus

import aiohttp
import yarl
from packaging.version import Version
from prance import ResolvingParser

from . import console
from .decorators import async_run

try:
    import ujson as json
except ImportError:
    import json


@dataclasses.dataclass
class OpenApiVulnScanner:
    _: dataclasses.KW_ONLY
    headers: dict[str, str]
    num_workers: int = 10
    timeout: float = 15.0
    user_agent: str = "Mozilla/5.0"

    @classmethod
    def parse_args(
        cls, argv: typing.Sequence | None = None
    ) -> argparse.Namespace:
        parser = argparse.ArgumentParser(
            formatter_class=argparse.ArgumentDefaultsHelpFormatter
        )
        parser.add_argument('url', help='target url')
        parser.add_argument(
            '-H',
            '--header',
            help='additional header',
            default=[],
            nargs='*',
            type=lambda s: s.split(':', 2),
        )
        parser.add_argument(
            '-a',
            '--user-agent',
            help='client user-agent',
            default=cls.user_agent,
        )
        parser.add_argument(
            '-t',
            '--timeout',
            help='client timeout',
            default=cls.timeout,
            type=float,
        )
        parser.add_argument(
            '-w',
            '--num-workers',
            help='number of workers',
            default=cls.num_workers,
            type=int,
        )
        return parser.parse_args(argv)

    @classmethod
    @async_run
    async def run(cls, argv: typing.Sequence | None = None) -> None:
        args = cls.parse_args(argv)
        scanner = cls(
            headers=dict(args.header),
            num_workers=args.num_workers,
            timeout=args.timeout,
            user_agent=args.user_agent,
        )
        try:
            await scanner.scan(args.url)
        except Exception as e:
            console.error(e)
            sys.exit(-1)

    @asynccontextmanager
    async def get_session(self) -> typing.AsyncIterable[aiohttp.ClientSession]:
        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(verify_ssl=False),
            headers=self.headers,
            timeout=aiohttp.ClientTimeout(total=self.timeout),
        ) as session:
            session.headers.setdefault('User-Agent', self.user_agent)
            yield session

    def normalize_url(self, url: str) -> str:
        return url

    async def worker(self, queue: asyncio.Queue) -> None:
        async with self.get_session() as session:
            try:
                pass
            except Exception as e:
                console.error(e)
            finally:
                queue.task_done()

    def filter_parameters(
        self, params: list[dict[str, typing.Any]], location: str
    ) -> list[dict[str, typing.Any]]:
        return list(filter(lambda x: x['in'] == location, params))

    def replace_path(path: str, params: dict[str, str]) -> str:
        return path.format(**{k: quote_plus(v) for k, v in params.items()})

    # https://github.com/tz4678/openapi-vulnerability-scanner/blob/main/openapi_scanner/scanner.py
    async def scan(self, url: str) -> None:
        url = self.normalize_url(url)
        console.info("Start scanning: %s", url)
        parser = ResolvingParser(url)
        spec = parser.specification
        if 'swagger' in spec and Version(spec['swagger']) >= Version('2.0'):
            base_url = yarl.URL(f"{spec['schemes'][0]}://{spec['host']}")
            paths = spec.get('paths', {})
            for path, path_object in paths.items():
                for operation, path_item in path_object.items():
                    if 'produces' in path_item:
                        assert 'application/json' in path_item['produces']
                    params = path_item.get('parameters', [])
                    path_params = self.filter_parameters(params, 'path')
                    query_params = self.filter_parameters(params, 'query')
                    header_params = self.filter_parameters(params, 'header')
                    formdata_params = self.filter_parameters(params, 'formData')
                    body_params = self.filter_parameters(params, 'body')
                    console.log("%s %s", operation, path)
                    # endpoint = base_url.with_path(path)
        else:
            raise ValueError("Invalid specification")
        # queue = asyncio.Queue()
        # workers = [self.worker(queue=queue) for _ in range(self.num_workers)]
