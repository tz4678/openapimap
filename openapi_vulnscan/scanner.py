import argparse
import asyncio
import dataclasses
import sys
import typing

# from concurrent.futures import Executor, ProcessPoolExecutor
from collections import defaultdict, namedtuple
from contextlib import asynccontextmanager
from copy import deepcopy
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


RequestData = namedtuple(
    'RequestData', 'method url query headers cookies data json'
)


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
        try:
            args = cls.parse_args(argv)
            instance = cls(
                headers=dict(args.header),
                num_workers=args.num_workers,
                timeout=args.timeout,
                user_agent=args.user_agent,
            )
            await instance.scan(args.url)
        except Exception as ex:
            console.error("Critical: %s", ex)
            sys.exit(1)

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

    def replace_path(path: str, params: dict[str, str]) -> str:
        return path.format(**{k: quote_plus(v) for k, v in params.items()})

    def fuzzing(
        self, params: list[dict[str, typing.Any]]
    ) -> list[dict[str, typing.Any]]:
        """Подставляет случайные параметры"""
        params = deepcopy(params)
        # __value
        return params

    def inject(self, value: typing.Any) -> typing.Any:
        return value

    def get_request_data(
        self,
        api_url: yarl.URL,
        operation: str,
        path: str,
        params: list[dict[str, typing.Any]],
    ) -> RequestData:
        collected = defaultdict(dict)
        for x in params:
            loc = x['in']
            if loc == 'body':
                assert 'name' not in x
                collected[loc] = x['__value']
            else:
                collected[loc][x['name']] = x['__value']
        path_params = collected['path']
        query = collected['query']
        headers = collected['header']
        cookies = collected['cookie']
        data = collected['formData']
        json = collected['body']
        assert not data or not body
        path = self.replace_path(path, path_params)
        endpoint = api_url.with_path(path)
        return RequestData(
            operation.upper(), endpoint, query, headers, cookies, data, json
        )

    def generate_tests(
        self,
        api_url: yarl.URL,
        path: str,
        operation: str,
        path_item: dict[str, typing.Any],
    ) -> typing.Iterable[RequestData]:
        if 'produces' in path_item:
            assert 'application/json' in path_item['produces']
        params = path_item.get('parameters', [])
        # Тестируем каждый параметр по очереди
        for i in range(len(params)):
            test_params = self.fuzzing(params)
            # Тут еще body нужно обработать
            test_params[i] = self.inject(test_params[i])
            yield self.get_request_data(api_url, operation, path, test_params)

    # https://github.com/tz4678/openapi-vulnerability-scanner/blob/main/openapi_scanner/scanner.py
    async def scan(self, url: str) -> None:
        url = self.normalize_url(url)
        console.info("Start scanning: %s", url)
        parser = ResolvingParser(url)
        spec = parser.specification
        if 'swagger' in spec:
            assert Version('3.0') > Version(spec['swagger']) >= Version('2.0')
            api_url = yarl.URL(f"{spec['schemes'][0]}://{spec['host']}")
            paths = spec.get('paths', {})
            for path, path_object in paths.items():
                for operation, path_item in path_object.items():
                    for req_data in self.generate_tests(
                        api_url, path, operation, path_item
                    ):
                        queue.put_nowait(req_data)
        else:
            raise ValueError("Invalid specification")
        # queue = asyncio.Queue()
        # workers = [self.worker(queue=queue) for _ in range(self.num_workers)]
