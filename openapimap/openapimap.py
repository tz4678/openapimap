__all__ = ('OpenAPIMap',)

import argparse
import asyncio
import cgi
import dataclasses
import random
import sys
import typing
import uuid
from collections import defaultdict, namedtuple
from concurrent.futures import Executor
from contextlib import asynccontextmanager
from copy import deepcopy

import aiohttp
import yarl
from packaging.version import Version
from prance import ResolvingParser

from .decorators import async_run
from .logger import logger
from .utils import random_datetime, random_email, random_phone_number

try:
    # сишная библиотека, которая работает на порядок быстрее встроенной
    import ujson as json
except ImportError:
    import json


SUPER_PASSWORD = 'T0p$3cR3t'

RequestInfo = namedtuple('RequestInfo', 'method url headers cookies data json')


@dataclasses.dataclass
class OpenAPIMap:
    _: dataclasses.KW_ONLY
    executor: Executor | None = None
    headers: dict[str, str] | None = None
    num_workers: int = 50
    timeout: float = 15.0
    user_agent: str = "Mozilla/5.0 ({pack}; Python/{pyver.major}.{pyver.minor}.{pyver.micro})".format(
        pack=__package__, pyver=sys.version_info
    )

    def __post_init__(self) -> None:
        # Устанавливаем дефолтное значение, если текущее None
        # Loop through the fields
        for field in dataclasses.fields(self):
            # If there is a default and the value of the field is none we can assign a value
            if (
                not isinstance(field.default, dataclasses._MISSING_TYPE)
                and getattr(self, field.name) is None
            ):
                setattr(self, field.name, field.default)

    @classmethod
    def parse_args(
        cls, argv: typing.Sequence | None = None
    ) -> argparse.Namespace:
        parser = argparse.ArgumentParser()
        parser.add_argument('url', help='target url')
        parser.add_argument(
            '-H',
            '--header',
            help="additional header. Example: \"Authorization: Bearer <token>\"",
            nargs='*',
            type=lambda s: s.split(':', 2),
        )
        parser.add_argument(
            '-a',
            '--user-agent',
            help=f"client User-Agent. Default: \"Mozilla/5.0 ({__package__}; Python/x.x.x)\"",
        )
        parser.add_argument(
            '-t',
            '--timeout',
            help=f"client timeout. Default: {OpenAPIMap.timeout} seconds",
            type=float,
        )
        parser.add_argument(
            '-w',
            '--num-workers',
            help=f"number of workers. Default: {OpenAPIMap.num_workers}",
            type=int,
        )
        parser.add_argument(
            '-v',
            '--verbose',
            action='count',
            help="be more verbose (-vv for debug)",
        )
        args = parser.parse_args(argv)
        return args

    @classmethod
    @async_run
    async def run(cls, argv: typing.Sequence | None = None) -> None:
        try:
            args = cls.parse_args(argv)
            levels = ['WARNING', 'INFO', 'DEBUG']
            lvl = levels[min(len(levels) - 1, args.verbose)]
            logger.setLevel(lvl)
            await cls(
                headers=args.header,
                num_workers=args.num_workers,
                timeout=args.timeout,
                user_agent=args.user_agent,
            ).scan(args.url)
        except Exception as ex:
            logger.critical(ex)
            sys.exit(1)

    def normalize_url(self, url: str) -> str:
        return url

    # name нужен для `properties: { name: { ... } }`
    def fuzzing(
        self, item: dict[str, typing.Any], name: str | None = None
    ) -> typing.Any:
        if 'oneOf' in item:
            return random.choice(item['oneOf'])
        # https://spec.openapis.org/oas/v3.1.0#example-object
        if 'examples' in item:
            return random.choice(list(item['examples'].values()))['value']
        # {'name': 'petId', 'in': 'path', 'description': 'ID of pet to update', 'required': True, 'type': 'integer', 'format': 'int64'}
        schema = item.get('schema', item)
        if 'default' in schema:
            return schema['default']
        if 'example' in item:
            return item['example']
        if 'enum' in schema:
            return random.choice(schema['enum'])
        name = name or item.get('name', '')
        lower_name = name.lower()
        match schema.get('type'):
            case 'object':
                return {
                    k: self.fuzzing(v, k)
                    for k, v in schema['properties'].items()
                }
            case 'array':
                return [
                    self.fuzzing(schema['items'])
                    for _ in range(schema.get('minItems', 1))
                ]
            case 'integer' | 'number':
                if 'id' in lower_name:
                    return random.randint(3, 10)
                match schema.get('format'):
                    case 'int32' | 'int64':
                        return random.randint(~(1 << 31) + 1, (1 << 31) - 1)
                    case _:
                        return random.random()
            case 'boolean':
                return bool(random.randbytes(1))
            case 'string':
                match schema.get('format'):
                    case 'date':
                        return str(random_datetime().date())
                    case 'date-time':
                        return str(random_datetime())
                    case 'password':
                        return SUPER_PASSWORD
                    case 'email':
                        return random_email()
                    case 'uuid':
                        return str(uuid.uuid4())
                # raise ValueError('lower ' + lower_name)
                if 'first' in lower_name:
                    return random.choice(['John', 'Joe', 'Jack'])
                if 'last' in lower_name:
                    return random.choice(['Smith', 'Wu', 'Li'])
                if 'pass' in lower_name:
                    return SUPER_PASSWORD
                if 'phone' in lower_name:
                    return random_phone_number()
                if 'email' in lower_name:
                    return random_email()
                minlen = schema.get('minLength', 5)
                maxlen = schema.get('maxLength', 10)
                if maxlen >= len(name) >= minlen:
                    return name
                return 'q' * minlen
        raise ValueError(item)

    def generate_test_requests(
        self,
        server_url: yarl.URL,
        path: str,
        operation: str,
        path_item: dict[str, typing.Any],
    ) -> typing.Iterable[RequestInfo]:
        if 'produces' in path_item:
            assert 'application/json' in path_item['produces']

        params = path_item.get('parameters')

        if not params:
            return

        # Сначала отсортируем параметры и заполним их случайными значениями
        collected = defaultdict(dict)
        for param in params:
            loc = param['in']
            if loc == 'body' or loc == 'requsetBody':
                if loc == 'requestBody':
                    for content_type, item in param['content'].items():
                        # На вход может попасть и такое:
                        #   text/plain; charset=utf-8
                        mime, _ = cgi.parse_header(content_type)
                        match mime:
                            case 'application/json':
                                collected['body'] = self.fuzzing(item)
                                break
                            case 'application/www-form-data':
                                collected['formData'] = self.fuzzing(item)
                                break
                else:
                    collected[loc] = self.fuzzing(param)
            else:
                collected[loc][param['name']] = self.fuzzing(param)

        # Теперь нужно проверить все параметры по очереди
        for loc, payload in collected.items():
            # {'in': 'body', 'name': 'body', 'description': 'List of user object', 'required': True, 'schema': {'type': 'array', 'items': {...}}}
            if type(payload) is not dict:
                logger.warning("skip: %s", payload)
                continue
            for name, value in payload.items():
                if not isinstance(value, (str, int, float, bool)):
                    logger.warning("skip: %s", value)
                    continue
                copy = deepcopy(collected)
                copy[loc][name] = "42'\""
                path_params = copy['path']
                query = copy['query']
                headers = copy['header']
                cookies = copy['cookie']
                data = copy['formData']
                json = copy['body']
                assert not data or not json
                path = path.format(**path_params)
                endpoint = server_url.with_path(path).with_query(query)
                yield RequestInfo(
                    method=operation.upper(),
                    url=str(endpoint),
                    headers=headers,
                    cookies=cookies,
                    data=data,
                    json=json,
                )

    @asynccontextmanager
    async def get_session(self) -> typing.AsyncIterable[aiohttp.ClientSession]:
        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(verify_ssl=False),
            headers=self.headers,
            timeout=aiohttp.ClientTimeout(self.timeout),
        ) as session:
            session.headers.setdefault('User-Agent', self.user_agent)
            yield session

    # Вынести в отдельный класс
    async def worker(self, queue: asyncio.Queue) -> None:
        session: aiohttp.ClientSession
        async with self.get_session() as session:
            while not queue.empty():
                try:
                    req: RequestInfo = await queue.get()
                    logger.debug(req)
                    response = await session.request(
                        req.method,
                        req.url,
                        headers=req.headers,
                        cookies=req.cookies,
                        # data and json parameters can not be used at the same time
                        data=req.data or None,
                        json=req.json or None,
                        allow_redirects=False,
                    )
                    logger.warn('[%d] %s', response.status, response.url)
                    if response.status in [401, 403, 404, 405]:
                        continue
                    # server error
                    has_error = response.status >= 500
                    if not has_error:
                        try:
                            await response.json(loads=json.loads)
                        except (aiohttp.ContentTypeError, json.JSONDecodeError):
                            logger.info("Page contains html output")
                            has_error = True
                    if has_error:
                        print(
                            json.dumps(
                                {
                                    'status': response.status,
                                    'request_info': req._asdict(),
                                }
                            ),
                            flush=True,
                        )
                except Exception as e:
                    logger.error(e)
                finally:
                    queue.task_done()

    # https://github.com/tz4678/openapi-vulnerability-scanner/blob/main/openapi_scanner/scanner.py
    async def scan(self, url: str) -> None:
        url = self.normalize_url(url)
        logger.debug("Start scanning: %s", url)
        # Отправляет запросы через requests
        specification = (
            await asyncio.get_event_loop().run_in_executor(
                self.executor, ResolvingParser, url
            )
        ).specification
        queue = asyncio.Queue()
        server_url = yarl.URL(
            f"{specification['schemes'][0]}://{specification['host']}"
        )
        paths = specification.get('paths', {})
        for path, path_object in paths.items():
            for operation, path_item in path_object.items():
                try:
                    logger.debug(
                        "%s %s - %s",
                        operation.upper(),
                        path,
                        path_item.get('summary', ''),
                    )
                    for req in self.generate_test_requests(
                        server_url, path, operation, path_item
                    ):
                        queue.put_nowait(req)
                except Exception as e:
                    logger.warning(e)
        workers = [
            self.worker(queue=queue)
            for _ in range(min(self.num_workers, queue.qsize()))
        ]
        await asyncio.gather(*workers)
        logger.debug("Finished")
