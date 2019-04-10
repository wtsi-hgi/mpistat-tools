#!/usr/bin/env python3.7
"""
mpistat Data Filter
Christopher Harrison <ch12@sanger.ac.uk>
GPLv3, or later
"""

import argparse
import base64
import gzip
import logging
import os.path
import sys
import typing as T
from abc import ABCMeta, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from grp import getgrgid
from pathlib import Path
from pwd import getpwuid


READ_REPORT = 50 * (1024 ** 2)  # 50MiB


@dataclass
class _mpistatRecord:
    _path:str
    size:int
    uid:int
    gid:int
    atime:datetime
    mtime:datetime
    ctime:datetime
    mode:str
    inode_id:int
    hardlinks:int
    dev_id:int

    @property
    def path(self) -> Path:
        """ Decode path, on demand """
        return Path(base64.b64decode(self._path).decode())

    @property
    def user(self) -> str:
        """ Get owner username, on demand """
        return getpwuid(self.uid).pw_name

    @property
    def group(self) -> str:
        """ Get owner group name, on demand """
        return getgrgid(self.uid).gr_name

class mpistatRecord(_mpistatRecord):
    def __init__(self, record:bytes) -> None:
        _to_str = lambda b: b.decode()
        _to_datetime = lambda b: datetime.fromtimestamp(int(b), tz=timezone.utc)
        _to_int = int

        _adaptors = [
            # FIXME Using positional adaptors is a bit opaque
            _to_str,      _to_int,      _to_int,      _to_int,
            _to_datetime, _to_datetime, _to_datetime, _to_str,
            _to_int,      _to_int,      _to_int
        ]

        _fields = record.split(b"\t")
        assert len(_fields) == 11

        super().__init__(*(
            _adapt(_field)
            for _adapt, _field in zip(_adaptors, _fields)
        ))


class AbstractRecordFilter(metaclass=ABCMeta):
    @abstractmethod
    def __call__(self, record:mpistatRecord) -> bool:
        """ Check record passes filter """

class directoryFilter(AbstractRecordFilter):
    directory:Path
    base64_prefix:str

    def __init__(self, directory:str) -> None:
        self.directory = Path(directory)

        _with_trailing = directory if directory.endswith("/")  else f"{directory}/"
        _without = _with_trailing[:-1]

        # Look for the common base64 prefix to avoid having to decode
        # every path in the stat data
        self.base64_prefix = os.path.commonprefix([
            base64.b64encode(_with_trailing.encode()),
            base64.b64encode(_without.encode())
        ]).decode()

    def __call__(self, record:mpistatRecord) -> bool:
        rec_path = record.path

        return record._path.startswith(self.base64_prefix) \
           and self.directory in [rec_path, *rec_path.parents]

_idT = T.Union[int, str, None]

class ownerFilter(AbstractRecordFilter):
    user:_idT
    group:_idT

    def __init__(self, user:_idT, group:_idT) -> None:
        assert user is not None or group is not None
        self.user = user
        self.group = group

    def __call__(self, record:mpistatRecord) -> bool:
        user_match = True
        if self.user is not None:
            user_match = self.user == (
                record.uid if isinstance(self.user, int) else record.user)

        group_match = True
        if self.group is not None:
            group_match = self.group == (
                record.gid if isinstance(self.group, int) else record.user)

        return user_match and group_match

class mpistatFilter(AbstractRecordFilter):
    filters:T.List[AbstractRecordFilter]

    # TODO More filters
    def __init__(self, *, directories:T.Optional[T.List[str]] = None,
                          owners:T.Optional[T.List[T.Tuple[_idT, _idT]]] = None) -> None:
        # Initialise filters
        self.filters = []

        for d in (directories or []):
            self.filters.append(directoryFilter(d))

        for u, g in (owners or []):
            self.filters.append(ownerFilter(u, g))

    def __call__(self, record:mpistatRecord) -> bool:
        return any(f(record) for f in self.filters)


def _parse_owner(owner:str) -> T.Tuple[_idT, _idT]:
    if not ":" in owner:
        owner = f"{owner}:"

    user, group = map(lambda x: int(x) if x.isnumeric() else (x or None),
                      owner.split(":"))

    return user, group

if __name__ == "__main__":
    arg_parser = argparse.ArgumentParser(description="Filter mpistat data")
    arg_parser.add_argument("mpistat", metavar="MPISTAT_DATA",
                            nargs="?", type=str, default=sys.stdin.buffer,
                            help="mpistat data")
    arg_parser.add_argument("--directory", nargs="*", type=str,
                            help="directory filter")
    arg_parser.add_argument("--owner", nargs="*", type=str,
                            help="owner filter")

    args = arg_parser.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s\t%(message)s",
                        datefmt="%Y-%m-%d %H:%M:%S %z")

    if isinstance(args.mpistat, str):
        if not os.path.isfile(args.mpistat):
            raise FileNotFoundError(f"{args.mpistat} is not a file")

        # If our input data is provided, we presume it's gzipped data
        logging.info("Reading data from %s", args.mpistat)
        args.mpistat = gzip.open(args.mpistat)

    else:
        logging.info("Reading data from stdin")

    filtered = mpistatFilter(directories=args.directory,
                             owners=list(map(_parse_owner, args.owner or [])))

    # Stream through data and filter
    read_bytes = read_lines = 0
    for record in args.mpistat:
        read_lines += 1
        read_bytes += len(record)
        if read_bytes > READ_REPORT:
            read_bytes = read_bytes % READ_REPORT
            logging.info("Read %d lines of data", read_lines)

        if filtered(mpistatRecord(record)):
            sys.stdout.buffer.write(record)

    logging.info("Finished; read %d lines of data", read_lines)
