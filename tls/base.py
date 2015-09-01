import io

class Decode:
    """
    Decode primitive values from bytes.
    """
    @staticmethod
    def u8(b):
        assert len(b) == 1
        return b[0]
    
    @staticmethod
    def u16(b):
        assert len(b) == 2
        return b[0] << 8 | b[1]

    @staticmethod
    def u24(b):
        assert len(b) == 3
        return b[0] << 16 | b[1] << 8 | b[2]

    @staticmethod
    def u32(b):
        assert len(b) == 4
        return b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3]

class Read:
    @staticmethod
    def must(f, n):
        """
        Read exactly n bytes from file-like object f.  Raises
        IOError if n bytes not available.
        """
        x = f.read(n)
        if x is None:
            raise IOError('{0} bytes not available from file {1}'.format(n, f))
        if len(x) != n:
            raise IOError('short read from {0}: wanted {1} bytes, got {2}'.format(f, n, len(x)))
        return x

    @staticmethod
    def partial(f, n):
        """
        Read up to n bytes from file-like object f.
        Returns the bytes, remain tuple (bytes is a bytes object,
        remain is an integer).  remain = n - len(bytes)
        """
        x = f.read(n)
        if x is None:
            raise IOError('{0} bytes not available from file {1}'.format(n, f))

        # return value-bytes, remain-int
        return x, n - len(x)
    
    u8 = lambda f: Decode.u8(Read.must(f, 1))
    u16 = lambda f: Decode.u16(Read.must(f, 2))
    u24 = lambda f: Decode.u24(Read.must(f, 3))
    u32 = lambda f: Decode.u32(Read.must(f, 4))

    @staticmethod
    def maybe(child):
        """
        Returns a file reading function, which fails softly
        with a None rather than an exception.
        """
        def reader(f):
            try:
                return child(f)
            except:
                return None
        return reader

    @staticmethod
    def vec(f, lenf, itemf):
        """
        Reads a vector of things from f, returning them as a list.

        lenf is a function which reads a length from a file-like object.

        itemf is a function which reads an arbitrary object from
        a file-like object.

        eg, to read a vector of shorts whose length is encoded with an octet:

        Read.vec(f, Read.u8, Read.u16)
        """

        o = []

        # take length and read in whole body
        ll = lenf(f)
        body_bytes = Read.must(f, ll)

        bodyf = io.BytesIO(body_bytes)
        while bodyf.tell() != ll:
            item = itemf(bodyf)
            if item is not None:
                o.append(item)
        
        return o

class Encode:
    """
    Encode assorted types to bytes/lists of bytes.
    """

    @staticmethod
    def u8(v):
        assert v >= 0 and v <= 0xff
        return [ v ]
    
    @staticmethod
    def u16(v):
        assert v >= 0 and v <= 0xffff
        return [ v >> 8 & 0xff, v & 0xff ]

    @staticmethod
    def u24(v):
        assert v >= 0 and v <= 0xffffff
        return [ v >> 16 & 0xff, v >> 8 & 0xff, v & 0xff ]

    @staticmethod
    def u32(v):
        assert v >= 0 and v <= 0xffffffff
        return [ v >> 24 & 0xff, v >> 16 & 0xff, v >> 8 & 0xff, v & 0xff ]

    @staticmethod
    def u64(v):
        assert v >= 0 and v <= 0xffffffffffffffff
        return Encode.u32(v >> 32) + Encode.u32(v & 0xffffffff)

    @staticmethod
    def item_vec(lenf, itemf, items):
        """
        Encode the vector of items.  Each item is encoded with itemf,
        the length of the vector (in bytes, not items) is encoded with
        lenf.
        """
        body = []
        for x in items:
            body.extend(itemf(x))
        return lenf(len(body)) + body

    @staticmethod
    def vec(lenf, items):
        """
        Encode the vector of items.  Each item is encoded with item.encode(),
        the length of the vector (in bytes, not items) is encoded with
        lenf.
        """
        body = []
        for x in items:
            body.extend(x.encode())
        return lenf(len(body)) + body

class Struct:
    """
    Base class for all structures in TLS.

    This knows how to encode itself into bytes, decode from bytes,
    make nice stringified versions of itself, etc.
    """
    def __bytes__(self):
        return bytes(self.encode())

    @classmethod
    def decode(cls, b, *args, **kwargs):
        f = io.BytesIO(b)
        r = cls.read(f, *args, **kwargs)
        return r

    def __repr__(self):
        return str(self)

    def __str__(self):
        o = []
        for k in sorted(self.__dict__.keys()):
            if k[0] == '_':
                continue
            o.append('{0} = {1}'.format(k, self.__dict__[k]))
        return '<{0} {1}>'.format(self.__class__.__name__, ', '.join(o))

class Enum:
    """
    Base class for all enumerations in TLS.

    You need to set _Decode, _Encode and _ByteSize.

    You also need to set class-level values for each value in
    the enumeration, plus one named MAX which should be the maximum
    allowed enumeration.

    This knows how to read from a file
    """
    @classmethod
    def read(cls, f, lax_enum = False):
        """
        Read a value from the file-like f.

        If lax_enum is True, then this function does
        not raise if the read value is unknown.

        Otherwise, this function raises if the value read
        is unknown.
        """
        v = Read.must(f, cls._ByteSize)
        v = cls._Decode(v)

        if lax_enum is False:
            cls.lookup(v)
        return v

    @classmethod
    def table(cls):
        """
        Returns a dict of values to names.
        """
        d = {}
        for k, v in cls.__dict__.items():
            if not k.isidentifier() or k[0] == '_' or k == 'MAX':
                continue
            if v in d:
                raise ValueError('{0} has more than one mapping for value {1:x} (at least {2!r} and {3!r})'.format(cls.__name__, v, d[v], k))
            d[v] = k
        return d
    
    @classmethod
    def lookup(cls, value):
        """
        Ensures the given value is valid for this enum.
        Raises if not.
        """
        if value > cls.MAX:
            raise ValueError('{0:x} cannot be decoded as a {1}: too large'.format(value, cls.__name__))

        d = cls.table()
        if value in d:
            return d[value]

        raise ValueError('{0:x} cannot be decoded as a {1}: unknown value'.format(value, cls.__name__))

    @classmethod
    def tostring(cls, value):
        name = cls.lookup(value)
        return '<{0} {1} ({2:x})>'.format(cls.__name__, name, value)

    @classmethod
    def to_json(cls, value):
        try:
            return [value, cls.__name__, cls.lookup(value)]
        except ValueError:
            return value

    @classmethod
    def encode(cls, value):
        return cls._Encode(value)

    @classmethod
    def all(cls):
        return [value for value, name in cls.table().items()]

class Enum8(Enum):
    """
    An enum encoded in a single octet.
    """
    _ByteSize = 1
    _Encode = Encode.u8
    _Decode = Decode.u8
    MAX = 0xff

class Enum16(Enum):
    """
    An enum encoded in a short.
    """
    _ByteSize = 2
    _Encode = Encode.u16
    _Decode = Decode.u16
    MAX = 0xffff

if __name__ == '__main__':
    class DemoEnum(Enum8):
        Pony = 1
        Breakfast = 2
        Jubilee = 3
        Combine = 5

    print(DemoEnum.tostring(DemoEnum.read(io.BytesIO(b'\x02'))))
    print(DemoEnum.table())
    print(Encode.item_vec(Encode.u16, DemoEnum.encode, [1, 2, 3, 5]))
