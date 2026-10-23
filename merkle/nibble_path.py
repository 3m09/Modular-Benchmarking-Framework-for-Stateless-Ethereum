import math

class NibblePath:
    ODD_FLAG = 0x10
    LEAF_FLAG = 0x20
    _EXTENDED_MARKER = 0xFF  # marker for non-hex prefix encoding

    def __init__(self, data, offset=0, width=16):
        """
        data can be:
          - bytes/bytearray: will be expanded into base-<width> digits
          - list/tuple of ints: treated as digits directly
        """
        if width is None:
            width = 16

        if not isinstance(width, int) or width < 2 or width > 256:
            raise ValueError("width must be an integer between 2 and 256")

        # Require power-of-two width and byte-aligned digit size to avoid key collisions
        if (width & (width - 1)) != 0:
            raise ValueError("width must be a power of two")
        bits_per_digit = int(math.log2(width))
        if 8 % bits_per_digit != 0:
            raise ValueError("width must have digit size dividing 8 bits (e.g., 2, 4, 16, 256)")

        self._width = width
        self._bits_per_digit = bits_per_digit
        self._offset = offset

        if isinstance(data, (bytes, bytearray)):
            self._digits = self._bytes_to_digits(bytes(data))
        elif isinstance(data, (list, tuple)):
            self._digits = list(data)
        else:
            raise TypeError("data must be bytes/bytearray or list/tuple of digits")

        for d in self._digits:
            if not (0 <= d < self._width):
                raise ValueError(f"digit {d} out of range for width={self._width}")

    def __len__(self):
        return len(self._digits) - self._offset

    def __repr__(self):
        return f"<NibblePath: Width: {self._width}, Digits: {self._digits}, Offset: {self._offset}>"

    def __str__(self):
        return f"<Width {self._width} | Digits {self._digits}>"

    def __eq__(self, other):
        if len(self) != len(other):
            return False

        for i in range(len(self)):
            if self.at(i) != other.at(i):
                return False

        return True

    @staticmethod
    def decode_with_type(data):
        """ Decodes NibblePath and its type from raw bytes. """
        if len(data) == 0:
            raise ValueError("Cannot decode empty path")

        # Extended encoding (non-hex widths)
        if data[0] == NibblePath._EXTENDED_MARKER:
            if len(data) < 7:
                raise ValueError("Invalid extended path encoding")

            flags = data[1]
            width = data[2]
            length = int.from_bytes(data[3:7], byteorder="big")

            digits = list(data[7:7 + length])
            if len(digits) != length:
                raise ValueError("Invalid extended path length")

            is_leaf = (flags & 0x01) == 0x01
            return NibblePath(digits, offset=0, width=width), is_leaf

        # Legacy hex-prefix encoding (width=16)
        is_odd_len = data[0] & NibblePath.ODD_FLAG == NibblePath.ODD_FLAG
        is_leaf = data[0] & NibblePath.LEAF_FLAG == NibblePath.LEAF_FLAG

        offset = 1 if is_odd_len else 2
        return NibblePath(data, offset, width=16), is_leaf

    @staticmethod
    def decode(data):
        """ Decodes NibblePath without its type from raw bytes. """
        return NibblePath.decode_with_type(data)[0]

    def starts_with(self, other):
        """ Checks if `other` is prefix of `self`. """
        if len(other) > len(self):
            return False

        for i in range(len(other)):
            if self.at(i) != other.at(i):
                return False

        return True

    def at(self, idx):
        """ Returns digit at the certain position. """
        idx = idx + self._offset
        return self._digits[idx]

    def consume(self, amount):
        """ Cuts off digits at the beginning of the path. """
        self._offset += amount
        return self

    def _create_new(path, length):
        """ Creates a new NibblePath from a given object with a certain length. """
        digits = [path.at(i) for i in range(length)]
        return NibblePath(digits, offset=0, width=path._width)

    def common_prefix(self, other):
        """ Returns common part at the beginning of both paths. """
        least_len = min(len(self), len(other))
        common_len = 0
        for i in range(least_len):
            if self.at(i) != other.at(i):
                break
            common_len += 1

        return NibblePath._create_new(self, common_len)

    def encode(self, is_leaf):
        """
        Encodes NibblePath into bytes.

        - width=16 uses legacy hex-prefix encoding (Ethereum compatible)
        - other widths use extended encoding:
            0xFF | flags | width | length(4 bytes) | digits...
        """
        if self._width == 16:
            # Legacy hex-prefix encoding
            output = []

            nibbles_len = len(self)
            is_odd = nibbles_len % 2 == 1

            prefix = 0x00
            prefix += self.ODD_FLAG + self.at(0) if is_odd else 0x00
            prefix += self.LEAF_FLAG if is_leaf else 0x00

            output.append(prefix)

            pos = nibbles_len % 2

            while pos < nibbles_len:
                byte = self.at(pos) * 16 + self.at(pos + 1)
                output.append(byte)
                pos += 2

            return bytes(output)

        # Extended encoding for non-hex widths
        flags = 0x01 if is_leaf else 0x00
        length = len(self)
        header = bytes([self._EXTENDED_MARKER, flags, self._width]) + length.to_bytes(4, "big")
        body = bytes([self.at(i) for i in range(length)])
        return header + body

    class _Chained:
        """ Class that chains two paths. """

        def __init__(self, first, second):
            self.first = first
            self.second = second

        def __len__(self):
            return len(self.first) + len(self.second)

        def at(self, idx):
            if idx < len(self.first):
                return self.first.at(idx)
            else:
                return self.second.at(idx - len(self.first))

    def combine(self, other):
        """ Merges two paths into one. """
        chained = NibblePath._Chained(self, other)
        return NibblePath._create_new(chained, len(chained))

    def _bytes_to_digits(self, data_bytes: bytes):
        """
        Convert raw bytes into base-<width> digits.
        width must have digit-size dividing 8 bits.
        """
        digits = []
        mask = (1 << self._bits_per_digit) - 1
        step = self._bits_per_digit

        for b in data_bytes:
            # Extract digits from most-significant to least-significant bits
            for shift in range(8 - step, -1, -step):
                digits.append((b >> shift) & mask)

        return digits
