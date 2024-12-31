import zlib
import pathlib
import os

def _compress_with_gzip(data, level=9):
    import zlib
    if   level < 0: level = 0
    elif level > 9: level = 9
    # gzip header without timestamp
    zobj = zlib.compressobj(level=level, wbits=16 + zlib.MAX_WBITS)
    return zobj.compress(data) + zobj.flush()

try:
    import zopfli
    # workaround for issues with conflicting zopfli packages
    if not hasattr(zopfli, '__COMPRESSOR_DOCSTRING__'):
        setattr(zopfli, '__COMPRESSOR_DOCSTRING__', '')

    # two python modules call themselves `zopfli`, which one is this?
    if hasattr(zopfli, 'ZopfliCompressor'):
        # we seem to have zopflipy
        from zopfli import ZopfliCompressor, ZOPFLI_FORMAT_GZIP
        def _compress_with_zopfli(data, iterations=15, maxsplit=15, **kw):
            zobj = ZopfliCompressor(
                ZOPFLI_FORMAT_GZIP,
                iterations=iterations,
                block_splitting_max=maxsplit,
                **kw,
            )
            return zobj.compress(data) + zobj.flush()

    else:
        # we seem to have pyzopfli
        import zopfli.gzip
        def _compress_with_zopfli(data, iterations=15, maxsplit=15, **kw):
            return zopfli.gzip.compress(
                data,
                numiterations=iterations,
                blocksplittingmax=maxsplit,
                **kw,
            )

    # values based on limited manual testing
    def _level_to_params(level):
        if   level == 10: return (15, 15)
        elif level == 11: return (15, 20)
        elif level == 12: return (15, 25)
        elif level == 13: return (15, 30)
        elif level == 14: return (15, 35)
        elif level == 15: return (33, 40)
        elif level == 16: return (67, 45)
        elif level == 17: return (100, 50)
        elif level == 18: return (500, 100)
        elif level >= 19: return (2500, 250)
        else:
            raise ValueError(f'Invalid level: {repr(level)}')

    def compress(data, level=None, *, iterations=None, maxsplit=None, **kw):
        if level is not None and (iterations is not None or maxsplit is not None):
            raise ValueError("The `level` argument can't be used with `iterations` and/or `maxsplit`!")

        # set parameters based on level or to defaults
        if iterations is None and maxsplit is None:
            if level is None: level = 10
            elif level < 10: return _compress_with_gzip(data, level)
            iterations, maxsplit = _level_to_params(level)

        if maxsplit is not None:
            kw['maxsplit'] = maxsplit

        if iterations is not None:
            kw['iterations'] = iterations

        return _compress_with_zopfli(data, **kw)

except ModuleNotFoundError:
    def compress(data, level=9, **kw):
        return _compress_with_gzip(data, level)
