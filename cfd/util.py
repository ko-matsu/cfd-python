from ctypes import c_int, c_void_p, c_char_p, c_int32, c_int64,\
    c_uint32, c_uint64, c_bool, CDLL, byref, POINTER
from os.path import isfile, abspath
import platform
import os


class CVoidPP(object):
    pass


class CCharPP(object):
    pass


class CBoolP(object):
    pass


class CUint32P(object):
    pass


class CIntP(object):
    pass


class CInt32P(object):
    pass


class CUint64P(object):
    pass


class CInt64P(object):
    pass


c_void_p_p = CVoidPP()
c_char_p_p = CCharPP()
c_bool_p = CBoolP()
c_int_p = CIntP()
c_uint32_p = CUint32P()
c_int32_p = CInt32P()
c_uint64_p = CUint64P()
c_int64_p = CInt64P()


class CfdError(Exception):
    def __init__(self, error_code=-1, message=''):
        self.error_code = error_code
        self.message = message

    def __str__(self):
        return 'code={}, msg={}'.format(self.error_code, self.message)


class CfdHandle:
    def __init__(self, handle):
        self._handle = handle

    def get_handle(self):
        return self._handle

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        get_util().free_handle(self._handle)


class JobHandle:
    def __init__(self, handle, job_handle, close_function_name):
        self._handle = handle
        self._job_handle = job_handle
        self._close_func = close_function_name

    def get_handle(self):
        return self._job_handle

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        get_util().call_func(
            self._close_func,
            self._handle.get_handle(),
            self._job_handle)


class CfdUtil:
    FUNC_LIST = [
        ('CfdCreateSimpleHandle', c_int, [c_void_p_p]),
        ('CfdFreeHandle', c_int, [c_void_p]),
        ('CfdFreeBuffer', c_int, [c_void_p]),
        ('CfdGetLastErrorCode', c_int, [c_void_p]),
        ('CfdGetLastErrorMessage', c_int, [c_void_p, c_char_p_p]),
        ('CfdRequestExecuteJson', c_int,
            [c_void_p, c_char_p, c_char_p, c_char_p_p]),
        ('CfdSerializeByteData', c_int, [c_void_p, c_char_p, c_char_p_p]),
        ('CfdCreateAddress', c_int, [
            c_void_p, c_int, c_char_p, c_char_p,
            c_int, c_char_p_p, c_char_p_p, c_char_p_p]),
        ('CfdInitializeMnemonicWordList', c_int,
            [c_void_p, c_char_p, c_void_p_p, c_uint32_p]),
        ('CfdGetMnemonicWord', c_int,
            [c_void_p, c_void_p, c_uint32, c_char_p_p]),
        ('CfdFreeMnemonicWordList', c_int, [c_void_p, c_void_p]),
    ]

    @classmethod
    def get_instance(cls):
        if not hasattr(cls, "_instance"):
            cls._instance = cls()
        return cls._instance

    def __init__(self):
        self._func_map = {}

        root_dir, lib_path = self._collect_lib_path()
        self._cfd = CDLL(root_dir + lib_path)

        free_func = self._cfd.CfdFreeStringBuffer
        free_func.restype, free_func.argtypes = c_int, [c_char_p]
        self.free_str_func = free_func
        self._load_functions()

    def _collect_lib_path(self):
        has_win = platform.system() == 'Windows'
        has_mac = platform.system() == 'Darwin'
        abs_path = os.path.dirname(os.path.abspath(__file__)) + '/'

        so_ext = 'dylib' if has_mac else 'dll' if has_win else 'so'
        so_prefix = '' if has_win else 'lib'
        lib_name = '{}cfd.{}'.format(so_prefix, so_ext)
        lib_path = lib_name
        root_dir = './'
        is_find = isfile(root_dir + lib_path)

        if not is_find:
            for depth in [0, 1, 2]:
                root_dir = abs_path + '../' * depth
                if isfile(root_dir + lib_path):
                    is_find = True
                    break

        if not is_find:
            lib_path = 'cmake_build/Release/' + lib_path
            for depth in [0, 1, 2]:
                root_dir = abs_path + '../' * depth
                if isfile(root_dir + lib_path):
                    is_find = True
                    break

        if not is_find:
            lib_path = lib_name
            if has_win:
                paths = os.getenv('PATH').split(';')
                for path in paths:
                    try:
                        fs = os.listdir(path)
                        for f in fs:
                            if f == 'lib' and isfile(
                                    path + '\\lib\\' + lib_name):
                                root_dir = path + '\\lib\\'
                    except WindowsError:
                        pass
            else:
                paths = ['/usr/local/lib/', '/usr/local/lib64/']
                for path in paths:
                    if isfile(path + lib_name):
                        root_dir = path

        if has_mac:
            root_dir = abspath(root_dir) + '/'
        return root_dir, lib_path

    def _load_functions(self):
        def bind_fn(name, res, args):
            fn = getattr(self._cfd, name)
            fn.restype, fn.argtypes = res, args
            # print('bind: {}, {}, {}'.format(name, res, args))
            return fn

        def in_string_fn_wrapper(fn, pos, *args):
            if isinstance(args[pos], str):
                new_args = [a for a in args]
                new_args[pos] = new_args[pos].encode('utf-8')
                return fn(*new_args)
            return fn(*args)

        def string_fn_wrapper(fn, *args):
            # Return output string parameters directly without leaking
            p = c_char_p()
            new_args = [a for a in args] + [byref(p)]
            ret = fn(*new_args)
            ret_str = None if p.value is None else p.value.decode('utf-8')
            self.free_str_func(p)
            if isinstance(ret, tuple):
                return [ret_str, ((ret[0],) + (ret_str,) + ret[1:])][True]
            else:
                return [ret_str, (ret, ret_str)][True]

        def value_fn_wrapper(p, fn, *args):
            new_args = [a for a in args] + [byref(p)]
            ret = fn(*new_args)
            if isinstance(ret, tuple):
                return [p.value, ((ret[0],) + (p.value,) + ret[1:])][True]
            else:
                return [p.value, (ret, p.value)][True]

        def make_str_fn(f):
            return lambda *args: string_fn_wrapper(f, *args)

        def make_void_fn(fn):
            return lambda *args: value_fn_wrapper(c_void_p(), fn, *args)

        def make_bool_fn(fn):
            return lambda *args: value_fn_wrapper(c_bool(), fn, *args)

        def make_int_fn(fn):
            return lambda *args: value_fn_wrapper(c_int(), fn, *args)

        def make_uint32_fn(fn):
            return lambda *args: value_fn_wrapper(c_uint32(), fn, *args)

        def make_int32_fn(fn):
            return lambda *args: value_fn_wrapper(c_int32(), fn, *args)

        def make_uint64_fn(fn):
            return lambda *args: value_fn_wrapper(c_uint64(), fn, *args)

        def make_int64_fn(fn):
            return lambda *args: value_fn_wrapper(c_int64(), fn, *args)

        def make_input_str_fn(fn, pos):
            return lambda *args: in_string_fn_wrapper(fn, pos, *args)

        for func_info in CfdUtil.FUNC_LIST:
            name, restype, argtypes = func_info

            in_str_pos = [i for (i, t) in enumerate(argtypes) if t == c_char_p]
            str_pos = [i for (i, t) in enumerate(argtypes) if t == c_char_p_p]
            void_pos = [i for (i, t) in enumerate(argtypes) if t == c_void_p_p]
            bool_pos = [i for (i, t) in enumerate(argtypes) if t == c_bool_p]
            int_pos = [i for (i, t) in enumerate(argtypes) if t == c_int_p]
            int32_pos = [i for (i, t) in enumerate(argtypes) if t == c_int32_p]
            uint32_pos = [i for (i, t) in enumerate(
                argtypes) if t == c_uint32_p]
            int64_pos = [i for (i, t) in enumerate(argtypes) if t == c_int64_p]
            uint64_pos = [i for (i, t) in enumerate(
                argtypes) if t == c_uint64_p]
            for i in range(len(argtypes)):
                if isinstance(argtypes[i], CCharPP):
                    argtypes[i] = POINTER(c_char_p)
                elif isinstance(argtypes[i], CVoidPP):
                    argtypes[i] = POINTER(c_void_p)
                elif isinstance(argtypes[i], CBoolP):
                    argtypes[i] = POINTER(c_bool)
                elif isinstance(argtypes[i], CIntP):
                    argtypes[i] = POINTER(c_int)
                elif isinstance(argtypes[i], CInt32P):
                    argtypes[i] = POINTER(c_int32)
                elif isinstance(argtypes[i], CUint32P):
                    argtypes[i] = POINTER(c_uint32)
                elif isinstance(argtypes[i], CInt64P):
                    argtypes[i] = POINTER(c_int64)
                elif isinstance(argtypes[i], CUint64P):
                    argtypes[i] = POINTER(c_uint64)

            fn = bind_fn(name, restype, argtypes)

            i = len(argtypes) - 1
            while i >= 0:
                if len(str_pos) > 0 and i in str_pos:
                    fn = make_str_fn(fn)
                elif len(void_pos) > 0 and i in void_pos:
                    fn = make_void_fn(fn)
                elif len(bool_pos) > 0 and i in bool_pos:
                    fn = make_bool_fn(fn)
                elif len(int_pos) > 0 and i in int_pos:
                    fn = make_int_fn(fn)
                elif len(int32_pos) > 0 and i in int32_pos:
                    fn = make_int32_fn(fn)
                elif len(uint32_pos) > 0 and i in uint32_pos:
                    fn = make_uint32_fn(fn)
                elif len(int64_pos) > 0 and i in int64_pos:
                    fn = make_int64_fn(fn)
                elif len(uint64_pos) > 0 and i in uint64_pos:
                    fn = make_uint64_fn(fn)
                i -= 1

            if len(in_str_pos) > 0 and fn:
                for pos in in_str_pos:
                    fn = make_input_str_fn(fn, pos)
            self._func_map[name] = fn

    def call_func(self, name, *args):
        # print('call: {}{}'.format(name, args))
        ret = self._func_map[name](*args)
        err_code = ret
        if isinstance(ret, tuple):
            err_code = ret[0]
        if err_code != 0:
            message = 'Error: ' + name
            if len(args) > 0 and \
                    args[0] != 'CfdCreateSimpleHandle' and \
                    args[0] != 'CfdFreeHandle' and \
                    args[0] != 'CfdFreeBuffer':
                temp_ret, err_msg = self._func_map['CfdGetLastErrorMessage'](
                    args[0])
                if temp_ret == 0:
                    message = err_msg
            raise CfdError(error_code=ret, message=message)
        if isinstance(ret, tuple) is False:
            return
        elif len(ret) == 1:
            return ret[0]
        elif len(ret) == 2:
            return ret[1]
        else:
            return ret[1:]

    def create_handle(self):
        ret, handle = self._func_map['CfdCreateSimpleHandle']()
        if ret != 0:
            raise CfdError(
                error_code=ret,
                message='Error: CfdCreateSimpleHandle')
        return CfdHandle(handle)

    def free_handle(self, handle):
        return self._func_map['CfdFreeHandle'](handle)


def get_util():
    return CfdUtil.get_instance()
