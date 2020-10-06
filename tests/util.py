import os
import json


def get_json_file(path):
    cur = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(cur, 'data', path), encoding='utf8') as f:
        return json.load(f)


def load_json_file(test_name):
    return get_json_file(test_name)


def load_test(test_list, test_name):
    for test_data in test_list:
        if test_data['name'] == test_name:
            return test_data['cases']
    print(test_list)
    raise Exception('test {} unknown.'.format(test_name))


def load_test_list(test_list, test_name):
    try:
        _dict = {}
        for test_data in test_list:
            if test_data['name'].startswith(test_name):
                _dict[test_data['name']] = test_data['cases']
        if len(_dict) > 0:
            return _dict
    except TypeError as err:
        print(err)
        raise err
    print(test_list)
    raise Exception('test {} unknown.'.format(test_name))


def assert_equal(test_obj, test_name, case, expect, value, param_name=''):
    if isinstance(value, bool) or isinstance(value, int):
        _value = value
    else:
        _value = str(value)
    if not param_name:
        test_obj.assertEqual(
            expect['python'], _value,
            'Fail: {}:{}'.format(test_name, case))
    elif param_name in expect:
        test_obj.assertEqual(
            expect[param_name], _value,
            'Fail: {}:{}:{}'.format(test_name, case, param_name))


def assert_match(test_obj, test_name, case, expect, value, param_name):
    test_obj.assertEqual(
        expect, value,
        'Fail: {}:{}:{}'.format(test_name, case, str(param_name)))


def assert_log(test_obj, test_name, case):
    test_obj.assertTrue(False, 'Fail: {}:{}'.format(test_name, case))


def assert_message(test_obj, test_name, case, msg):
    test_obj.assertTrue(False, 'Fail: {}:{} {}'.format(test_name, case, msg))


def assert_error(test_obj, test_name, case, is_error_pattern):
    if is_error_pattern:
        msg = 'Fail: {}:{} not error occurred'.format(test_name, case)
        test_obj.assertTrue(False, msg)
        raise Exception(msg)
