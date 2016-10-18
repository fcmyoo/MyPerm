import logging
import os
from Crypto.Cipher import AES
import random
import datetime
import hashlib
# import crypt
from MyPerm.cryptforwindows import crypt
from binascii import b2a_hex, a2b_hex
from django.core.paginator import Paginator, EmptyPage, InvalidPage
from django.shortcuts import render_to_response, render
from django.template import RequestContext
from django.core.urlresolvers import reverse
from django.http import HttpResponseRedirect, HttpResponse
from MyPerm.settings import LOG_DIR, LOG_LEVEL
from user.models import *


# 自定义异常类
class ServerError(Exception):
    pass


# 加密类
class PyCrypt(object):
    def __init__(self, key):
        self.key = key
        self.mode = AES.MODE_CBC

    # 随机生成密码
    @staticmethod
    def gen_rand_pass(length=16, especial=False):
        '''
        随机生成密码
        '''
        salt_key = '1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_'
        symbol = '!@$%^&*()_'
        salt_list = []
        if especial:
            for i in range(length - 4):
                salt_list.append(random.choice(salt_key))
            for i in range(4):
                salt_list.append(random.choice(symbol))
        else:
            for i in range(length):
                salt_list.append(random.choice(salt_key))
        salt = ''.join(salt_list)
        return salt

    # md5非对称加密
    @staticmethod
    def md5_crypt(string):
        '''
        md5非对称加密
        :param string:
        :return: 加密后的MD5值
        '''
        return hashlib.new('md5', string).hexdigest()

    # 生成sha512加密密码
    @staticmethod
    def gen_sha512(salt, password):
        '''
        生成sha512加密密码
        :param salt: 加密字符串
        :param password: 密码
        :return: 加密后的密码
        '''
        return crypt(password, '$6$%s$' % salt)

    # 对称加密之加密生成密码
    def encrypt(self, passwd=None, length=32):
        '''
        对称加密之加密生成密码
        :param passwd: 密码
        :param length: 长度32
        :return: 返回加密生成密码
        '''
        if not passwd:
            passwd = self.gen_rand_pass()

        cryptor = AES.new(self.key, self.mode, b'8122ca7d906ad5e1')
        try:
            count = len(passwd)
        except TypeError:
            raise ServerError('Encrypt password error, TYpe error.')

        add = (length - (count % length))
        passwd += ('\0' * add)
        cipher_text = cryptor.encrypt(passwd)
        return b2a_hex(cipher_text)


# 使用改封装函数查询数据库
def get_object(model, **kwargs):
    '''
    使用改封装函数查询数据库
    :param model:实体
    :param kwargs: 参数
    :return: 返回查询的数据
    '''
    for value in list(kwargs.values()):
        if not value:
            return None

    the_object = model.objects.filter(**kwargs)
    if len(the_object) == 1:
        the_object = the_object[0]
    else:
        the_object = None
    return the_object


# 封装加载模板并作为HttpResponse返回
def my_render(template, data, request):
    '''
    封装加载模板并作为HttpResponse返回
    :param template: 加载的模板
    :param data: 传递的数据
    :param request: 传递的请求
    :return:
    '''
    return render(request, template, data)


# 分页公用函数，返回分页的对象元组
def pages(post_objects, request):
    '''
    分页公用函数，返回分页的对象元组
    :param post_objects: 对象
    :param request:
    :return:返回枫叶对象元组
    '''
    paginator = Paginator(post_objects, 20)
    try:
        current_page = int(request.GET.get('page', '1'))
    except ValueError:
        current_page = 1
    page_range = page_list_return(len(paginator.page_range))

    try:
        page_objects = paginator.page(current_page)
    except(EmptyPage, InvalidPage):
        page_objects = paginator.page(paginator.num_pages)
    if current_page >= 5:
        show_first = 1
    else:
        show_first = 0
    if current_page <= (len(paginator.page_range) - 3):
        show_end = 1
    else:
        show_end = 0
    return post_objects, paginator, page_objects, page_range, show_first, show_end


# 分页，返回本次分页的最小页数到最大页数列表
def page_list_return(total, current=1):
    min_page = current - 2 if current - 4 > 0 else 1
    max_page = current + 4 if current + 4 < total else total
    return list(range(min_page, max_page + 1))


# 根据提示设置log打印
def set_log(level, filename='server.log'):
    """
    return a log file object
    根据提示设置log打印
    """
    log_file = os.path.join(LOG_DIR)
    if not os.path.exists(log_file):
        os.mkdir(log_file)
        # os.chmod(log_file, 0o777)
    log_level_total = {'debug': logging.DEBUG, 'info': logging.INFO, 'warning': logging.WARN, 'error': logging.ERROR,
                       'critical': logging.CRITICAL}
    logger_f = logging.getLogger('server')
    logger_f.setLevel(logging.DEBUG)
    fh = logging.FileHandler(os.path.join(os.getcwd(), filename), 'w+')
    fh.setLevel(log_level_total.get(level, logging.DEBUG))
    formatter = logging.Formatter('%(asctime)s - %(filename)s - %(levelname)s - %(message)s')
    fh.setFormatter(formatter)
    logger_f.addHandler(fh)

    return logger_f


# 控制用户角色的装饰器
def require_role(role='user'):
    '''
    要求用户是某种角色 ["super", "admin", "user"]的装饰器
    :param role: ["super", "admin", "user"]
    :return:
    '''

    def _deco(func):
        def __deco(request, *args, **kwargs):
            request.session['pre_url'] = request.path
            if not request.user.is_authenticated():
                return HttpResponseRedirect(reverse('login'))
            if role == 'admin':
                if request.user.role == 'CU':
                    return HttpResponseRedirect(reverse('index'))
            elif role == 'supper':
                if request.user.role in ['CU', 'GA']:
                    return HttpResponseRedirect(reverse('index'))
            return func(request, *args, **kwargs)

        return __deco

    return _deco


# 控制请求
def defend_attack(func):
    def _deco(request, *args, **kwargs):
        if int(request.session.get('visit', 1)) > 10:
            logger.debug('请求次数:{}'.format(request.session.get('visit', 1)))
            return HttpResponse('Forbidden', status=403)
        request.session['visit'] = request.session.get('visit', 1)
        request.session.set_expiry(300)
        return func(request, *args, **kwargs)

    return _deco


logger = set_log(LOG_LEVEL)
