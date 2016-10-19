import hashlib
import logging
import os
import random
from binascii import b2a_hex

from Crypto.Cipher import AES
from django.core.paginator import Paginator, EmptyPage, InvalidPage
from django.core.urlresolvers import reverse
from django.http import HttpResponseRedirect, HttpResponse
from django.shortcuts import render

from MyPerm.cryptforwindows import crypt
from MyPerm.settings import LOG_DIR, LOG_LEVEL, KEY
from user.models import User


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


# 要求请求角色正确
def is_role_request(request, role='user'):
    """
    require this request of user is right
    要求请求角色正确
    """
    role_all = {'user': 'CU', 'admin': 'GA', 'super': 'SU'}
    if request.user.role == role_all.get(role, 'CU'):
        return True
    else:
        return False


# 获取用户信息
@require_role
def get_session_user_info(request):
    """
    get the user info of the user in session, for example id, username etc.
    获取用户的信息
    """
    # user_id = request.session.get('user_id', 0)
    # user = get_object(User, id=user_id)
    # if user:
    #     return [user.id, user.username, user]
    return [request.user.id, request.user.username, request.user]


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


# 获取session中用户的部门
def get_session_user_dept(request):
    """
    get department of the user in session
    获取session中用户的部门
    """
    # user_id = request.session.get('user_id', 0)
    # print '#' * 20
    # print user_id
    # user = User.objects.filter(id=user_id)
    # if user:
    #     user = user[0]
    #     return user, None
    return request.user, None


# 获取用户的部门id
def get_user_dept(request):
    """
    get the user dept id
    获取用户的部门id
    """
    user_id = request.user.id
    if user_id:
        user_dept = User.objects.get(id=user_id).dept
        return user_dept.id


def validate(request, user_group=None, user=None, asset_group=None, asset=None, edept=None):
    """
    validate the user request
    判定用户请求是否合法
    """
    dept = get_session_user_dept(request)[1]
    if edept:
        if dept.id != int(edept[0]):
            return False

    if user_group:
        dept_user_groups = dept.usergroup_set.all()
        user_group_ids = []
        for group in dept_user_groups:
            user_group_ids.append(str(group.id))

        if not set(user_group).issubset(set(user_group_ids)):
            return False

    if user:
        dept_users = dept.user_set.all()
        user_ids = []
        for dept_user in dept_users:
            user_ids.append(str(dept_user.id))

        if not set(user).issubset(set(user_ids)):
            return False

    if asset_group:
        dept_asset_groups = dept.bisgroup_set.all()
        asset_group_ids = []
        for group in dept_asset_groups:
            asset_group_ids.append(str(group.id))

        if not set(asset_group).issubset(set(asset_group_ids)):
            return False

    if asset:
        dept_assets = dept.asset_set.all()
        asset_ids = []
        for dept_asset in dept_assets:
            asset_ids.append(str(dept_asset.id))

        if not set(asset).issubset(set(asset_ids)):
            return False

    return True


# 请求成功
def http_success(request,msg):
    return render(request,'success.html',locals())


# 请求错误
def http_error(request, msg):
    message = msg
    return render(request, 'error.html', locals())


logger = set_log(LOG_LEVEL)
CRYPTOR = PyCrypt(KEY)
