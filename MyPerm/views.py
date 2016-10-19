from os import mkdir

from django.contrib.auth import authenticate, login, logout
from django.shortcuts import render_to_response

from MyPerm.api import *
from MyPerm.models import Setting
from MyPerm.settings import BASE_DIR
from user.models import User


def skin_config(request):
    return render_to_response('skin_config.html')


@defend_attack
def Login(request):
    """登录界面"""
    error = ''
    if request.user.is_authenticated():
        return HttpResponseRedirect(reverse('index'))
    if request.method == 'GET':
        return render(request, 'login.html')
    else:
        username = request.POST.get('username')
        password = request.POST.get('password')
        if username and password:
            user = authenticate(username=username, password=password)
            if user is not None:
                if user.is_active:
                    login(request, user)
                    # c = {}
                    # c.update(csrf(request))
                    # request.session['csrf_token'] = str(c.get('csrf_token'))
                    # user_filter = User.objects.filter(username=username)
                    # if user_filter:
                    #     user = user_filter[0]
                    #     if PyCrypt.md5_crypt(password) == user.password:
                    #         request.session['user_id'] = user.id
                    #         user_filter.update(last_login=datetime.datetime.now())
                    if user.role == 'SU':
                        request.session['role_id'] = 2
                    elif user.role == 'GA':
                        request.session['role_id'] = 1
                    else:
                        request.session['role_id'] = 0
                    return HttpResponseRedirect(request.session.get('pre_url', '/'))
                # response.set_cookie('username', username, expires=604800)
                # response.set_cookie('seed', PyCrypt.md5_crypt(password), expires=604800)
                # return response
                else:
                    error = '用户未激活'
            else:
                error = '用户名或密码错误'
        else:
            error = '用户名或密码错误'
    return render(request, 'login.html', {'error': error})


@require_role('admin')
def setting(request):
    header_title, path1 = '项目设置', '设置'
    setting_default = get_object(Setting, name='default')

    if request.method == "POST":
        try:
            setting_raw = request.POST.get('setting', '')
            if setting_raw == 'default':
                username = request.POST.get('username', '')
                port = request.POST.get('port', '')
                password = request.POST.get('password', '')
                private_key = request.POST.get('key', '')

                if len(password) > 30:
                    raise ServerError('秘密长度不能超过30位!')

                if '' in [username, port]:
                    return ServerError('所填内容不能为空, 且密码和私钥填一个')
                else:
                    private_key_dir = os.path.join(BASE_DIR, 'keys', 'default')
                    private_key_path = os.path.join(private_key_dir, 'admin_user.pem')
                    mkdir(private_key_dir)

                    if private_key:
                        with open(private_key_path, 'w') as f:
                            f.write(private_key)
                        os.chmod(private_key_path, 0o600)

                    if setting_default:
                        if password:
                            password_encode = CRYPTOR.encrypt(password)
                        else:
                            password_encode = password
                        Setting.objects.filter(name='default').update(field1=username, field2=port,
                                                                      field3=password_encode,
                                                                      field4=private_key_path)

                    else:
                        password_encode = CRYPTOR.encrypt(password)
                        setting_r = Setting(name='default', field1=username, field2=port,
                                            field3=password_encode,
                                            field4=private_key_path).save()
                        msg = "设置成功"
        except ServerError as e:
            error = e.message
    return render(request, 'setting.html', locals())

@require_role(role='user')
def index_cu(request):
    username = request.user.username
    return HttpResponseRedirect(reverse('user_detail'))


@require_role(role='user')
def index(request):
    print(request)
    if not request.user.is_authenticated():
        return HttpResponseRedirect(reverse('login'))
    if is_role_request(request,'user'):
        return index_cu(request)
    elif is_role_request(request,'super'):
        # dashboard 显示汇总
        users = User.objects.all()
        # hosts = Asset.objects.all()
        # online = Log.objects.filter(is_finished=0)
        # online_host = online.values('host').distinct()
        # online_user = online.values('user').distinct()
        active_users = User.objects.filter(is_active=1)
        # active_hosts = Asset.objects.filter(is_active=1)
    return render(request,'index.html',locals())


@defend_attack
def Logout(request):
    logout(request)
    return HttpResponseRedirect(reverse('index'))
