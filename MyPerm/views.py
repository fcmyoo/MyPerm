from django.http import HttpResponseRedirect
from django.shortcuts import render_to_response
from django.contrib.auth import authenticate, login, logout
from django.core.urlresolvers import reverse
from MyPerm.api import *


def skin_config(request):
    return render_to_response('skin_config.html')


@defend_attack
def Login(request):
    """登录界面"""
    error = ''
    print('one',request)
    if request.user.is_authenticated():
        return HttpResponseRedirect(reverse('index'))
    if request.method == 'GET':

        return render_to_response('login.html')
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
    return render_to_response('login.html', {'error': error})


@require_role(role='user')
def index_cu(request):
    username = request.user.username
    return HttpResponseRedirect(reverse('user_detail'))


@require_role(role='user')
def index(request):
    return index_cu(request)


@defend_attack
def Logout(request):
    logout(request)
    return HttpResponseRedirect(reverse('index'))
