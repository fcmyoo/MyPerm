from django.conf.global_settings import EMAIL_HOST_USER
from django.shortcuts import render
import uuid
from django.db.models import Q

from MyPerm.settings import MAIL_ENABLE
from user.user_api import *

# Create your views here.


MAIL_FROM = EMAIL_HOST_USER


# 添加用户
def user_add(request):
    error = ''
    msg = ''
    header_title, path1, path2 = '添加用户', '用户管理', '添加用户1'
    user_role = {
        'SU': '超级管理员',
        'CU': '普通用户',
    }
    group_all = UserGroup.objects.all()

    if request.method == 'POST':
        username = request.POST.get('username', '')
        password = PyCrypt.gen_rand_pass(16)
        name = request.POST.get('name', '')
        email = request.POST.get('email', '')
        groups = request.POST.getlist('groups', '')
        admin_groups = request.POST.getlist('admin_groups', '')
        role = request.POST.get('role', 'CU')
        uuid_r = uuid.uuid4().get_hex()
        extra = request.POST.getlist('extra', [])
        is_active = False if '0' in extra else True
        send_mail_need = False if '1' in extra else True
        try:
            if '' in [username, password, name, role]:
                error = '带*内容不能为空'
                raise ServerError
        except ServerError:
            pass
        else:
            try:
                user = db_add_user(username=username, name=name, password=password, email=email, role=role, uuid=uuid_r,
                                   groups=groups, admin_groups=admin_groups, is_active=is_active,
                                   date_joined=datetime.datetime.now())
                user = get_object(User, username=username)
                if groups:
                    user_groups = []
                    for user_group_id in groups:
                        user_groups.extend(UserGroup.objects.filter(id=user_group_id))
            except IndexError as e:
                error = '添加用户{}失败{}'.format(username, e)
                try:
                    db_del_user(username)
                except Exception as e:
                    pass
            else:
                if MAIL_ENABLE and send_mail_need:
                    user_add_mail(user, kwargs=locals())
                msg = get_display_msg(user, password=password, send_mail_need=send_mail_need)
    return my_render('user/user_add.html', locals(), request)


# 展示用户列表
def user_list(request):
    user_role = {'SU': '超级管理员', 'GA': '组管理员', 'CU': '普通用户'}
    keyword = request.GET.get('keyword', '')
    gid = request.GET.get('gid', '')
    users_list = User.objects.all().order_by('username')
    if gid:
        user_group = UserGroup.objects.filter(id=gid)
        if user_group:
            user_group = user_group[0]
            users_list = user_group.user_set.all()
        if keyword:
            users_list = users_list.filter(Q(username__icontains=keyword) | Q(name__icontains=keyword)).order_by(
                'username')
        users_list, p, users, page_range, current_page, showfirst, show_end = pages(users_list, request)
    return render(request, 'user/user_list.html', locals())
    # return my_render('/user/user_list.html', locals(), request)


# 用户详情页
def user_detail(request):
    if request.session.get('role_id') == 0:
        user_id = request.user.id
    else:
        user_id = request.GET.get('id', '')
    user = get_object(User, id=user_id)
    if not user:
        return HttpResponseRedirect(reverse('user_list'))
        # 稍后实现权限部分
        # user_perm_info = get_group_user_perm(user)

    return my_render('user/user_detail.html', locals(), request)


# 修改用户
def user_edit(request):
    if request.method == 'GET':
        user_id = request.GET.get('id', '')
        if not user_id:
            return HttpResponseRedirect(reverse('index'))

        user_role = {'SU': '超级管理员', 'CU': '普通用户'}
        user = get_object(User, id=user_id)
        group_all = UserGroup.objects.all()
        if user:
            groups_str = ' '.join([str(group.id) for group in user.group.all()])
            admin_groups_str = ' '.join([str(admin_group.group.id) for admin_group in user.admingroup_set.all()])
    else:
        user_id = request.GET.get('id', '')
        password = request.POST.get('password', '')
        name = request.POST.get('name', '')
        email = request.POST.get('email', '')
        groups = request.POST.getlist('groups', [])
        role_post = request.POST.get('role', 'CU')
        admin_groups = request.POST.getlist('admin_groups', [])
        extra = request.POST.getlist('extra', [])
        is_active = True if '0' in extra else False
        email_need = True if '1' in extra else False
        user_role = {'SU': '超级管理员', 'GA': '部门管理员', 'CU': '普通用户'}

        if user_id:
            user = get_object(User, id=user_id)
        else:
            return HttpResponseRedirect(reverse('user_list'))

        db_update_user(user_id=user_id,
                       password=password,
                       name=name,
                       email=email,
                       groups=groups,
                       admin_groups=admin_groups,
                       role=role_post,
                       is_active=is_active)

        if email_need:
            msg = """
                    Hi %s:
                        您的信息已修改，请登录查看详细信息
                        地址：%s
                        用户名： %s
                        密码：%s (如果密码为None代表密码为原密码)
                        权限：：%s

                    """ % (user.name, URL, user.username, password, user_role.get(role_post, ''))
            send_mail('您的信息已修改', msg, MAIL_FROM, [email], fail_silently=False)

        return HttpResponseRedirect(reverse('user_list'))
    return my_render('user/user_edit.html', locals(), request)


# 删除用户
def user_del(request):
    if request.method == 'GET':
        user_ids = request.GET.get('id', '')
        user_id_list = user_ids.split(',')
    elif request.method == "POST":
        user_ids = request.POST.get('id', '')
        user_id_list = user_ids.split(',')
    else:
        return HttpResponse('请求错误')
    for user_id in user_id_list:
        user = get_object(User, id=user_id)
        if user and user.username != 'admin':
            logger.debug('删除用户{}'.format(user.username))
            user.delete()
    return HttpResponse('删除成功')


# 个人信息页
def profile(request):
    user_id = request.user.id
    if not user_id:
        return HttpResponseRedirect(reverse('index'))
    user = User.objects.get(id=user_id)
    return my_render('user/profile.html', locals(), request)


# 个人信息修改
def change_info(request):
    user_id = request.user.id
    user = User.objects.get(id=user_id)
    error = ''
    if not user:
        return HttpResponseRedirect(reverse('index'))
    if request.method == 'POST':
        name = request.POST.get('name', '')
        password = request.POST.get('password', '')
        email = request.POST.get('email', '')

        if '' in [name, email]:
            error = '不能为空'
        if not error:
            user.name = name
            user.email = email
            user.save()
            if len(password) > 0:
                user.set_password(password)
                user.save()
            msg = '修改成功'
    return my_render('user/change_info.html', locals(), request)
