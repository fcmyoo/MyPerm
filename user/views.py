import uuid

from django.conf.global_settings import EMAIL_HOST_USER
from django.db.models import Q
import datetime
from django.http import Http404
from MyPerm.settings import MAIL_ENABLE, KEY
from user.user_api import *

MAIL_FROM = EMAIL_HOST_USER


# 添加用户
@require_role(role='super')
def user_add(request):
    error = ''
    msg = ''
    header_title, path1, path2 = '添加用户', '用户管理', '添加用户'
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
        uuid_r = uuid_r = uuid.uuid4().hex
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
@require_role(role='super')
def user_list(request):
    header_title, path1, path2 = '查看用户', '用户管理', '用户列表'
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
@require_role(role='super')
def user_detail(request):
    header_title, path1, path2 = '用户详情', '用户管理', '用户详情'
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
@require_role(role='super')
def user_edit(request):
    header_title, path1, path2 = '编辑用户', '用户管理', '编辑用户'
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
@require_role(role='admin')
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
@require_role(role='user')
def profile(request):
    user_id = request.user.id
    if not user_id:
        return HttpResponseRedirect(reverse('index'))
    user = User.objects.get(id=user_id)
    return my_render('user/profile.html', locals(), request)


# 个人信息修改
def change_info(request):
    header_title, path1, path2 = '修改信息', '用户管理', '修改个人信息'
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
    return render(request,'user/change_info.html', locals() )


# 忘记密码
@defend_attack
def forget_password(request):
    if request.method == 'POST':
        defend_attack(request)
        email = request.POST.get('email', '')
        username = request.POST.get('username', '')
        name = request.POST.get('name', '')
        user = get_object(User, username=username, email=email, name=name)
        if user:
            timestamp = int(time.time())
            hash_encode = PyCrypt.md5_crypt(str(user.uuid) + str(timestamp) + KEY)
            msg = """
               Hi %s, 请点击下面链接重设密码！
               %s/juser/password/reset/?uuid=%s&timestamp=%s&hash=%s
               """ % (user.name, URL, user.uuid, timestamp, hash_encode)
            send_mail('忘记跳板机密码', msg, MAIL_FROM, [email], fail_silently=False)
            msg = '请登陆邮箱，点击邮件重设密码'
            return http_success(request, msg)
        else:
            error = '用户不存在或邮件地址错误'

    return render(request, 'user/forget_password.html', locals())


# 重置密码
@defend_attack
def reset_password(request):
    uuid_r = request.GET.get('uuid', '')
    timestamp = request.GET.get('timestamp', '')
    hash_encode = request.GET.get('hash', '')
    action = '/user/password/rest/?uuid={}&timestamp={}&hash={}'.format(uuid_r, timestamp, hash_encode)
    if hash_encode == PyCrypt.md5_crypt(uuid_r + timestamp + KEY):
        if int(time.time()) - int(timestamp) > 600:
            return http_error(request, '链接超时')
    else:
        return HttpResponse('hash效验失败')

    if request.method == 'POST':
        password = request.POST.get('password')
        password_confirm = request.POST.get('password_confirm')
        print(password, password_confirm)
        if password != password_confirm:
            return HttpResponse('两次输入的密码不一致!')
        else:
            user = get_object(User, uuid=uuid_r)
            if user:
                user.set_password(password)
                user.save()
                return http_success(request, '密码重设成功')
            else:
                return HttpResponse('用户不存在')

    else:
        return render(request, 'user/reset_password.html', locals())


# 添加用户组
@require_role(role='super')
def group_add(request):
    error = ''
    msg = ''
    herder_title, path1, path2 = '添加用户组', '用户组管理', '添加用户组'
    user_all = User.objects.all()
    if request.method == 'POST':
        group_name = request.POST.get('group_name', '')
        user_selected = request.POST.getlist('user_selected', '')
        comment = request.POST.get('comment', '')
        try:
            if not group_name:
                error = '组名不能为空'
                raise ServerError(error)
            if UserGroup.objects.filter(name=group_name):
                error = '组名已存在'
                raise ServerError(error)
            db_add_group(name=group_name, user_id=user_selected, comment=comment)
        except TypeError:
            error = '添加小组失败'
        except ServerError:
            pass
        else:
            msg = '添加组{}成功'.format(group_name)
    return render(request, 'user/group_add.html', locals())


# 修改用户组
@require_role(role='super')
def group_edit(request):
    error = ''
    msg = ''
    header_title, path1, path2 = '编辑用户组', '用户管理', '编辑用户组'
    if request.method == 'GET':
        group_id = request.GET.get('id', '')
        user_group = get_object(UserGroup, id=group_id)
        users_selected = get_object(User, group=user_group)
        user_remain = User.objects.filter(~Q(group=user_group))
        user_all = User.objects.all()
    elif request.method == 'POST':
        group_id = request.POST.get('id', '')
        group_name = request.POST.get('group_name', '')
        comment = request.POST.get('comment', '')
        users_selected = request.POST.getlist('users_selected')
        try:
            if '' in [group_id, group_name]:
                raise ServerError('组名不能为空')
            if len(UserGroup.objects.filter(name=group_name)) > 1:
                raise ServerError('{}用户组已存在'.format(group_name))

            user_group = get_object_or_404(UserGroup, id=group_id)
            user_group.user_set.clear()
            for user in User.objects.filter(id__in=users_selected):
                user.group.add(UserGroup.objects.get(id=group_id))

            user_group.name = group_name
            user_group.comment = comment
            user_group.save()
        except ServerError as e:
            error = e
        if not error:
            return HttpResponseRedirect(reverse('user_group_list'))
        else:
            users_all = User.objects.all()
            users_selected = User.objects.filter(group=user_group)
            users_remain = User.objects.filter(~Q(group=user_group))
    return render(request, 'user/group_edit.html', locals())


# 用户组列表
@require_role(role='super')
def group_list(request):
    header_title, path1, path2 = '查看用户组', '用户管理', '查看用户组'
    keyword = request.GET.get('search', '')
    user_group_list = UserGroup.objects.all().order_by('name')
    group_id = request.GET.get('id', '')
    if keyword:
        user_group_list = user_group_list.filter(Q(name__icontains=keyword) | Q(comment__icontains=keyword))
    if group_id:
        user_group_list = user_group_list.filter(id=int(group_id))
    user_group_list, p, user_groups, page_range, current_page, show_first, show_end = pages(user_group_list, request)
    return render(request, 'user/group_list.html', locals())


# 删除用户组
@require_role(role='super')
def group_del(request):
    group_ids = request.GET.get('id', '')
    group_id_list = group_ids.split(',')
    for group_id in group_id_list:
        UserGroup.objects.filter(id=group_id).delete()
    return HttpResponse('删除成功')


# 重发邮件
@require_role('admin')
def send_mail_retry(request):
    uuid_r = request.GET.get('uuid', '1')
    user = get_object(User, uuid=uuid_r)
    msg = """
    跳板机地址： %s
    用户名：%s
    重设密码：%s/juser/password/forget/
    请登录web点击个人信息页面重新生成ssh密钥
    """ % (URL, user.username, URL)

    try:
        send_mail('邮件重发', msg, MAIL_FROM, [user.email], fail_silently=False)
    except IndexError:
        return Http404
    return HttpResponse('发送成功')
