from django.core.mail import send_mail

from MyPerm.api import *
from MyPerm.settings import EMAIL_HOST_USER as MAIL_FROM, URL


# 数据库中添加用户
def db_add_user(**kwargs):
    groups_post = kwargs.pop('groups')
    admin_groups = kwargs.pop('admin_groups')
    role = kwargs.get('role', 'CU')
    user = User(**kwargs)
    user.set_password(kwargs.get('password'))
    user.save()
    if groups_post:
        group_select = []
        for group_id in groups_post:
            group = UserGroup.objects.filter(id=group_id)
            group_select.extend(group)
        user.group = group_select

    # 如果是组管理员就要添加组管理员和组到管理中
    if admin_groups and role == 'GA':
        for group_id in admin_groups:
            group = get_object(UserGroup, id=group_id)
            if group:
                AdminGroup(user=user, group=group).save()
    return user


# 数据库中删除用户
def db_del_user(username):
    user = get_object(User, username=username)
    if user:
        user.delete()


# 修改数据库中用户
def db_update_user(**kwargs):
    groups_post = kwargs.pop('groups')
    admin_groups_post = kwargs.pop('admin_groups')
    user_id = kwargs.pop('user_id')
    user = User.objects.filter(id=user_id)
    if user:
        user_get = user[0]
        password = kwargs.pop('password')
        user.update(**kwargs)
        if password.strip():
            user_get.set_password(password)
            user_get.save()
        else:
            return None
        group_select = []
        if groups_post:
            for group_id in groups_post:
                group = UserGroup.objects.filter(id=group_id)
                group_select.extend(group)
        user_get.group = group_select

        if admin_groups_post != '':
            user_get.admingroup_set.all().delete()
            for group_id in admin_groups_post:
                group = get_object(UserGroup, id=group_id)
                AdminGroup(user=user, group=group).save()


# 发送用户添加邮件
def user_add_mail(user, kwargs):
    """
    add user send mail
    发送用户添加邮件
    """
    user_role = {'SU': '超级管理员', 'GA': '组管理员', 'CU': '普通用户'}
    mail_title = '恭喜你的跳板机用户 %s 添加成功 Jumpserver' % user.name
    mail_msg = """
    Hi, %s
        您的用户名： %s
        您的权限： %s
        您的web登录密码： %s
        说明： xxxxxx！
    """ % (user.name, user.username, user_role.get(user.role, '普通用户'),
           kwargs.get('password'))
    send_mail(mail_title, mail_msg, MAIL_FROM, [user.email], fail_silently=False)


# 向前台发送注册相关信息
def get_display_msg(user, password='', send_mail_need=False):
    if send_mail_need:
        msg = '添加用户 %s 成功！ 用户密码已发送到 %s 邮箱！' % (user.name, user.email)
    else:
        msg = """
               用户名：%s <br />
               密码：%s <br />
               地址：%s <br />
               该账号密码可以登陆web和跳板机。
               """ % (user.username, password, URL)
    return msg


# 向用户组添加用户写入数据库
def group_add_user(group, user_id=None, username=None):
    if user_id:
        user = get_object(User, user_id)
    else:
        user = get_object(User, username=username)
    if user:
        group.user_set.add(user)


# 向数据库添加用户组
def db_add_group(**kwargs):
    name = kwargs.get('name')
    group = get_object(UserGroup, name=name)
    users = kwargs('user_id')
    if not group:
        group = UserGroup(**kwargs)
        group.save()
        for user_id in users:
            group_add_user(group, user_id)
