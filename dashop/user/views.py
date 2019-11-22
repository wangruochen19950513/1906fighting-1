# Create your views here.
import hashlib
import random
import base64
import json

from urllib.parse import unquote
from celery_tasks.user_tasks import send_verify
from .models import UserProfile, Address, WeiboUser
from django_redis import get_redis_connection
from django.views.generic import View
from django.http import JsonResponse
from django.db import transaction
from dtoken.views import make_token
from .weiboapi import OAuthWeibo
from utils.loging_decorator import logging_check,get_username_by_request,get_user_by_request

# Create your views here.

class CreateAddresses(View):
    """
    用来生成用户地址列表
    """
    def get_address_list(self,alladdress):
        addressList = []
        for values in alladdress:
            each_address = {}
            each_address['id'] = values.id
            each_address['address'] = values.address
            each_address['receiver'] = values.receiver
            each_address['receiver_mobile'] = values.receiver_mobile
            each_address['tag'] = values.tag
            each_address['is_default'] = values.default_address
            addressList.append(each_address)
        return addressList


class ModifyPasswordView(View):
    """
    用户登陆状态下 修改密码：
    http://127.0.0.1:8000/v1/user/<username>/password
    """
    @logging_check
    def post(self, request, username):
        """
        :param request:
        :return:
        """
        user = get_user_by_request(request)
        data = json.loads(request.body)
        oldpassword = data.get('oldpassword', None)
        password1 = data.get('password1', None)
        password2 = data.get('password2', None)
        if not oldpassword:
            return JsonResponse({'code': 10103, 'error': {'message': 'Old password error!'}})
        if not password1:
            return JsonResponse({'code': 10108, 'error': {'message': 'please enter your password!'}})
        if not password2:
            return JsonResponse({'code': 10109, 'error': {'message': 'Confirm that the password is incorrect!'}})
        if oldpassword == password1 or oldpassword == password2:
            return JsonResponse({'code': 10109, 'error': {'message': 'Use Different Password!'}})
        token_username = get_username_by_request(request)
        if token_username != username:
            return JsonResponse({'code': 10131, 'error': {'message': 'User not logged in!'}})
        # 判断两次密码是否一致
        if password1 != password2:
            return JsonResponse({'code': 10102, 'error': {'message': 'Inconsistent passwords!'}})
        try:
            user = UserProfile.objects.get(username=token_username)
        except Exception as e:
            return JsonResponse({'code': 10104, 'error': {'message': 'User query error'}})
        real_password = user.password
        m = hashlib.md5()
        m.update(oldpassword.encode())
        if m.hexdigest() != real_password:
            return JsonResponse({'code': 10103, 'error': {'message': 'Old password error!'}})
        new = hashlib.md5()
        new.update(password1.encode())
        user.password = new.hexdigest()
        user.save()
        return JsonResponse({'code': 200, 'data': {'message': 'OK'}})


class SendSmsCodeView(View):
    """
    用户找回密码视图处理函数：
    分为三步：
    1.验证邮箱，并且发送邮件验证码
    2.验证邮件验证码，
    3.验证码验证成功，修改密码
    """

    def post(self, request):
        data = json.loads(request.body)
        email = data.get('email',None)

        if not email:
            return JsonResponse({'code': 10100, 'error': {'message': 'Invalid parameters!'}})
        # 验证用户是否是已经注册用户
        try:
            user = UserProfile.objects.get(email=email)
        except Exception as e:
            return JsonResponse({'code': 10104, 'error': {'message': 'User query error'}})
        # 先去查询该用户是否在时效时间内发送过验证码
        redis_conn = get_redis_connection('verify_email')
        try:
            email_code = redis_conn.get('email_code_%s'%email)
        except Exception as e:
            return JsonResponse({'code': 10132, 'data': {'message': 'Verify Code Error'}})
        if email_code:
            return JsonResponse({'code': 202, 'data': {'message': 'please enter your code!'}})

        email_code = "%06d" % random.randint(0, 999999)
        try:
            redis_conn.setex("email_code_%s" % email, 10 * 60, email_code)
        except Exception as e:
            return JsonResponse({'code': 10105, 'error': {'message': 'Storage authentication code failed'}})
        send_verify.delay(email=email, email_code=email_code, sendtype=0)
        return JsonResponse({'code': 200, 'data': {'message': 'OK'}})


class VerifyCodeView(View):
    """
    第二步 验证发送邮箱的验证码
    """

    def post(self, request, username):
        """
        验证用户邮箱验证码
        :param request:
        :param username: 用户名
        :return:
        """
        data = json.loads(request.body)
        email = data.get('email', None)
        code = data.get('code', None)
        if not email:
            return JsonResponse({'code': 10100, 'error': {'message': 'Invalid parameters'}})
        if not code:
            return JsonResponse({'code': 10100, 'error': {'message': 'Invalid parameters'}})
        # 验证用户是否匹配
        redis_conn = get_redis_connection('verify_email')
        try:
            email_code = redis_conn.get('email_code_%s' % email)
        except Exception as e:
            return JsonResponse({'code': 10106,
                                 'error': {'message': 'The validation code is invalid. Please send it again.'}})
        redis_code = email_code.decode()
        if redis_code == code:
            return JsonResponse({'code': 200, 'data': {'message': 'OK'}, 'email': email})


class ModifyPwdView(View):
    """
    最后一步验证邮箱，修改密码
    """

    def post(self, request, username):
        data = json.loads(request.body)
        old_password = data.get('old_password', None)
        password1 = data.get('password1', None)
        password2 = data.get('password2', None)
        if not old_password:
            return JsonResponse({'code': 10107,
                                 'error': {'message': 'Unable to retrieve old password'}})
        if not password1:
            return JsonResponse({'code': 10108, 'error': {'message': 'please enter password!'}})
        if not password2:
            return JsonResponse({'code': 10109, 'error': {'message': 'Confirm that the password is incorrect!'}})

        if password1 != password2:
            return JsonResponse({'code': 10110, 'error': {'message': 'Password Inconsistencies!'}})
        try:
            user = UserProfile.objects.get(username=username)
        except Exception as e:
            return JsonResponse({'code': 10104, 'error': {'message': 'User query error!'}})
        # 读取旧密码
        real_password = user.password
        # 用户输入的旧密码
        m = hashlib.md5()
        m.update(old_password.encode())
        if m.hexdigest() != real_password:
            return JsonResponse({'code': 10111, 'error': {'message': 'Old password error!'}})
        new = hashlib.md5()
        new.update(password1.encode())
        user.password = new.hexdigest()
        user.save()
        return JsonResponse({'code': 200, 'data': {'message': 'OK'}})


class ActiveView(View):
    """
    # 用户发送邮件激活
    # GET http://127.0.0.1:8000/v1/user/active?code=xxxxx&username=xxx
    """
    def get(self, request):
        """
        由于没有设置激活链接的参数的redis中的有效时间。
        在用户激活之后删除redis中缓存的激活链接
        """
        code = request.GET.get('code', None)
        username = request.GET.get('username', None)
        if not username:
            return JsonResponse({'code': 10113, 'error': {'message': 'Error activating link parameters'}})
        if not code:
            return JsonResponse({'code': 10113, 'error': {'message': 'Error activating link parameters'}})
        try:
            user = UserProfile.objects.get(username=username)
        except Exception as e:
            return JsonResponse({'code': 10104, 'error': {'message': 'User query error!'}})
        email = user.email
        redis_conn = get_redis_connection('verify_email')
        result = redis_conn.get('email_active_%s' % email)
        if not result:
            return JsonResponse({'code': 10112, 'error': {'message': 'Verify that the link is invalid and resend it!'}})
        user.isActive = True
        user.save()
        redis_conn.delete('email_active_%s'%email)
        return JsonResponse({'code': 200, 'data': {'message': 'OK'}})


class AddressView(CreateAddresses):
    """
    get: 获取用户的绑定的收获地址
    post: 新增用户绑定的收获地址
    delete：实现用户删除地址功能
    put: 实现用户修改地址功能
    """
    @logging_check
    def get(self, request, username, id=None):
        """
        返回用户关联的地址页面，以及地址
        :param request:
        :return: addressAdmin.html & addresslist
        """
        try:
            user = UserProfile.objects.get(username=username)
        except Exception as e:
            return JsonResponse({'code': 10104, 'error': {'message': 'User query error'}})
        # 获取用户的id
        userId = user.id
        # 返回当前用户所有地址，
        try:
            all_address = Address.objects.filter(uid=userId, is_alive=True)
            # 获取用户地址，然后用json的地址返回查询后根据querySet 返回相应的字符串。
        except Address.DoesNotExist as e:
            return JsonResponse({'code': 10114, 'error': {'message': 'Error in Address Query!'}})
        addressList =self.get_address_list(all_address)
        result = {
            'code': 200,
            'data': {
                'addresslist': addressList
            }
        }
        return JsonResponse(result)

    @logging_check
    def post(self, request, username, id=None):
        """
        用来提交保存用户的收获地址
        1.先获取相应的用户，然后根据用户的id来绑定地址
        :param request:
        :return:返回保存后的地址以及地址的id
        """
        data = json.loads(request.body)
        if not data:
            return JsonResponse({'code': 10100, 'error': {'message': 'Submit invalid parameters'}})
        receiver = data.get('receiver', None)
        if not receiver:
            return JsonResponse({'code': 10115, 'error': {'message': 'invalid recipients'}})
        address = data.get('address', None)
        if not address:
            return JsonResponse({'code': 10116, 'error': {'message': 'Invalid address'}})
        receiver_phone = data.get('receiver_phone', None)
        if not receiver_phone:
            return JsonResponse({'code': 10117, 'error': {'message': 'Invalid phone number'}})
        postcode = data.get('postcode', None)
        if not postcode:
            postcode = '0000000'
        tag = data.get('tag', None)
        if not tag:
            return JsonResponse({'code': 10119, 'error': {'message': 'Invalid tag'}})
        try:
            user = UserProfile.objects.get(username=username)
        except UserProfile.DoesNotExist as e:
            return JsonResponse({'code': 10104, 'error': {'message': 'User query error'}})
        # 先查询当前用户有没有保存的地址。
        # 如果有则需要将default_address 设置为False
        # 如果没有则需要default_address 设置为True
        query_address = Address.objects.filter(uid=user.id)
        if not query_address:
            try:
                Address.objects.create(
                    uid=user,
                    receiver=receiver,
                    address=address,
                    default_address=True,
                    receiver_mobile=receiver_phone,
                    is_alive=True,
                    postcode=postcode,
                    tag=tag,
                )
            except Exception as e:
                return JsonResponse({'code': 10120, 'error': {'message': 'Address storage exception'}})
            try:
                all_address = Address.objects.filter(uid=user, is_alive=True)
            except Exception as e:
                return JsonResponse({'code': 10121, 'error': {'message': 'Address storage exception'}})
            addressList =(all_address)
            result = {
                'code': 200,
                'data': {
                    'addresslist': addressList
                }
            }
            return JsonResponse(result)
        else:
            try:
                Address.objects.create(
                    uid=user,
                    receiver=receiver,
                    address=address,
                    default_address=False,
                    receiver_mobile=receiver_phone,
                    is_alive=True,
                    postcode=postcode,
                    tag=tag,
                )
            except Exception as e:
                return JsonResponse({'code': 10120, 'error': {'message': 'Address storage exception'}})
            try:
                all_address = Address.objects.filter(uid=user, is_alive=True)
            except Exception as e:
                return JsonResponse({'code': 10121, 'error': {'message': 'Get address exception'}})
            addressList =self.get_address_list(all_address)     
            result = {
                'code': 200,
                'data': {
                    'addresslist': addressList
                }
            }
            return JsonResponse(result)

    @logging_check
    def delete(self, request, username, id=None):
        """
         删除用户的提交的地址
         :param request: 提交的body中为用户的地址的id
         :param username:
         :return: 删除后用户的所有的收获地址
        """
        # 根据用户发来的地址的id来直接删除用户地址
        if not id:
            return JsonResponse({'code': 10122, 'error': {'message': 'Get address id error'}})
        try:
            address = Address.objects.get(id=id)
        except Address.DoesNotExist as e:
            # 此刻应该写个日志
            return JsonResponse({'code': 10121, 'error': {'message': 'Get address exception'}})
        address.is_alive = False
        address.save()
        # 获取用户的id，然后根据用户的id来返回用户绑定的所有的未删除的地址
        uid = address.uid
        # 将包含用户的uid的以及用户的可以用的地址删选出来
        try:
            all_address = Address.objects.filter(uid=uid, is_alive=True)
        except Address.DoesNotExist as e:
            return JsonResponse({'code': 10121, 'error': {'message': 'Get address exception'}})
        addressList =self.get_address_list(all_address)
        result = {
            'code': 200,
            'data': {
                'addresslist': addressList
            }
        }
        return JsonResponse(result)

    @logging_check
    def put(self, request, username, id=None):
        """
        根据用户传递过来的收货地址来修改相应的内容
        :param request: 用户请求的对象
        :param address_id:用户地址id
        :return: 返回修改之后的地址的全部内容
        """
        if not id:
            return JsonResponse({'code': 10122, 'error': {'message': 'Get address id error'}})
        try:
            data = json.loads(request.body)
        except Exception as e:
            return JsonResponse({'code': 10123, 'error': {'message': 'Error in address modification parameters!'}})
        address = data.get('address',None)
        receiver = data.get('receiver',None)
        tag = data.get('tag',None)
        receiver_mobile = data.get('receiver_mobile',None)
        # 1  根据地址的id筛选出那一条记录
        try:
            filter_address = Address.objects.filter(id=id)[0]
        except Exception as e:
            return JsonResponse({'code': 10122, 'error': {'message': 'Get address exception!'}})
        # 要修改的地址
        # 修改内容：
        filter_address.receiver = receiver
        filter_address.receiver_mobile =receiver_mobile
        filter_address.address = address
        filter_address.tag = tag
        filter_address.save()
        # 将所有的地址都筛选出来，返回
        uid = filter_address.uid
        try:
            all_address = Address.objects.filter(uid=uid, is_alive=True)
        except Address.DoesNotExist as e:
            return JsonResponse({'code': 10121, 'error': {'message': 'Get address exception'}})
        addressList =self.get_address_list(all_address)
        result = {
            'code': 200,
            'data': {
                'addresslist': addressList
            }
        }
        return JsonResponse(result)


class DefaultAddressView(CreateAddresses):
    """
    用来修改默认地址
    """
    @logging_check
    def post(self, request, username):
        """
        用来修改默认地址
        :param request:用户请求对象
        :param address_id:用户修改地址的id
        :return:
        """
        # 先根据address_id 来匹配出用户的id
        # 找到用户的id之后选出所有的用户地址。
        # 在将用户地址id为address_id 设为默认
        json_obj = json.loads(request.body)
        address_id = json_obj.get('id',None)
        if not address_id:
            return JsonResponse({'code': 10121, 'error': {'message': 'Get address id exception!'}})
        try:
            address = Address.objects.get(id=address_id)
        except Exception as e:
            return JsonResponse({'code': 10121, 'error': {'message': 'Get address exception!'}})
        # 用户ID
        uid = address.uid
        user_address = Address.objects.filter(uid=uid)
        for single_address in user_address:
            if single_address.id == address_id:
                single_address.default_address = True
                single_address.save()
            else:
                single_address.default_address = False
                single_address.save()
        # 返回用户所有地址
        try:
            all_address = Address.objects.filter(uid=uid, is_alive=True)
        except Address.DoesNotExist as e:
            return JsonResponse({'code': 10121, 'error': {'message': 'Get address exception!'}})
        addressList =self.get_address_list(all_address)
        result = {
            'code': 200,
            'data': {
                'addresslist': addressList
            }
        }
        return JsonResponse(result)


class OAuthWeiboUrlView(View):
    def get(self, request):
        """
        用来获取微博第三方登陆的url
        :param request:
        :param username:
        :return:
        """
        try:
            oauth_weibo = OAuthWeibo()
            oauth_weibo_url = oauth_weibo.get_weibo_login_code()
        except Exception as e:
            return JsonResponse({'code': 10124, 'message': {'message': 'Cant get weibo login page'}})
        print('test')
        return JsonResponse({'code': 200, 'oauth_url': oauth_weibo_url})


class OAuthWeiboView(View):
    def get(self, request):
        """
        获取用户的code,以及用户的token
        :param request:
        :return:
        """
        # 首先获取两个参数code 和state
        code = request.GET.get('code', None)
        if not code:
            return JsonResponse({'code': 10100, 'error': {'message': 'Invalid parameters'}})
        try:
            oauth_weibo = OAuthWeibo()
        except Exception as e:
            return JsonResponse({'code': 10125, 'error': {'message': 'Unable to get weibo token'}})
        # 返回用户的绑定信息
        # 信息格式为
        """
        data = {
            # 用户令牌，可以使用此作为用户的凭证
            "access_token": "2.00aJsRWFn2EsVE440573fbeaF8vtaE",
            "remind_in": "157679999",             # 过期时间
            "expires_in": 157679999,
            "uid": "5057766658",
            "isRealName": "true"
        }
        """
        userInfo = oauth_weibo.get_access_token_uid(code)
        # 将用户weibo的uid传入到前端
        weibo_uid = userInfo_dict.get('uid')
        try:
            weibo_user = WeiboUser.objects.get(uid=weibo_uid)
        except Exception as e:
            # 如果查不到相关的token 则说明没用绑定相关的用户
            # 没有绑定微博用户则说明用户表中也没有创建用户信息。此时返回access_token,
            # 并且让跳转到 绑定用户的页面，填充用户信息，提交 绑定微博信息
            data = {
                'code': '201',
                'uid': weibo_uid 
            }
            return JsonResponse(data)
        else:
            # 如果查询到相关用户绑定的uid
            # 此时正常登陆。然后返回jwt_token
            user_id = weibo_user.uid
            str_user_id = str(user_id)
            try:
                user = UserProfile.objects.get(id=int(str_user_id))
            except Exception as e:
                return JsonResponse({'code':10134,'error':{'message':'Cant get User'}})
            username = user.username
            token = make_token(username)
            result = {'code': 200, 'username': username, 'data': {'token': token.decode()}}
            return JsonResponse(result)

    def post(self, request):
        """
        此时用户提交了关于个人信息以及uid
        创建用户，并且创建绑定微博关系
        :param requset:
        :return:
        """
        data = json.loads(request.body)
        uid = data.get('uid', None)
        username = data.get('username', None)
        password = data.get('password', None)
        phone = data.get('phone', None)
        email = data.get('email', None)
        if not username:
            return JsonResponse({'code': 201, 'error': {'message': 'Invalid username!'}})
        if not password:
            return JsonResponse({'code': 10108, 'error': {'message': 'Invalid password!'}})
        if not email:
            return JsonResponse({'code': 10126, 'error': {'message': 'Invalid email'}})
        if not phone:
            return JsonResponse({'code': 10117, 'error': {'message': 'Invalid phone number!'}})
        if not uid:
            return JsonResponse({'code': 10130, 'error': {'message': 'Invalid access token!'}})
        # 创建用户表
        m = hashlib.md5()
        m.update(password.encode())
        # 创建用户以及微博用户表
        try:
            with transaction.Atomic(using=None, savepoint=True):
                UserProfile.objects.create(username=username, password=m.hexdigest(),
                                       email=email, phone=phone)
                user = UserProfile.objects.get(username=username) 
                user.uid = uid
                user.save()
        except Exception as e:
            print(e)
            return JsonResponse({'code': 10128, 'error': {'message': 'create user failed!'}})
        # 创建成功返回用户信息
        token = make_token(username)
        result = {'code': 200, 'username': username, 'data': {'token': token.decode()}}
        return JsonResponse(result)


class Users(View):
    def get(self, request, username=None):
        pass

    def post(self, request):

        json_str = request.body
        if not json_str:
            result = {'code': 10132, 'error': 'No data found'}
            return JsonResponse(result)

        json_obj = json.loads(json_str)

        username = json_obj.get('uname')
        if not username:
            result = {'code': 202, 'error': 'Please give me username'}
            return JsonResponse(result)
        email = json_obj.get('email')
        if not email:
            result = {'code': 203, 'error': 'Please give me email'}
            return JsonResponse(result)
        # 优先查询当前用户名是否已存在
        old_user = UserProfile.objects.filter(username=username)

        if old_user:
            result = {'code': 206, 'error': 'Your username is already existed'}
            return JsonResponse(result)

        password = json_obj.get('password')
        m = hashlib.md5()
        m.update(password.encode())

        phone = json_obj.get('phone')
        if not phone:
            result = {'code': 207, 'error': 'Please give me phone'}
            return JsonResponse(result)

        try:
            UserProfile.objects.create(username=username, password=m.hexdigest(),
                                       email=email, phone=phone)
        except Exception as e:
            result = {'code': 208, 'error': 'Server is busy'}
            return JsonResponse(result)
        # 发送用户激活链接
        code_str = username + '.' + email
        # 生成激活链接：
        active_code = base64.b64encode(code_str.encode(encoding='utf-8')).decode('utf-8')
        redis_conn = get_redis_connection('verify_email')
        ### todo : 用户激活链接永久有效
        redis_conn.set("email_active_%s" % email, active_code)
        verify_url = 'http://127.0.0.1:8080/templates/web/active.html?code=%s&username=%s' % (active_code, username)
        token = make_token(username)
        result = {'code': 200, 'username': username, 'data': {'token': token.decode()}}
        send_verify.delay(email=email, verify_url=verify_url, sendtype=1)
        return JsonResponse(result)


class SmScodeView(View):
    """
    实现短信验证码功能
    """
    def post(self, request):
        """
        短信测试：
        :param request:
        :return:
        """
        data = json.loads(request.body)
        if not data:
            return JsonResponse({'code': 10131, 'error': {'message': 'Invalid phone number!'}})
        phone = data.get('phone', None)
        code = "%06d" % random.randint(0, 999999)
        try:
            redis_conn = get_redis_connection('verify_email')
            redis_conn.setex("sms_code_%s" % phone, 3 * 60, code)
        except Exception as e:
            return JsonResponse({'code': 10105, 'error': {'message': 'Storage authentication code failed'}})
        send_verify.delay(phone=phone, code=code, sendtype=2)
        return JsonResponse({'code': 200, 'data': {'message': 'OK'}})
