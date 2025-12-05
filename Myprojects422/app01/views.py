# 导入Django和必要的库
from django.shortcuts import render, HttpResponse, redirect
import requests
import json
from django.http import HttpRequest, JsonResponse
from django.core.paginator import Paginator
from django.http import StreamingHttpResponse
def home(request):
    """首页视图，渲染home.html模板"""
    return render(request, 'home.html')

def login_check(request: HttpRequest):
    """
    登录验证视图
    参数:request: HttpRequest对象，包含请求信息
    返回:登录成功则重定向到容器页面，失败则返回登录页并显示错误信息
    """
    # 获取用户名和密码
    username = request.POST.get("u")
    password = request.POST.get("p")
    # 调用get_token函数验证用户凭据
    code = get_token(username, password)
    if code.status_code == 201:
        # 如果验证成功，将用户信息和token保存在session中
        # 注意：在运行项目前，需先执行python manage.py migrate创建session表
        request.session['user'] = username
        request.session['token'] = code.headers.get("X-Subject-Token")
        return redirect('/containers')
    else:
        # 登录失败，显示错误信息
        error_msg = "用户名或密码不正确，请重新登录"
        return render(request, "home.html", {
            'login_error_msg': error_msg,
        })

def create_openstack_user(username, password, email):
    """
    在OpenStack中创建新用户
    参数:username: 用户名password: 密码email: 邮箱地址
    返回:(成功标志, 消息)元组，成功返回(True, "用户创建成功")，失败返回(False, 错误信息)
    """
    # 首先使用管理员账户获取token
    admin_token = get_admin_token()
    if not admin_token:
        return False, "获取管理员权限失败"
    
    # 准备创建用户的数据
    user_data = {
        "user": {
            "name": username,
            "password": password,
            "email": email,
            "enabled": True
        }
    }
    
    # OpenStack Identity API创建用户的端点
    url = "http://192.168.17.222:5000/v3/users"
    headers = {
        "X-Auth-Token": admin_token,
        "Content-Type": "application/json"
    }
    
    try:
        # 发送创建用户的请求
        response = requests.post(url, headers=headers, data=json.dumps(user_data))
        if response.status_code == 201:
            # 创建成功，获取用户ID
            user_id = response.json()['user']['id']
            # 为用户分配到默认项目（admin项目）
            assign_user_to_project(user_id, admin_token)
            return True, "用户创建成功"
        else:
            return False, f"创建用户失败: {response.text}"
    except Exception as e:
        return False, f"创建用户异常: {str(e)}"

def get_admin_token():
    """
    获取管理员token，用于创建用户等需要管理员权限的操作
    返回:
        成功返回管理员token字符串，失败返回None
    """
    # 准备管理员认证数据
    admin_data = {
        "auth": {
            "identity": {
                "methods": ["password"],
                "password": {
                    "user": {
                        "domain": {"name": "default"},
                        "name": "admin",  # 管理员用户名
                        "password": "1234"  # 管理员密码
                    }
                }
            },
            "scope": {
                "project": {
                    "domain": {"name": "default"},
                    "name": "admin"
                }
            }
        }
    }
    
    # 发送认证请求
    url = "http://192.168.17.222:5000/v3/auth/tokens"
    response = requests.post(url, data=json.dumps(admin_data))
    
    if response.status_code == 201:
        # 获取并返回X-Subject-Token
        return response.headers.get("X-Subject-Token")
    return None

def assign_user_to_project(user_id, admin_token):
    """
    将用户分配到默认项目(admin项目)并授予admin角色
    参数:user_id: 用户ID admin_token: 管理员token
    
    """
    # 获取默认项目ID（admin项目）
    project_url = "http://192.168.17.222:5000/v3/projects?name=admin"
    #防止未授权访问任何项目或域名将创建的用户名分配到admin项目中去
    headers = {"X-Auth-Token": admin_token}
    response = requests.get(project_url, headers=headers)
    if response.status_code == 200:
        project_id = response.json()['projects'][0]['id']
        # 获取admin角色ID
        role_url = "http://192.168.17.222:5000/v3/roles?name=admin"
        role_response = requests.get(role_url, headers=headers)
        if role_response.status_code == 200:
            role_id = role_response.json()['roles'][0]['id']
            # 分配角色
            assign_url = f"http://192.168.17.222:5000/v3/projects/{project_id}/users/{user_id}/roles/{role_id}"
            #给创建的用户分配admin角色
            requests.put(assign_url, headers=headers)

# 修改现有的register函数
def register(request: HttpRequest):
    """
    用户注册视图
    参数:request: HttpRequest对象，包含请求信息
    返回:GET请求返回注册页面，POST请求处理注册逻辑并返回相应结果
    """
    if request.method == 'GET':
        # 显示注册页面
        return render(request, 'register.html')
    elif request.method == 'POST':
        # 获取表单数据
        username = request.POST.get('username')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')
        email = request.POST.get('email')
        
        # 验证表单数据
        if not username or not password:
            error_msg = "用户名或密码不能为空，请重新输入"
            return render(request, "register.html", {'error_msg': error_msg,})
        if password != confirm_password:
            error_msg = "两次密码输入不一致，请重新输入"
            return render(request, "register.html", {'error_msg': error_msg,})
        
        # 调用函数在OpenStack中创建用户
        success, message = create_openstack_user(username, password, email)
        if success:
            # 记录注册日志
            log_action(username, "用户注册成功")
            # 注册成功后重定向到登录页
            return redirect('/home')
        else:
            # 注册失败，显示错误信息
            return render(request, "register.html", {'error_msg': message})

def get_token(username, password):
    """
    获取用户认证token
    参数:username: 用户名password: 密码
    返回:包含认证结果的response对象
    """
    # 准备认证数据
    data = {
        "auth": {
            "identity": {
                "methods": ["password"],
                "password": {
                    "user": {
                        "domain": {"name": "default"},
                        "name": username,
                        "password": password
                    }
                }
            },
            "scope": {
                "project": {
                    "domain": {"name": "default"},
                    "name": "admin"
                }
            }
        }
    }
    # 调用OpenStack认证接口
    url = "http://192.168.17.222:5000/v3/auth/tokens" # OpenStack认证接口地址
    code = requests.post(url, data=json.dumps(data)) # 将Python对象编码成JSON字符串
    return code

def containers(request: HttpRequest):
    """
    容器列表视图
    参数:request: HttpRequest对象
    返回:渲染后的容器列表页面
    """
    # 设置请求头，包含认证token
    headers = {}
    headers['X-Auth-Token'] = request.session['token']
    # OpenStack对象存储API地址
    url2 = "http://192.168.17.222:8080/v1/AUTH_0a1976918df0407da41ab01eca0b9974?format=json"
    # 发送请求获取容器列表
    resp1 = requests.get(url2, headers=headers)
    resp2 = resp1.json()
    # 分页显示，每页7个容器
    pages = Paginator(resp2, 7)
    try:
        page_number = request.GET['page']
    except:
        page_number = 1
    page = pages.get_page(page_number)
    print(page)
    # 渲染容器列表页面
    return render(request, 'containers.html', {'resp1': page})

# 进入容器读取对象
def objects(request, data2):
    """
    容器内对象列表视图
    参数:request: HttpRequest对象data2: 容器名称
    返回:渲染后的对象列表页面
    """
    # 设置请求头，包含认证token
    headers = {}
    headers["X-Auth-Token"] = request.session.get('token')
    # 构建获取容器内对象的API地址
    url4 = "http://192.168.17.222:8080/v1/AUTH_0a1976918df0407da41ab01eca0b9974/" + str(data2)+"?format=json"
    # 发送请求获取对象列表
    resp3 = requests.get(url4, headers=headers)
    resp4 = resp3.json()
    # 搜索功能：获取搜索关键词
    search_query = request.GET.get('search', '').strip()
    if search_query:
        # 过滤文件名包含搜索关键词的文件
        resp4 = [obj for obj in resp4 if search_query.lower() in obj['name'].lower()]

    # 排序功能
    sort_by = request.GET.get('sort', 'name')
    if sort_by == 'name':
        resp4.sort(key=lambda x: x['name'].lower())  # 按名称排序
    elif sort_by == 'date':
        resp4.sort(key=lambda x: x['last_modified'], reverse=True)  # 按日期排序（最新在前）
    elif sort_by == 'size':
        resp4.sort(key=lambda x: x['bytes'])  # 按大小排序
    # 分页显示，每页6个对象
    pages = Paginator(resp4, 6)
    try:
        page_number = request.GET['page']
    except:
        page_number = 1
    page = pages.get_page(page_number)
    # 渲染对象列表页面，传递分页后的数据、容器名称、搜索关键词和排序方式
    return render(request, 'objects.html', {'resp1': page, 'data2': data2, 'search_query': search_query, 'sort_by': sort_by}) 

def addContainer(request, data):
    """
    创建新容器视图
    参数:request: HttpRequest对象data: 容器名称
    返回:重定向到容器列表页面
    """
    # 设置请求头，包含认证token
    headers = {}
    headers["X-Auth-Token"] = request.session.get('token')
    # 构建创建容器的API地址
    url = "http://192.168.17.222:8080/v1/AUTH_0a1976918df0407da41ab01eca0b9974/" + str(data)
    # 发送PUT请求创建容器
    requests.put(url, headers=headers)
    # 重定向到容器列表页面
    return redirect('/containers')

def logout(request):
    """登出视图，清空session
    参数:request: HttpRequest对象
    返回:重定向到首页
    """
    # 清空session中的所有数据
    request.session.flush()
    # 重定向到首页
    return redirect('/home')

def download(request: HttpRequest, container, object):
    """文件下载视图
    参数:request: HttpRequest对象container: 容器名称object: 文件名
    返回: 流式下载响应
    """
    # 构建文件下载地址
    url = f"http://192.168.17.222:8080/v1/AUTH_0a1976918df0407da41ab01eca0b9974/{container}/{object}"
    headers = {}
    headers["X-Auth-Token"] = request.session.get('token')
    # 获取文件内容
    datas = requests.get(url, headers=headers)
    # 记录下载日志
    log_action(request.session.get('user', 'unknown'), f"下载文件: {object} 从容器: {container}")
    # 创建流式响应
    response = StreamingHttpResponse(datas)
    response['Content-Type'] = "application/text"
    # 设置Content-Disposition头，使浏览器提示下载
    response['Content-Disposition'] = 'attachment;filename=' + object.encode('utf-8').decode('ISO-8859-1')
    return response

def upload(request: HttpRequest, object):
    """
    文件上传视图
    参数:request: HttpRequest对象object: 目标容器名称
    返回:上传成功重定向到对象列表，失败返回错误信息
    """
    # 1.获取token
    headers = {}
    headers["X-Auth-Token"] = request.session.get('token')
    # 2.获取前端传来的文件
    file_obj = request.FILES.get('filename')
    if not file_obj:
        return HttpResponse('请选择要上传的文件')
    # 3.读取文件内容（二进制模式）
    file_content = file_obj.read()
    # 4.设置Content-Type
    if file_obj.content_type:
        headers['Content-Type'] = file_obj.content_type
    # 5.定义上传接口URL
    url = f"http://192.168.17.222:8080/v1/AUTH_0a1976918df0407da41ab01eca0b9974/{object}/{file_obj.name}"

    # 6.发送请求到接口地址
    try:
        response = requests.put(url, headers=headers, data=file_content)
        if response.status_code == 201:
            # 记录上传日志
            log_action(request.session.get('user', 'unknown'), f"上传文件: {file_obj.name} 到容器: {object}")
            # 上传成功，重定向回对象列表并传递成功参数
            return redirect(f'/objects/{object}?upload=success')
        else:
            return HttpResponse(f'上传失败，状态码: {response.status_code}')
    except Exception as e:
        return HttpResponse(f'上传失败: {str(e)}')

def delete(request: HttpRequest, container, object):
    """
    文件删除视图
    参数:request: HttpRequest对象container: 容器名称object: 文件名
    返回:重定向到对象列表页面
    """
    # 1.获取token
    headers = {}
    headers["X-Auth-Token"] = request.session.get('token')
    # 2.定义删除接口URL
    url = f"http://192.168.17.222:8080/v1/AUTH_0a1976918df0407da41ab01eca0b9974/{container}/{object}"
    # 3.发送删除请求
    requests.delete(url, headers=headers)
    # 记录删除日志
    log_action(request.session.get('user', 'unknown'), f"删除文件: {object} 从容器: {container}")
    # 重定向回对象列表页面
    return redirect('/objects/'+container)

def view_file(request: HttpRequest, container, object, content_type):
    """
    文件查看视图
    参数request: HttpRequest对象container: 容器名称object: 文件名content_type: 内容类型
    返回:渲染后的文件查看页面
    """
    # 1.获取token
    headers = {}
    headers["X-Auth-Token"] = request.session.get('token')
    # 2.定义获取文件内容的接口URL
    url = f"http://192.168.17.222:8080/v1/AUTH_0a1976918df0407da41ab01eca0b9974/{container}/{object}"
    # 3.发送请求获取文件内容
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        # 4.处理文件内容编码
        file_content = ""
        is_image = False
        is_pdf = False
        # 检查是否为PDF文件
        if content_type == 'application/pdf':
            is_pdf = True
        # 检查是否为图片文件
        elif content_type.startswith('image/'):
            # 图片文件直接显示，不读取文本内容
            file_content = ""
            is_image = True
        elif content_type.startswith('text/') or 'text' in content_type:
            file_content = response.content.decode('utf-8')
            
        else:
            # 非文本非图片非PDF文件，提示下载
            try:
                file_content = response.content.decode('utf-8', errors='replace')
            except:
                file_content = "二进制文件，无法直接查看内容，请下载后查看"

        # 5.准备上下文数据
        context = {
            'file_name': object,
            'content_type': content_type,
            'file_content': file_content,
            'container': container,
            'data2': container,  # 用于返回按钮
            'is_image': is_image,
            'is_pdf': is_pdf
        }
        # 记录查看日志
        log_action(request.session.get('user', 'unknown'), f"查看文件: {object} 从容器: {container}")
        # 6.渲染查看文件页面
        return render(request, 'view_file.html', context)
    except Exception as e:
        return HttpResponse(f'查看文件失败: {str(e)}')

def check_container_objects(request, container):
    """
    检查容器中是否有对象的视图
    参数:request: HttpRequest对象container: 容器名称
    返回:JSON响应，包含has_objects布尔值
    """
    # 设置请求头，包含认证token
    headers = {}
    headers["X-Auth-Token"] = request.session.get('token')
    # 构建获取容器内对象的API地址
    url = f"http://192.168.17.222:8080/v1/AUTH_0a1976918df0407da41ab01eca0b9974/{container}?format=json"
    try:
        # 发送请求获取对象列表
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            objects = response.json()
            has_objects = len(objects) > 0
            return JsonResponse({'has_objects': has_objects})
        else:
            return JsonResponse({'has_objects': False})
    except Exception as e:
        return JsonResponse({'has_objects': False})

def delete_container(request, container):
    """
    删除容器视图
    参数:request: HttpRequest对象container: 容器名称
    返回:重定向到容器列表页面
    """
    # 1.获取token
    headers = {}
    headers["X-Auth-Token"] = request.session.get('token')
    # 2.定义删除容器的接口URL
    url = f"http://192.168.17.222:8080/v1/AUTH_0a1976918df0407da41ab01eca0b9974/{container}"
    # 3.发送删除请求
    requests.delete(url, headers=headers)
    # 4.删除成功后重定向回容器列表页面
    return redirect('/containers')

def log_action(user, action):
    """
    简单的访问日志记录功能
    参数:user: 用户名action: 操作描述
    """
    import os # 导入os模块，用于文件操作
    from datetime import datetime

    # 确保日志目录存在
    log_dir = os.path.join(os.path.dirname(__file__), 'logs')
    os.makedirs(log_dir, exist_ok=True)
    # 日志文件路径
    log_file = os.path.join(log_dir, 'access.log')
    # 获取当前时间戳
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    # 写入日志
    with open(log_file, 'a', encoding='utf-8') as f:
        f.write(f"[{timestamp}] {user}: {action}\n")
def view_logs(request):
    """
    查看访问日志视图
    参数:request: HttpRequest对象
    返回:渲染后的日志查看页面
    """
    import os
    from django.core.paginator import Paginator
    # 日志文件路径
    log_dir = os.path.join(os.path.dirname(__file__), 'logs')
    log_file = os.path.join(log_dir, 'access.log')
    logs = []
    if os.path.exists(log_file):
        try:
            with open(log_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                # 只显示最新的1000条记录，并反向显示（最新的在前）
                for line in reversed(lines[-1000:]):
                    if line.strip():
                        logs.append(line.strip())
        except Exception as e:
            logs = [f"读取日志失败: {str(e)}"]
    # 分页显示日志，每页50条
    paginator = Paginator(logs, 50)
    try:
        page_number = request.GET.get('page', 1)
    except:
        page_number = 1
    page = paginator.get_page(page_number)
    # 渲染日志查看页面
    return render(request, 'logs.html', {'logs': page})