
from django.shortcuts import render,HttpResponse,redirect
import requests
import json
from django.http import HttpRequest, JsonResponse
from django.core.paginator import Paginator
from django.http import StreamingHttpResponse
# Create your views here.
def index(request):
    return HttpResponse('hello world,王和平')

def home (request):
    return render(request,'home.html')

def login_check(request: HttpRequest):
    # if request.method == 'POST':
    #     u = request.POST.get('u')
    #     p = request.POST.get('p')
    #     if u == 'admin' and p == '123456':
    #         return render(request,'welcome.html',{'u':u})
    # return render(request,'home.html')
    request.method == "POST"
    username = request.POST.get("u")
    password = request.POST.get("p")
    code = get_token(username, password)
    print(code.status_code)
    if code.status_code == 201:
        # 如果验证成功，将token保存在session中
        # 切记在python manage.py runserver运行项目前，先python manage.py migrate创建session表
        request.session['user'] = username
        request.session['token'] = code.headers.get("X-Subject-Token")
        return redirect('/containers')
        # return HttpResponse('登录成功')
    else:
        error_msg ="用户名或密码不正确，请重新登录"
        return render(request,"home.html",{
        'login_error_msg':error_msg,
    })
def get_token(username, password):
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
    url = "http://192.168.17.222:5000/v3/auth/tokens" #调用OpenStack auth接口，接口地址为http://ip:5000/v3/auth/tokens
    code = requests.post(url, data=json.dumps(data)) #json.dumps 用于将 Python 对象编码成 JSON 字符串
    return code
#读取容器
def containers(request: HttpRequest):
    headers = {}
    headers['X-Auth-Token'] = request.session['token']
    url2 = "http://192.168.17.222:8080/v1/AUTH_0a1976918df0407da41ab01eca0b9974?format=json"#http://{ip}:8080/v1/{account}
    resp1 = requests.get(url2, headers=headers) #把token放在get头中
    print(resp1)
    resp2 = resp1.json()
    print(resp2)
    pages = Paginator(resp2, 7)
    try:
        page_number = request.GET['page']
    except:
        page_number = 1
    page = pages.get_page(page_number)
    print(page)
    return render(request, 'containers.html', {'resp1': page})

#进入容器读取对象
def objects(request, data2):
    # data = {
    #     "auth": {
    #         "identity": {
    #             "methods": [
    #                 "password"
    #             ],
    #             "password": {
    #                 "user": {
    #                     "domain": {
    #                         "name": "default"
    #                     },
    #                     "name": "admin",
    #                     "password": "1234"
    #                 }
    #             }
    #         },
    #         "scope": {
    #             "project": {
    #                 "domain": {
    #                     "name": "default"
    #                 },
    #                 "name": "admin"
    #             }
    #         }
    #     }
    # }
    # 进入容器
    # url = "http://192.168.17.222:5000/v3/auth/tokens"
    # code = requests.post(url, data=json.dumps(data))
    # .headers.get("X-Subject-Token")
    # headers = {}
    # 
    headers = {}
    headers["X-Auth-Token"] = request.session.get('token')
    # print(data2)
    url4 = "http://192.168.17.222:8080/v1/AUTH_0a1976918df0407da41ab01eca0b9974/" + str(data2)+"?format=json"
    resp3 = requests.get(url4, headers=headers)
    # print(resp3.text)
    resp4 = resp3.json()
    # print(resp4)
    pages = Paginator(resp4, 6)
    try:
        page_number = request.GET['page']
    except:
        page_number = 1

    page = pages.get_page(page_number)
    return render(request, 'objects.html', {'resp1': page, 'data2': data2}) 
def addContainer(request, data):
    headers = {}
    headers["X-Auth-Token"] = request.session.get('token')
    url="http://192.168.17.222:8080/v1/AUTH_0a1976918df0407da41ab01eca0b9974/" + str(data)
    requests.put(url, headers=headers)
    return redirect('/containers')

def logout(request):
    # if 'user' in request.session:
    #     del request.session['user']
    # if 'token' in request.session:
    #     del request.session['token']
    request.session.flush()
    return redirect('/home')
def download(request:HttpRequest, container, object):#container当前容器，object选中的对象名
    url = f"http://192.168.17.222:8080/v1/AUTH_0a1976918df0407da41ab01eca0b9974/{container}/{object}" 
    headers = {}
    headers["X-Auth-Token"] = request.session.get('token')
    datas = requests.get(url, headers=headers)
    response = StreamingHttpResponse(datas)
    response['Content-Type'] = "application/text"
    response['Content-Disposition'] = 'attachment;filename=' + object.encode('utf-8').decode('ISO-8859-1')
    return response

def upload(request:HttpRequest,object):
    if request.method != 'POST':
        return HttpResponse('请使用POST方法上传文件')

    #1.获取token
    headers = {}
    headers["X-Auth-Token"] = request.session.get('token')

    #2.获取前端传来的文件
    file_obj = request.FILES.get('filename')
    if not file_obj:
        return HttpResponse('请选择要上传的文件')

    #3.读取文件内容（二进制模式）
    file_content = file_obj.read()

    #4.设置正确的Content-Type
    if file_obj.content_type:
        headers['Content-Type'] = file_obj.content_type

    #5.定义接口
    url = f"http://192.168.17.222:8080/v1/AUTH_0a1976918df0407da41ab01eca0b9974/{object}/{file_obj.name}"

    #6.发送请求到接口地址
    try:
        response = requests.put(url, headers=headers, data=file_content)
        if response.status_code == 201:
            return HttpResponse('上传成功')
        else:
            return HttpResponse(f'上传失败，状态码: {response.status_code}')
    except Exception as e:
        return HttpResponse(f'上传失败: {str(e)}')

def delete(request:HttpRequest, container, object):
    #1.获取token
    headers = {}
    headers["X-Auth-Token"] = request.session.get('token')
    #2.定义接口
    url = f"http://192.168.17.222:8080/v1/AUTH_0a1976918df0407da41ab01eca0b9974/{container}/{object}"
    #3.发送请求到接口地址
    requests.delete(url, headers=headers)
    return redirect('/objects/'+container)
def view_file(request: HttpRequest, container, object, content_type):
    #1.获取token
    headers = {}
    headers["X-Auth-Token"] = request.session.get('token')

    #2.定义接口URL
    url = f"http://192.168.17.222:8080/v1/AUTH_0a1976918df0407da41ab01eca0b9974/{container}/{object}"

    #3.发送请求获取文件内容
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()

        #4.处理文件内容编码
        file_content = ""
        is_image = False

        # 检查是否为图片文件
        if content_type.startswith('image/'):
            # 图片文件直接显示，不读取文本内容
            file_content = ""
            is_image = True
        elif content_type.startswith('text/') or 'text' in content_type:
            # 文本文件，尝试自动检测编码
            try:
                # 尝试UTF-8编码
                file_content = response.content.decode('utf-8')
            except UnicodeDecodeError:
                try:
                    # 尝试GBK编码
                    file_content = response.content.decode('gbk')
                except UnicodeDecodeError:
                    try:
                        # 尝试GB2312编码
                        file_content = response.content.decode('gb2312')
                    except UnicodeDecodeError:
                        # 都失败则使用替换模式
                        file_content = response.content.decode('utf-8', errors='replace')
        else:
            # 非文本非图片文件，提示下载
            try:
                file_content = response.content.decode('utf-8', errors='replace')
            except:
                file_content = "二进制文件，无法直接查看内容，请下载后查看"

        #5.准备上下文数据
        context = {
            'file_name': object,
            'content_type': content_type,
            'file_content': file_content,
            'container': container,
            'data2': container,  # 用于返回按钮
            'is_image': is_image
        }

        #6.渲染查看文件页面
        return render(request, 'view_file.html', context)
    except Exception as e:
        return HttpResponse(f'查看文件失败: {str(e)}')
def check_container_objects(request, container):
    # 检查容器中是否有对象
    headers = {}
    headers["X-Auth-Token"] = request.session.get('token')
    url = f"http://192.168.17.222:8080/v1/AUTH_0a1976918df0407da41ab01eca0b9974/{container}?format=json"

    try:
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
    #1.获取token
    headers = {}
    headers["X-Auth-Token"] = request.session.get('token')
    #2.定义接口
    url = f"http://192.168.17.222:8080/v1/AUTH_0a1976918df0407da41ab01eca0b9974/{container}"
    #3.发送请求到接口地址
    requests.delete(url, headers=headers)
    #4.删除成功后重定向回容器列表页面
    return redirect('/containers')