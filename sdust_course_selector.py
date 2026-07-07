#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
山东科技大学教务系统自动选课脚本
基于 HAR 抓包分析

功能：
  1. 登录教务系统（密码登录 / Cookie登录）
  2. 查询选课轮次
  3. 进入选课中心
  4. 查询公选课 / 落实实践课列表
  5. 自动选课 / 退课
  6. 查询已选课程

使用方法:
  python sdust_course_selector.py
"""

import requests
import base64
import json
import time
import sys
import os
import re
from urllib.parse import urlencode


class SDUSTCourseSelector:
    """山东科技大学教务系统选课工具"""

    BASE_URL = "https://jwglxt.sdust.edu.cn"

    # DataTables 公选课查询列定义
    GGXXK_COLUMNS = [
        'kch', 'kcmc', 'ktmc', 'xf', 'skls', 'sksj', 'skdd',
        'xqmc', 'xkrs', 'syrs', 'skfsmc', 'ctsm', 'szkcflmc', 'bz', 'czOper'
    ]

    # DataTables 落实实践课查询列定义
    LDSJK_COLUMNS = GGXXK_COLUMNS  # 结构相同

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                          'AppleWebKit/537.36 (KHTML, like Gecko) '
                          'Chrome/150.0.0.0 Safari/537.36',
            'Accept': 'text/javascript, application/javascript, application/'
                      'ecmascript, application/x-ecmascript, */*; q=0.01',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
            'X-Requested-With': 'XMLHttpRequest',
            'Origin': self.BASE_URL,
        })
        self.student_id = None
        self.logged_in = False
        self.current_zbid = None  # 当前选课轮次ID
        self.config_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.json')

    def _load_config(self):
        """从配置文件读取账号密码"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                return config.get('username', ''), config.get('password', '')
            except Exception:
                pass
        return '', ''

    def _save_config(self, username, password):
        """保存账号密码到配置文件"""
        try:
            config = {'username': username, 'password': password}
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, ensure_ascii=False, indent=2)
            print(f"[配置] 已保存到: {self.config_file}")
            return True
        except Exception as e:
            print(f"[配置] 保存失败: {e}")
            return False

    def auto_login(self):
        """尝试从配置文件自动登录"""
        username, password = self._load_config()
        if username and password:
            print(f"[配置] 检测到保存的账号: {username}")
            choice = input("是否使用保存的账号登录? (y/n, 默认y): ").strip().lower()
            if choice in ('', 'y', 'yes'):
                return self.login(username, password)
        return False

    # ==================== 登录模块 ====================

    @staticmethod
    def _encode_inp(input_str):
        """
        金智教务系统 encodeInp 函数 (标准Base64编码)
        对应 conwork.js 中的 encodeInp 函数
        """
        return base64.b64encode(input_str.encode('utf-8')).decode('utf-8')

    def _fetch_scode_sxh(self):
        """
        从登录页面获取动态生成的 scode 和 sxh 值

        山东科技大学教务系统的登录页面每次加载时，会在HTML中
        嵌入不同的 scode 和 sxh 值，用于加密 encoded 参数。
        这是服务器端的反自动化措施。
        """
        resp = self.session.get(f"{self.BASE_URL}/jsxsd/", timeout=15)
        html = resp.text

        scode_match = re.search(r'scode\s*=\s*["\']([^"\']+)["\']', html)
        sxh_match = re.search(r'sxh\s*=\s*["\']([^"\']+)["\']', html)

        scode = scode_match.group(1) if scode_match else None
        sxh = sxh_match.group(1) if sxh_match else None

        return scode, sxh

    def _encrypt_login(self, username, password, scode, sxh):
        """
        山东科技大学教务系统登录加密算法

        加密流程 (逆向自登录页面 submitForm1 函数):
        1. account = base64(用户名)        -- encodeInp = 标准 Base64
        2. passwd = base64(密码)
        3. codeDog = base64(' ')           -- 设备序列号，普通用户为空格
        4. code = account + "%%%" + passwd + "%%%" + codeDog
        5. 用 scode 和 sxh 对 code 进行混淆插入:
           - 对 code 的前55个字符，每个字符后面插入 scode 的前 n 个字符
             (n = sxh 的第 i 位数字)
           - 55之后的字符直接拼接
        """
        account = self._encode_inp(username)
        passwd = self._encode_inp(password)
        code_dog = self._encode_inp(' ')  # 空格，因为普通用户无加密狗

        code = account + "%%%" + passwd + "%%%" + code_dog

        encoded = ""
        for i in range(len(code)):
            if i < 55:
                n = int(sxh[i])
                encoded += code[i] + scode[:n]
                scode = scode[n:]
            else:
                encoded += code[i:]
                break

        return encoded

    def login(self, username, password):
        """
        方式一：密码登录 (已破解加密算法)

        加密流程:
        1. 从登录页面获取动态 scode/sxh (每次加载都不同)
        2. base64编码用户名、密码、设备序列号
        3. 用 scode/sxh 混淆插入生成 encoded
        4. POST 提交登录
        """
        print(f"[登录] 正在使用账号 {username} 登录...")

        # 步骤1: 访问登录页获取动态 scode/sxh 和初始 Cookie
        print("[登录] 获取动态加密参数...")
        scode, sxh = self._fetch_scode_sxh()
        if not scode or not sxh:
            print("[登录] 获取加密参数失败，请使用Cookie方式登录 (选项 2)")
            return False

        print(f"[登录] scode: {scode[:20]}... (长度{len(scode)})")
        print(f"[登录] sxh: {sxh[:20]}... (长度{len(sxh)})")

        # 步骤2: 加密
        encoded = self._encrypt_login(username, password, scode, sxh)
        print(f"[登录] 加密完成: {encoded[:30]}... (长度{len(encoded)})")

        # 步骤3: 提交登录
        login_data = {
            'loginMethod': 'LoginToXk',
            'userlanguage': '0',
            'userAccount': username,
            'userPassword': '',  # 密码不直接传输，放在encoded中
            'encoded': encoded,
        }

        # 登录请求不需要 X-Requested-With
        headers = {'X-Requested-With': '', 'Referer': f'{self.BASE_URL}/jsxsd/'}
        resp = self.session.post(
            f"{self.BASE_URL}/jsxsd/xk/LoginToXk",
            data=login_data,
            headers=headers,
            allow_redirects=False,
            timeout=15
        )

        # 金智系统登录成功返回 302 跳转
        if resp.status_code == 302:
            location = resp.headers.get('Location', '')
            if 'xsrkxz' in location or 'framework' in location:
                self.logged_in = True
                self.student_id = username
                print(f"[登录] 登录成功! 学号: {username}")
                return True

        # 检查是否有错误信息
        if resp.status_code == 200:
            text = resp.text
            if '用户名或密码' in text or '密码错误' in text:
                print("[登录] 登录失败: 用户名或密码错误")
                return False
            if '验证码' in text:
                print("[登录] 登录失败: 需要验证码，请使用Cookie方式登录")
                return False

        print(f"[登录] 登录失败 (HTTP {resp.status_code})")
        return False

    def login_with_cookies(self, cookie_str):
        """
        方式二：Cookie 登录
        从浏览器复制 Cookie 字符串直接登录

        使用方法:
          1. 在浏览器登录教务系统
          2. F12 -> Network -> 任意请求 -> Request Headers -> Cookie
          3. 复制完整的 Cookie 值
        """
        print("[登录] 使用Cookie登录...")

        # 设置Cookie
        self.session.headers.update({'Cookie': cookie_str})

        # 验证登录状态: 查询选课轮次
        try:
            resp = self.session.get(
                f"{self.BASE_URL}/jsxsd/xsxk/xklc_list_data?xkmc=",
                timeout=10
            )
            data = resp.json()
            if 'code' in data and data['code'] == '0':
                self.logged_in = True
                # 从已选课程中获取学号
                try:
                    resp2 = self.session.get(
                        f"{self.BASE_URL}/jsxsd/xsxkjg/getTkrzList",
                        timeout=10
                    )
                    d2 = resp2.json()
                    self.student_id = d2.get('xh', '未知')
                except Exception:
                    self.student_id = '未知'
                print(f"[登录] Cookie登录成功! 学号: {self.student_id}")
                return True
            else:
                print("[登录] Cookie可能已过期，请重新获取")
                return False
        except Exception as e:
            print(f"[登录] Cookie验证失败: {e}")
            return False

    def ensure_login(self):
        """检查是否已登录"""
        if not self.logged_in:
            print("[错误] 请先登录!")
            return False
        return True

    # ==================== 选课轮次模块 ====================

    def get_course_rounds(self):
        """获取选课轮次列表"""
        if not self.ensure_login():
            return []

        print("\n[选课轮次] 正在查询...")
        resp = self.session.get(
            f"{self.BASE_URL}/jsxsd/xsxk/xklc_list_data?xkmc=",
            timeout=15
        )
        data = resp.json()

        rounds = data.get('data', [])
        if not rounds:
            print("[选课轮次] 未找到选课轮次")
            return []

        print(f"[选课轮次] 共找到 {len(rounds)} 个轮次:\n")
        print(f"{'序号':<4} {'选课名称':<40} {'选课时间':<40} {'退课':<8} {'状态'}")
        print("-" * 100)
        for i, r in enumerate(rounds):
            mc = r.get('xklc_mc', '未命名')
            xksj = r.get('xksj', '')
            txkzmc = r.get('txkzmc', '')
            xkzt = r.get('xkzt', '')
            xkzt_str = '进行中' if xkzt == '1' else '未开始/已结束'
            print(f"{i+1:<4} {mc:<40} {xksj:<40} {txkzmc:<8} {xkzt_str}")

        return rounds

    # ==================== 进入选课中心 ====================

    def enter_selection(self, jx0502zbid):
        """
        进入选课中心
        参数: jx0502zbid - 选课轮次ID
        """
        if not self.ensure_login():
            return False

        print(f"\n[选课中心] 正在进入轮次 {jx0502zbid}...")

        # 步骤1: 退出之前的选课会话
        self.session.get(
            f"{self.BASE_URL}/jsxsd/xsxk/xsxk_exit",
            params={'jx0404id': '1'},
            timeout=10
        )

        # 步骤2: 加载选课轮次列表页
        self.session.get(
            f"{self.BASE_URL}/jsxsd/xsxk/xklc_list",
            params={'isallsc': '1'},
            timeout=10
        )

        # 步骤3: 进入选课中心
        resp = self.session.get(
            f"{self.BASE_URL}/jsxsd/xsxk/newXsxkzx",
            params={'jx0502zbid': jx0502zbid, 'isallsc': '1'},
            timeout=10
        )
        if resp.status_code != 200:
            print(f"[选课中心] 进入失败 (HTTP {resp.status_code})")
            return False

        # 步骤4: 查询免听申请
        self.session.post(f"{self.BASE_URL}/jsxsd/xsxk/mzlist.do", timeout=10)

        # 步骤5: 加载选课表格/底部
        self.session.get(f"{self.BASE_URL}/jsxsd/xsxk/selectTable", timeout=10)
        self.session.get(
            f"{self.BASE_URL}/jsxsd/xsxk/selectNum",
            params={'jx0502zbid': jx0502zbid, 'isallsc': '1'},
            timeout=10
        )
        self.session.get(
            f"{self.BASE_URL}/jsxsd/xsxk/selectBottom",
            params={'jx0502zbid': jx0502zbid, 'sfylxkstr': ''},
            timeout=10
        )

        print("[选课中心] 进入成功!")
        self.current_zbid = jx0502zbid

        # 自动显示该轮次的课程列表
        self._auto_show_courses(jx0502zbid)
        return True

    def _auto_show_courses(self, jx0502zbid):
        """根据轮次类型自动查询并显示课程列表"""
        rounds = self.get_course_rounds()
        current_round = None
        for r in rounds:
            if r.get('jx0502zbid') == jx0502zbid:
                current_round = r
                break

        if not current_round:
            return

        round_name = current_round.get('xklc_mc', '')
        print(f"\n[选课中心] 当前轮次: {round_name}")

        # 根据轮次名称判断课程类型，查询对应接口
        if '公选课' in round_name:
            courses, total = self.get_public_courses(page=1, page_size=100)
            self.display_courses(courses)
        elif '体育' in round_name:
            # 体育课轮次包含必修课和实践课
            print("\n--- 必修课程 ---")
            courses1, total1 = self.get_required_courses(page=1, page_size=100)
            self.display_courses(courses1)
            print("\n--- 实践课程 ---")
            courses2, total2 = self.get_practice_courses(page=1, page_size=100)
            self.display_courses(courses2)
        elif '实践' in round_name or '劳动' in round_name:
            courses, total = self.get_practice_courses(page=1, page_size=100)
            self.display_courses(courses)
        elif '专业选修' in round_name or '外语' in round_name or '小语种' in round_name or '俄语' in round_name or '日语' in round_name:
            # 专业选修课和外语类用限选课接口
            courses, total = self.get_limited_courses(page=1, page_size=100)
            self.display_courses(courses)
        else:
            # 默认查询所有类型
            print("\n--- 公选课 ---")
            courses, total = self.get_public_courses(page=1, page_size=100)
            self.display_courses(courses)
            print("\n--- 必修课 ---")
            courses, total = self.get_required_courses(page=1, page_size=100)
            self.display_courses(courses)
            print("\n--- 限选课 ---")
            courses, total = self.get_limited_courses(page=1, page_size=100)
            self.display_courses(courses)

    # ==================== 课程查询模块 ====================

    def _query_course_list(self, endpoint, columns, page=1, page_size=10,
                           szjylb='', sfym='false'):
        """
        通用课程列表查询 (DataTables协议)

        参数:
          endpoint: 查询接口路径 (如 xsxkGgxxkxk 或 xsxkLdsjkxk)
          columns: 列定义列表
          page: 页码 (从1开始)
          page_size: 每页条数
          szjylb: 实践类别筛选
          sfym: 是否查询已选
        """
        start = (page - 1) * page_size

        # URL参数
        params = {
            'kcxx': '', 'skls': '', 'skxq': '', 'skjc': '',
            'endJc': '', 'sfym': sfym, 'sfct': 'true',
            'szjylb': szjylb, 'sfxx': 'true', 'skfs': '', 'kctype': '',
        }

        # POST body (DataTables格式)
        data = {
            'sEcho': str(page),
            'iColumns': str(len(columns)),
            'sColumns': '',
            'iDisplayStart': str(start),
            'iDisplayLength': str(page_size),
        }
        for i, col in enumerate(columns):
            data[f'mDataProp_{i}'] = col

        resp = self.session.post(
            f"{self.BASE_URL}/jsxsd/xsxkkc/{endpoint}",
            params=params,
            data=data,
            timeout=15
        )
        try:
            return resp.json()
        except Exception:
            print(f"[错误] 接口返回非JSON数据 (HTTP {resp.status_code})")
            print(f"  响应内容前200字: {resp.text[:200]}")
            if '登录' in resp.text or 'login' in resp.text.lower():
                print("  -> 登录可能已过期，请重新登录")
            else:
                print("  -> 可能未进入选课中心，请先执行选项4进入选课中心")
            return {'aaData': [], 'iTotalRecords': 0}

    def get_public_courses(self, page=1, page_size=100, szjylb=''):
        """
        查询公选课列表
        返回课程列表和总数
        """
        if not self.ensure_login():
            return [], 0

        # 自动进入选课中心 (如果尚未进入)
        if not self.current_zbid:
            rounds = self.get_course_rounds()
            if not rounds:
                print("[公选课] 无法获取选课轮次")
                return [], 0
            # 默认选第一个进行中的轮次
            self.enter_selection(rounds[0]['jx0502zbid'])

        # 先加载公选课页面
        self.session.get(f"{self.BASE_URL}/jsxsd/xsxkkc/getGgxxk", timeout=10)

        print(f"\n[公选课] 查询第 {page} 页...")
        result = self._query_course_list(
            'xsxkGgxxkxk', self.GGXXK_COLUMNS,
            page=page, page_size=page_size, szjylb=szjylb
        )

        courses = result.get('aaData', [])
        total = int(result.get('iTotalRecords', 0))

        print(f"[公选课] 共 {total} 门课程, 当前页 {len(courses)} 门")
        return courses, total

    def get_practice_courses(self, page=1, page_size=100, szjylb=''):
        """查询落实实践课列表"""
        if not self.ensure_login():
            return [], 0

        # 自动进入选课中心 (如果尚未进入)
        if not self.current_zbid:
            rounds = self.get_course_rounds()
            if not rounds:
                print("[落实实践课] 无法获取选课轮次")
                return [], 0
            self.enter_selection(rounds[0]['jx0502zbid'])

        # 先加载实践课页面
        self.session.get(f"{self.BASE_URL}/jsxsd/xsxkkc/comeInLdsjkxk", timeout=10)

        print(f"\n[落实实践课] 查询第 {page} 页...")
        result = self._query_course_list(
            'xsxkLdsjkxk', self.LDSJK_COLUMNS,
            page=page, page_size=page_size, szjylb=szjylb
        )

        courses = result.get('aaData', [])
        total = int(result.get('iTotalRecords', 0))
        print(f"[落实实践课] 共 {total} 门课程, 当前页 {len(courses)} 门")
        return courses, total

    def get_required_courses(self, page=1, page_size=100, szjylb=''):
        """查询必修课列表"""
        if not self.ensure_login():
            return [], 0

        if not self.current_zbid:
            rounds = self.get_course_rounds()
            if not rounds:
                return [], 0
            self.enter_selection(rounds[0]['jx0502zbid'])

        # 加载必修课页面
        self.session.get(f"{self.BASE_URL}/jsxsd/xsxkkc/comeInBxxk", timeout=10)

        print(f"\n[必修课] 查询第 {page} 页...")
        result = self._query_course_list(
            'xsxkBxxk', self.GGXXK_COLUMNS,
            page=page, page_size=page_size, szjylb=szjylb
        )

        courses = result.get('aaData', [])
        total = int(result.get('iTotalRecords', 0))
        print(f"[必修课] 共 {total} 门课程, 当前页 {len(courses)} 门")
        return courses, total

    def get_limited_courses(self, page=1, page_size=100, szjylb=''):
        """查询限选课/专业选修课列表"""
        if not self.ensure_login():
            return [], 0

        if not self.current_zbid:
            rounds = self.get_course_rounds()
            if not rounds:
                return [], 0
            self.enter_selection(rounds[0]['jx0502zbid'])

        # 加载限选课页面
        self.session.get(f"{self.BASE_URL}/jsxsd/xsxkkc/comeInXxxk", timeout=10)

        print(f"\n[限选课] 查询第 {page} 页...")
        result = self._query_course_list(
            'xsxkXxxk', self.GGXXK_COLUMNS,
            page=page, page_size=page_size, szjylb=szjylb
        )

        courses = result.get('aaData', [])
        total = int(result.get('iTotalRecords', 0))
        print(f"[限选课] 共 {total} 门课程, 当前页 {len(courses)} 门")
        return courses, total

    def display_courses(self, courses, show_all=False):
        """打印课程列表"""
        if not courses:
            print("  (无课程)")
            return

        print(f"\n{'序号':<4} {'课程名称':<22} {'课头名':<10} {'学分':<5} {'学时':<5} {'上课时间':<24} {'地点':<10} {'老师':<6} {'已选/容量':<10} {'类别':<6} {'jx0404id'}")
        print("-" * 140)
        for i, c in enumerate(courses):
            kcmc = (c.get('kcmc') or '')[:20]
            ktmc = (c.get('ktmc') or '')[:8]
            xf = c.get('xf') or ''
            zxs = c.get('zxs') or ''
            sksj = (c.get('sksj') or '').replace('<br>', ' ')[:22]
            skdd = (c.get('skdd') or '')[:8]
            skls = (c.get('skls') or '')[:6]
            xkrs = c.get('xkrs') or ''
            pkrs = c.get('pkrs') or ''
            syrs = c.get('syrs') or ''
            if pkrs:
                capacity = f"{xkrs}/{pkrs}"
            elif xkrs and syrs:
                try:
                    capacity = f"{xkrs}/{int(xkrs)+int(syrs)}"
                except ValueError:
                    capacity = ''
            else:
                capacity = ''
            flmc = (c.get('szkcflmc') or '')[:4]
            jxid = c.get('jx0404id') or ''
            print(f"{i+1:<4} {kcmc:<22} {ktmc:<10} {xf:<5} {zxs:<5} {sksj:<24} {skdd:<10} {skls:<6} {capacity:<10} {flmc:<6} {jxid}")

    # ==================== 时间冲突检测模块 ====================

    @staticmethod
    def _parse_course_time(time_str):
        """
        解析课程时间字符串
        返回时间段列表,每个元素为字典:
        {'week_start': int, 'week_end': int, 'weekday': int, 'section_start': int, 'section_end': int}

        支持格式:
          "3-12周 星期日 9-10"
          "9-16周 星期二 9-10  9-16周 星期四 7-8"
        """
        if not time_str:
            return []

        # 清理HTML标签
        time_str = time_str.replace('<br>', ' ').replace('<br/>', ' ')

        weekday_map = {
            '星期一': 1, '星期二': 2, '星期三': 3, '星期四': 4,
            '星期五': 5, '星期六': 6, '星期日': 7,
            '周一': 1, '周二': 2, '周三': 3, '周四': 4,
            '周五': 5, '周六': 6, '周日': 7,
        }

        import re
        # 匹配 "X-Y周 星期Z A-B" 模式
        pattern = r'(\d+)-(\d+)周\s+(星期[一二三四五六日]|周[一二三四五六日])\s+(\d+)-(\d+)'
        matches = re.findall(pattern, time_str)

        slots = []
        for m in matches:
            week_start = int(m[0])
            week_end = int(m[1])
            weekday = weekday_map.get(m[2], 0)
            section_start = int(m[3])
            section_end = int(m[4])
            if weekday > 0:
                slots.append({
                    'week_start': week_start,
                    'week_end': week_end,
                    'weekday': weekday,
                    'section_start': section_start,
                    'section_end': section_end,
                })

        return slots

    @staticmethod
    def _time_slots_conflict(slot1, slot2):
        """检查两个时间段是否冲突"""
        # 周次不重叠 -> 不冲突
        if slot1['week_end'] < slot2['week_start'] or slot2['week_end'] < slot1['week_start']:
            return False
        # 不是同一天 -> 不冲突
        if slot1['weekday'] != slot2['weekday']:
            return False
        # 节次不重叠 -> 不冲突
        if slot1['section_end'] < slot2['section_start'] or slot2['section_end'] < slot1['section_start']:
            return False
        return True

    def _check_course_conflict(self, course, selected_courses):
        """
        检查课程是否与已选课程时间冲突
        返回 (是否冲突, 冲突课程名)
        """
        course_slots = self._parse_course_time(course.get('sksj', ''))
        if not course_slots:
            return False, None

        for sc in selected_courses:
            sc_slots = self._parse_course_time(sc.get('sksj', ''))
            for s1 in course_slots:
                for s2 in sc_slots:
                    if self._time_slots_conflict(s1, s2):
                        return True, sc.get('kcmc', '') or sc.get('ktmc', '')

        return False, None

    def _is_course_full(self, course):
        """检查课程是否已满员"""
        pkrs = course.get('pkrs', '')
        xkrs = course.get('xkrs', '')
        syrs = course.get('syrs', '')

        # 如果 pkrs 和 xkrs 都有值,比较是否相等
        if pkrs and xkrs:
            try:
                if int(pkrs) <= int(xkrs):
                    return True
            except ValueError:
                pass

        # 如果 syrs 存在且 <= 0
        if syrs:
            try:
                if int(syrs) <= 0:
                    return True
            except ValueError:
                pass

        return False

    # ==================== 选课/退课模块 ====================

    def _get_oper_endpoint(self):
        """根据当前轮次类型获取对应的选课操作接口"""
        # 默认公选课操作接口
        endpoint = 'ggxxkxkOper'

        if not self.current_zbid:
            return endpoint

        # 查询轮次名称
        try:
            resp = self.session.get(
                f"{self.BASE_URL}/jsxsd/xsxk/xklc_list_data?xkmc=",
                timeout=10
            )
            rounds = resp.json().get('data', [])
            for r in rounds:
                if r.get('jx0502zbid') == self.current_zbid:
                    name = r.get('xklc_mc', '')
                    if '公选课' in name:
                        endpoint = 'ggxxkxkOper'
                    elif '专业选修' in name or '外语' in name or '小语种' in name or '俄语' in name or '日语' in name:
                        endpoint = 'xxxkOper'
                    elif '体育' in name or '必修' in name:
                        endpoint = 'bxxkOper'
                    elif '实践' in name or '劳动' in name:
                        endpoint = 'ldsjkOper'
                    break
        except Exception:
            pass

        return endpoint

    def select_course(self, kcid, jx0404id):
        """
        选课操作
        参数:
          kcid: 课程ID
          jx0404id: 教学班ID
        """
        if not self.ensure_login():
            return False

        endpoint = self._get_oper_endpoint()
        print(f"\n[选课] 正在选课: kcid={kcid}, jx0404id={jx0404id}")
        print(f"[选课] 使用操作接口: {endpoint}")

        params = {
            'kcid': kcid,
            'cfbs': 'null',
            'jx0404id': jx0404id,
            'xkzy': '',
            'trjf': '',
            'sfsyjc': '',
        }
        resp = self.session.get(
            f"{self.BASE_URL}/jsxsd/xsxkkc/{endpoint}",
            params=params,
            timeout=15
        )
        result = resp.json()

        success = result.get('success', False)
        message = result.get('message', '')
        if success:
            print(f"[选课] 选课成功! {message}")
        else:
            print(f"[选课] 选课失败: {message}")
        return success

    def select_course_by_keyword(self, keyword, course_type='public'):
        """
        按关键词智能查询选课

        功能:
          1. 关键词匹配课程名称/课头名/课程号
          2. 自动获取已选课程,检测时间冲突
          3. 自动过滤人数已满的课程
          4. 显示过滤后的可选课程,让用户选择

        参数:
          keyword: 课程关键词 (如 "智能电网" 或 "临班314")
          course_type: 'public' 公选课 / 'practice' 实践课 / 'required' 必修课 / 'limited' 限选课
        """
        if not self.ensure_login():
            return False

        print(f"\n[智能查询] 关键词: '{keyword}', 类型: {course_type}")

        # 步骤1: 查询课程列表
        if course_type == 'public':
            courses, total = self.get_public_courses(page=1, page_size=200)
        elif course_type == 'practice':
            courses, total = self.get_practice_courses(page=1, page_size=200)
        elif course_type == 'required':
            courses, total = self.get_required_courses(page=1, page_size=200)
        elif course_type == 'limited':
            courses, total = self.get_limited_courses(page=1, page_size=200)
        else:
            courses, total = self.get_public_courses(page=1, page_size=200)

        # 多页查询
        page = 2
        while len(courses) < total:
            if course_type == 'public':
                cs, _ = self.get_public_courses(page=page, page_size=200)
            elif course_type == 'practice':
                cs, _ = self.get_practice_courses(page=page, page_size=200)
            elif course_type == 'required':
                cs, _ = self.get_required_courses(page=page, page_size=200)
            elif course_type == 'limited':
                cs, _ = self.get_limited_courses(page=page, page_size=200)
            else:
                cs, _ = self.get_public_courses(page=page, page_size=200)
            if not cs:
                break
            courses.extend(cs)
            page += 1

        print(f"[智能查询] 共查询到 {len(courses)} 门课程")

        # 步骤2: 关键词匹配 (课程名/课头名/课程号/老师名/类别)
        matched = []
        for c in courses:
            kch = c.get('kch') or ''
            ktmc = c.get('ktmc') or ''
            kcmc = c.get('kcmc') or ''
            skls = c.get('skls') or ''
            flmc = c.get('szkcflmc') or ''  # 课程类别 (如 人文/创新创业)
            if keyword.lower() in kch.lower() or \
               keyword.lower() in ktmc.lower() or \
               keyword.lower() in kcmc.lower() or \
               keyword.lower() in skls.lower() or \
               keyword.lower() in flmc.lower():
                matched.append(c)

        if not matched:
            print(f"[智能查询] 未找到匹配 '{keyword}' 的课程")
            return False

        print(f"[智能查询] 关键词匹配到 {len(matched)} 门课程")

        # 步骤3: 获取已选课程(用于冲突检测)
        print("[智能查询] 获取已选课程进行冲突检测...")
        try:
            resp = self.session.get(
                f"{self.BASE_URL}/jsxsd/xsxkjg/getTkrzList",
                timeout=10
            )
            selected = resp.json().get('data', [])
        except Exception:
            selected = []
        print(f"[智能查询] 已选课程 {len(selected)} 门")

        # 步骤4: 过滤:时间冲突 + 人数已满
        available = []      # 可选的
        conflict = []       # 时间冲突的
        full = []           # 已满员的

        for c in matched:
            # 检查是否已满
            if self._is_course_full(c):
                full.append(c)
                continue

            # 检查时间冲突
            is_conflict, conflict_with = self._check_course_conflict(c, selected)
            if is_conflict:
                c['_conflict_with'] = conflict_with
                conflict.append(c)
                continue

            available.append(c)

        # 步骤5: 显示结果
        print(f"\n{'='*60}")
        print(f"[智能查询] 匹配结果统计:")
        print(f"  可选: {len(available)} 门")
        print(f"  时间冲突: {len(conflict)} 门")
        print(f"  名额已满: {len(full)} 门")
        print(f"{'='*60}")

        # 显示可选课程
        if available:
            print(f"\n>>> 可选课程 (无冲突、有余额):")
            self.display_courses(available)

            # 让用户选择
            choice = input("\n输入序号选择课程 (直接回车取消): ").strip()
            if choice:
                try:
                    idx = int(choice) - 1
                    if 0 <= idx < len(available):
                        c = available[idx]
                        jx0404id = c.get('jx0404id', '')
                        if jx0404id:
                            return self.select_course(kcid=jx0404id, jx0404id=jx0404id)
                    else:
                        print("[智能查询] 序号无效")
                except ValueError:
                    print("[智能查询] 输入无效")
        else:
            print("\n>>> 没有可选课程!")

        # 显示冲突课程(供参考)
        if conflict:
            print(f"\n>>> 以下课程与已选课程时间冲突:")
            for i, c in enumerate(conflict):
                kcmc = (c.get('kcmc') or '')[:20]
                ktmc = (c.get('ktmc') or '')[:10]
                sksj = (c.get('sksj') or '').replace('<br>', ' ')[:24]
                cf = c.get('_conflict_with', '')
                print(f"  {i+1}. {kcmc} {ktmc} | {sksj} | 冲突: {cf}")

        # 显示已满课程(供参考)
        if full:
            print(f"\n>>> 以下课程名额已满:")
            for i, c in enumerate(full):
                kcmc = (c.get('kcmc') or '')[:20]
                ktmc = (c.get('ktmc') or '')[:10]
                xkrs = c.get('xkrs', '')
                pkrs = c.get('pkrs', '')
                capacity = f"{xkrs}/{pkrs}" if pkrs else ''
                print(f"  {i+1}. {kcmc} {ktmc} | 已选/容量: {capacity}")

        return False

    def get_course_categories(self, course_type='public'):
        """
        获取当前轮次的所有课程类别
        返回类别列表 [(类别名, 可用课程数, 总课程数), ...]
        """
        if not self.ensure_login():
            return []

        # 查询所有课程
        if course_type == 'public':
            courses, total = self.get_public_courses(page=1, page_size=200)
        elif course_type == 'limited':
            courses, total = self.get_limited_courses(page=1, page_size=200)
        elif course_type == 'required':
            courses, total = self.get_required_courses(page=1, page_size=200)
        elif course_type == 'practice':
            courses, total = self.get_practice_courses(page=1, page_size=200)
        else:
            courses, total = self.get_public_courses(page=1, page_size=200)

        # 多页查询
        page = 2
        while len(courses) < total:
            if course_type == 'public':
                cs, _ = self.get_public_courses(page=page, page_size=200)
            elif course_type == 'limited':
                cs, _ = self.get_limited_courses(page=page, page_size=200)
            elif course_type == 'required':
                cs, _ = self.get_required_courses(page=page, page_size=200)
            elif course_type == 'practice':
                cs, _ = self.get_practice_courses(page=page, page_size=200)
            else:
                cs, _ = self.get_public_courses(page=page, page_size=200)
            if not cs:
                break
            courses.extend(cs)
            page += 1

        # 获取已选课程
        try:
            resp = self.session.get(f"{self.BASE_URL}/jsxsd/xsxkjg/getTkrzList", timeout=10)
            selected = resp.json().get('data', [])
        except Exception:
            selected = []

        # 统计每个类别
        from collections import defaultdict
        cat_stats = defaultdict(lambda: {'total': 0, 'available': 0})

        for c in courses:
            flmc = (c.get('szkcflmc') or '未分类').strip()
            cat_stats[flmc]['total'] += 1
            if not self._is_course_full(c):
                is_conflict, _ = self._check_course_conflict(c, selected)
                if not is_conflict:
                    cat_stats[flmc]['available'] += 1

        # 转换为列表并排序
        result = [(cat, info['available'], info['total'])
                  for cat, info in cat_stats.items()]
        result.sort(key=lambda x: -x[1])
        return result

    def _extract_categories_from_page(self):
        """
        从公选课页面提取 szjylb 类别下拉框选项
        返回 [(value, name), ...]
        """
        try:
            resp = self.session.get(f"{self.BASE_URL}/jsxsd/xsxkkc/getGgxxk", timeout=10)
            html = resp.text
            m = re.search(r'<select[^>]*id=["\']szjylb["\'][^>]*>(.*?)</select>', html, re.S | re.I)
            if not m:
                return []

            options = []
            for opt in re.finditer(r'<option[^>]*value=["\']([^"\']*)["\'][^>]*>(.*?)</option>', m.group(1), re.S | re.I):
                val = opt.group(1).strip()
                text = opt.group(2).strip()
                if val:  # 跳过"所有课程"
                    options.append((val, text))
            return options
        except Exception:
            return []

    def smart_auto_select(self, course_type='public', category=None):
        """
        智能自动选课 (支持 szjylb 细分类别)

        功能:
        1. 从页面提取细分类别，测试哪些在当前轮次有课程
        2. 用 szjylb 参数精确查询某类别课程
        3. 自动过滤已满和冲突课程
        4. 支持线上/线下筛选
        5. 自动选课（单门或全部可选）
        """
        if not self.ensure_login():
            return False

        print(f"\n[智能抢课] 正在分析课程...")

        # 获取已选课程(用于冲突检测)
        try:
            resp = self.session.get(f"{self.BASE_URL}/jsxsd/xsxkjg/getTkrzList", timeout=10)
            selected = resp.json().get('data', [])
        except Exception:
            selected = []
        print(f"[智能抢课] 已选课程 {len(selected)} 门")

        # 如果是公选课，从页面提取细分类别
        szjylb_value = None
        if course_type == 'public':
            print("[智能抢课] 正在获取课程类别...")
            categories = self._extract_categories_from_page()
            if categories:
                # 测试每个类别，找出有课程的
                valid_cats = []
                columns = ['kch', 'kcmc', 'ktmc', 'xf', 'skls', 'sksj', 'skdd', 'xqmc', 'xkrs', 'syrs', 'skfsmc', 'ctsm', 'szkcflmc', 'bz', 'czOper']
                data = {'sEcho': '1', 'iColumns': str(len(columns)), 'sColumns': '', 'iDisplayStart': '0', 'iDisplayLength': '1'}
                for i, col in enumerate(columns):
                    data[f'mDataProp_{i}'] = col

                for val, name in categories:
                    resp = self.session.post(
                        f"{self.BASE_URL}/jsxsd/xsxkkc/xsxkGgxxkxk",
                        params={'kcxx': '', 'skls': '', 'skxq': '', 'skjc': '', 'endJc': '', 'sfym': 'false', 'sfct': 'true', 'szjylb': val, 'sfxx': 'true', 'skfs': '', 'kctype': ''},
                        data=data, timeout=15
                    )
                    try:
                        result = resp.json()
                        total = result.get('iTotalRecords', 0)
                        if total > 0:
                            valid_cats.append((val, name, total))
                    except:
                        pass

                if valid_cats:
                    print(f"\n=== 当前轮次可选类别 ===")
                    print(f"{'序号':<4} {'类别':<20} {'课程数':<8}")
                    print("-" * 36)
                    for i, (val, name, total) in enumerate(valid_cats):
                        print(f"{i+1:<4} {name:<20} {total:<8}")

                    if category is None:
                        choice = input("\n输入类别序号 (或类别名, 回车取消): ").strip()
                        if not choice:
                            return False

                        # 尝试按序号匹配
                        try:
                            idx = int(choice) - 1
                            if 0 <= idx < len(valid_cats):
                                szjylb_value = valid_cats[idx][0]
                                category = valid_cats[idx][1]
                        except ValueError:
                            # 按名称匹配
                            for val, name, total in valid_cats:
                                if choice in name:
                                    szjylb_value = val
                                    category = name
                                    break
                    else:
                        # 按传入的 category 名称匹配
                        for val, name, total in valid_cats:
                            if category in name:
                                szjylb_value = val
                                category = name
                                break

                    if szjylb_value is None:
                        print(f"[智能抢课] 未找到类别 '{category}'")
                        return False

                    print(f"[智能抢课] 选择类别: {category} (szjylb={szjylb_value})")

        # 查询课程 (公选课带 szjylb 参数)
        if course_type == 'public' and szjylb_value:
            courses, total = self.get_public_courses(page=1, page_size=200, szjylb=szjylb_value)
        elif course_type == 'public':
            courses, total = self.get_public_courses(page=1, page_size=200)
        elif course_type == 'limited':
            courses, total = self.get_limited_courses(page=1, page_size=200)
        elif course_type == 'required':
            courses, total = self.get_required_courses(page=1, page_size=200)
        elif course_type == 'practice':
            courses, total = self.get_practice_courses(page=1, page_size=200)
        else:
            courses, total = self.get_public_courses(page=1, page_size=200)

        print(f"[智能抢课] 共查询到 {len(courses)} 门课程")

        # 过滤: 已满 + 冲突
        available = []
        for c in courses:
            if self._is_course_full(c):
                continue
            is_conflict, _ = self._check_course_conflict(c, selected)
            if is_conflict:
                continue
            available.append(c)

        print(f"[智能抢课] 过滤后可选课程: {len(available)} 门")

        if not available:
            print("[智能抢课] 没有可选课程！")
            return False

        # 线上/线下筛选
        def is_online(c):
            skfsmc = c.get('skfsmc') or ''
            skdd = c.get('skdd') or ''
            return '线上' in skfsmc or '线上' in skdd or '虚拟' in skdd

        online_count = sum(1 for c in available if is_online(c))
        offline_count = len(available) - online_count

        print(f"\n授课方式筛选:")
        print(f"  1 - 线上课 ({online_count}门)")
        print(f"  2 - 线下课 ({offline_count}门)")
        print(f"  3 - 不限 ({len(available)}门)")
        print(f"  回车 - 不限")
        mode_filter = input("选择授课方式: ").strip()

        if mode_filter == '1':
            available = [c for c in available if is_online(c)]
            print(f"[智能抢课] 筛选后: {len(available)} 门线上课")
        elif mode_filter == '2':
            available = [c for c in available if not is_online(c)]
            print(f"[智能抢课] 筛选后: {len(available)} 门线下课")

        if not available:
            print("[智能抢课] 没有符合条件的课程！")
            return False

        print(f"\n[智能抢课] 共 {len(available)} 门可选课程:")
        self.display_courses(available)

        # 选课模式
        print(f"\n选课模式:")
        print(f"  a - 全部选课 (一键选完所有 {len(available)} 门)")
        print(f"  s - 单选 (手动选择其中一门)")
        print(f"  回车 - 取消")
        mode = input("选择模式: ").strip().lower()

        if mode == 'a':
            success_count = 0
            for c in available:
                jx0404id = c.get('jx0404id', '')
                if not jx0404id:
                    continue
                print(f"\n>>> 正在选课: {(c.get('kcmc') or '')} {(c.get('ktmc') or '')}")
                if self.select_course(kcid=jx0404id, jx0404id=jx0404id):
                    success_count += 1
                time.sleep(0.3)
            print(f"\n[智能抢课] 完成! 成功 {success_count}/{len(available)} 门")
            return success_count > 0

        elif mode == 's':
            choice = input("输入序号选择课程: ").strip()
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(available):
                    c = available[idx]
                    jx0404id = c.get('jx0404id', '')
                    return self.select_course(kcid=jx0404id, jx0404id=jx0404id)
                else:
                    print("[智能抢课] 序号无效")
            except ValueError:
                print("[智能抢课] 输入无效")
        else:
            print("[智能抢课] 已取消")

        return False

    def get_selected_courses(self):
        """查询已选课程"""
        if not self.ensure_login():
            return []

        print("\n[已选课程] 正在查询...")
        resp = self.session.get(
            f"{self.BASE_URL}/jsxsd/xsxkjg/getTkrzList",
            timeout=15
        )
        data = resp.json()

        courses = data.get('data', [])
        xh = data.get('xh', '')

        # 计算总学分和总学时
        total_xf = 0.0
        total_zxs = 0
        for c in courses:
            try:
                total_xf += float(c.get('xf', 0) or 0)
            except (ValueError, TypeError):
                pass
            try:
                total_zxs += int(c.get('zxs', 0) or 0)
            except (ValueError, TypeError):
                pass

        print(f"[已选课程] 学号: {xh}, 已选 {len(courses)} 门课程")
        print(f"[已选课程] 总学分: {total_xf:.1f}, 总学时: {total_zxs}\n")

        print(f"{'序号':<4} {'课程号':<14} {'课头名':<18} {'学分':<5} {'学时':<5} {'上课时间':<26} {'课程性质':<10} {'属性':<6} {'jx0404id'}")
        print("-" * 130)
        for i, c in enumerate(courses):
            kch = c.get('kch', '')
            ktmc = c.get('ktmc', '')
            xf = c.get('xf') or ''
            zxs = c.get('zxs') or ''
            sksj = c.get('sksj', '').replace('<br>', ' ')[:24]
            kcxz = c.get('kcxzmc', '')
            kcsx = c.get('kcsxmc', '')
            jxid = c.get('jx0404id', '')
            print(f"{i+1:<4} {kch:<14} {ktmc:<18} {xf:<5} {zxs:<5} {sksj:<26} {kcxz:<10} {kcsx:<6} {jxid}")

        return courses

    def drop_course(self, jx0404id):
        """
        退课操作
        参数: jx0404id - 教学班ID
        """
        if not self.ensure_login():
            return False

        print(f"\n[退课] 正在退课: jx0404id={jx0404id}...")
        resp = self.session.get(
            f"{self.BASE_URL}/jsxsd/xsxkjg/xstkOper",
            params={'jx0404id': jx0404id},
            timeout=15
        )
        result = resp.json()

        success = result.get('success', False)
        message = result.get('message', '')
        if success:
            print(f"[退课] 退课成功! {message}")
        else:
            print(f"[退课] 退课失败: {message}")
        return success


# ==================== 交互式命令行 ====================

def print_menu():
    print("\n" + "=" * 50)
    print("  山东科技大学教务系统选课工具")
    print("=" * 50)
    print("  1. 密码登录")
    print("  2. Cookie登录")
    print("  3. 查询选课轮次")
    print("  4. 进入选课中心 (自动显示课程)")
    print("  5. 查询公选课列表")
    print("  6. 查询落实实践课")
    print("  7. 查询必修课列表")
    print("  8. 查询限选课/专业选修课")
    print("  9. 选课 (输入jx0404id)")
    print(" 10. 按关键词智能选课")
    print(" 11. 查询已选课程")
    print(" 12. 退课")
    print(" 13. 智能自动抢课 (按类别/线上/线下)")
    print("  0. 退出")
    print("=" * 50)


def main():
    selector = SDUSTCourseSelector()

    # 启动时尝试自动登录
    print("\n[启动] 山东科技大学教务系统选课工具")
    if not selector.auto_login():
        print("[启动] 未配置自动登录或用户取消，请手动登录")

    while True:
        print_menu()
        choice = input("请选择操作: ").strip()

        if choice == '0':
            print("再见!")
            break

        elif choice == '1':
            username = input("学号: ").strip()
            password = input("密码: ").strip()
            if selector.login(username, password):
                # 登录成功，询问是否保存配置
                save = input("是否保存账号密码到配置文件? (y/n, 默认n): ").strip().lower()
                if save in ('y', 'yes'):
                    selector._save_config(username, password)

        elif choice == '2':
            print("请从浏览器复制Cookie值 (F12 -> Network -> 任意请求 -> Cookie)")
            cookie = input("Cookie: ").strip()
            selector.login_with_cookies(cookie)

        elif choice == '3':
            selector.get_course_rounds()

        elif choice == '4':
            rounds = selector.get_course_rounds()
            if rounds:
                idx = input("选择轮次序号: ").strip()
                try:
                    idx = int(idx) - 1
                    zbid = rounds[idx]['jx0502zbid']
                    selector.enter_selection(zbid)
                except (ValueError, IndexError):
                    print("无效的序号")

        elif choice == '5':
            page = input("页码 (默认1): ").strip() or '1'
            courses, total = selector.get_public_courses(page=int(page), page_size=100)
            selector.display_courses(courses)

        elif choice == '6':
            page = input("页码 (默认1): ").strip() or '1'
            courses, total = selector.get_practice_courses(page=int(page), page_size=100)
            selector.display_courses(courses)

        elif choice == '7':
            page = input("页码 (默认1): ").strip() or '1'
            courses, total = selector.get_required_courses(page=int(page), page_size=100)
            selector.display_courses(courses)

        elif choice == '8':
            page = input("页码 (默认1): ").strip() or '1'
            courses, total = selector.get_limited_courses(page=int(page), page_size=100)
            selector.display_courses(courses)

        elif choice == '9':
            jx0404id = input("jx0404id (教学班ID, 从课程列表中获取): ").strip()
            selector.select_course(jx0404id, jx0404id)

        elif choice == '10':
            keyword = input("课程关键词 (如 课程名/课头名/老师名/类别): ").strip()
            ctype = input("课程类型 (1=公选课 2=实践课 3=必修课 4=限选课, 默认1): ").strip() or '1'
            type_map = {
                '1': 'public', '公选课': 'public', '公选': 'public',
                '2': 'practice', '实践课': 'practice', '实践': 'practice',
                '3': 'required', '必修课': 'required', '必修': 'required',
                '4': 'limited', '限选课': 'limited', '限选': 'limited', '专业选修': 'limited',
            }
            ct = type_map.get(ctype, 'public')
            selector.select_course_by_keyword(keyword, course_type=ct)

        elif choice == '11':
            selector.get_selected_courses()

        elif choice == '12':
            selector.get_selected_courses()
            jx0404id = input("输入要退课的 jx0404id: ").strip()
            selector.drop_course(jx0404id)

        elif choice == '13':
            ctype = input("课程类型 (1=公选课 2=实践课 3=必修课 4=限选课, 默认1): ").strip() or '1'
            type_map = {
                '1': 'public', '公选课': 'public', '公选': 'public',
                '2': 'practice', '实践课': 'practice', '实践': 'practice',
                '3': 'required', '必修课': 'required', '必修': 'required',
                '4': 'limited', '限选课': 'limited', '限选': 'limited', '专业选修': 'limited',
            }
            ct = type_map.get(ctype, 'public')
            print("\n说明: 自动抢课会自动过滤已满和冲突课程, 然后按类别分组, 最后一键选完所有可选课程")
            print("指定类别, 如 '人文' 可以直接输入类别名")
            print("如果不指定类别，会列出该类型下所有类别供你选择")
            cat = input("指定类别名称(直接回车不指定): ").strip()
            cat = cat if cat else None
            selector.smart_auto_select(course_type=ct, category=cat)

        else:
            print("无效选择")


if __name__ == '__main__':
    main()
