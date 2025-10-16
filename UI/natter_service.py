import subprocess
import threading
import os
import time
import queue
import psutil

class NatterService:
    def __init__(self):
        self.process = None
        self.is_running_flag = False
        self.output_queue = queue.Queue()
        self.output_thread = None
        self.monitor_thread = None
        self.process_pid = None

    def start(self, config):
        """启动 Natter 服务"""
        if self.is_running():
            raise Exception("服务已在运行中")

        # 构建命令行参数
        args = self.build_arguments(config)

        # 查找 natter 可执行文件
        natter_path = self.find_natter()
        if not natter_path:
            raise Exception("未找到 natter.exe 可执行文件")

        # 启动进程
        try:
            # 如果没有设置任何参数，直接运行 natter
            if not args:
                self.process = subprocess.Popen(
                    [natter_path],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                    universal_newlines=True,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
            else:
                self.process = subprocess.Popen(
                    [natter_path] + args,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                    universal_newlines=True,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )

            self.process_pid = self.process.pid
            self.is_running_flag = True

            # 启动输出读取线程
            self.output_thread = threading.Thread(target=self.read_output, daemon=True)
            self.output_thread.start()

            # 启动监控线程
            self.monitor_thread = threading.Thread(target=self.monitor_process, daemon=True)
            self.monitor_thread.start()

        except Exception as e:
            self.is_running_flag = False
            raise Exception(f"启动进程失败: {str(e)}")

    def stop(self):
        """停止 Natter 服务"""
        if self.process or self.process_pid:
            try:
                # 首先尝试终止整个进程树
                self.kill_process_tree()

                # 然后确保主进程也被终止
                if self.process:
                    try:
                        self.process.terminate()
                        self.process.wait(timeout=3)
                    except (subprocess.TimeoutExpired, AttributeError):
                        if self.process:
                            self.process.kill()
                            self.process.wait()
            except Exception as e:
                print(f"停止进程时发生错误: {e}")
            finally:
                self.process = None
                self.process_pid = None
                self.is_running_flag = False

    def kill_process_tree(self):
        """终止整个进程树"""
        try:
            if self.process_pid:
                # 使用 psutil 终止整个进程树
                parent = psutil.Process(self.process_pid)
                children = parent.children(recursive=True)

                # 先终止所有子进程
                for child in children:
                    try:
                        child.terminate()
                    except psutil.NoSuchProcess:
                        pass

                # 等待子进程终止
                gone, still_alive = psutil.wait_procs(children, timeout=3)

                # 强制终止仍然存活的子进程
                for child in still_alive:
                    try:
                        child.kill()
                    except psutil.NoSuchProcess:
                        pass

                # 终止父进程
                try:
                    parent.terminate()
                    parent.wait(timeout=3)
                except (psutil.TimeoutExpired, psutil.NoSuchProcess):
                    try:
                        parent.kill()
                    except psutil.NoSuchProcess:
                        pass

        except psutil.NoSuchProcess:
            # 进程已经不存在
            pass
        except Exception as e:
            print(f"终止进程树时发生错误: {e}")

    def cleanup_all_natter_processes(self):
        """清理所有 natter.exe 进程（紧急情况使用）"""
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    if proc.info['name'] and 'natter.exe' in proc.info['name'].lower():
                        print(f"强制终止残留进程: {proc.info['pid']}")
                        proc.kill()
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
        except Exception as e:
            print(f"清理进程时发生错误: {e}")

    def check_nat_type(self):
        """检测 NAT 类型"""
        # 查找 natter 可执行文件
        natter_path = self.find_natter()
        if not natter_path:
            raise Exception("未找到 natter.exe 可执行文件")

        try:
            result = subprocess.run(
                [natter_path, "--check"],
                capture_output=True,
                text=True,
                timeout=30,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            return result.stdout if result.stdout else result.stderr
        except subprocess.TimeoutExpired:
            return "检测超时，请重试"
        except Exception as e:
            raise Exception(f"执行检测失败: {str(e)}")

    def is_running(self):
        """检查服务是否在运行"""
        return self.is_running_flag

    def set_running(self, running):
        """设置运行状态"""
        self.is_running_flag = running

    def process_alive(self):
        """检查进程是否存活"""
        if self.process and self.process.poll() is None:
            return True
        return False

    def get_output(self):
        """获取输出内容"""
        outputs = []
        while not self.output_queue.empty():
            try:
                outputs.append(self.output_queue.get_nowait())
            except queue.Empty:
                break
        return "".join(outputs)

    def read_output(self):
        """读取进程输出"""
        try:
            for line in iter(self.process.stdout.readline, ''):
                if line:
                    self.output_queue.put(line)
        except Exception:
            pass

    def monitor_process(self):
        """监控进程状态"""
        try:
            while self.is_running_flag:
                if not self.process_alive():
                    self.is_running_flag = False
                    # 进程异常退出时清理残留
                    self.cleanup_all_natter_processes()
                    break
                time.sleep(1)
        except Exception:
            pass

    def build_arguments(self, config):
        """构建命令行参数"""
        args = []

        # 基本参数
        if config.get('udp_mode'):
            args.append('-u')
        if config.get('enable_upnp'):
            args.append('-U')
        if config.get('verbose'):
            args.append('-v')
        if config.get('exit_on_change'):
            args.append('-q')

        if config.get('keep_alive') and config.get('keep_alive').strip():
            args.extend(['-k', config['keep_alive']])

        if config.get('stun_server') and config.get('stun_server').strip():
            args.extend(['-s', config['stun_server']])

        # 脚本路径参数
        if config.get('script_path') and config.get('script_path').strip():
            args.extend(['-e', config['script_path']])

        # 绑定参数和转发参数不能同时使用
        using_bind = (config.get('bind_interface') and config.get('bind_interface').strip()) or \
                    (config.get('bind_port') and config.get('bind_port').strip())
        using_forward = (config.get('forward_method') and config.get('forward_method').strip()) or \
                       (config.get('target_address') and config.get('target_address').strip()) or \
                       (config.get('target_port') and config.get('target_port').strip())

        if using_bind and using_forward:
            raise Exception("绑定模式和转发模式参数不能同时使用")

        # 绑定参数
        if config.get('bind_interface') and config.get('bind_interface').strip():
            args.extend(['-i', config['bind_interface']])

        if config.get('bind_port') and config.get('bind_port').strip():
            args.extend(['-b', config['bind_port']])

        # 转发参数
        if config.get('forward_method') and config.get('forward_method').strip():
            args.extend(['-m', config['forward_method']])

        if config.get('target_address') and config.get('target_address').strip():
            args.extend(['-t', config['target_address']])

        if config.get('target_port') and config.get('target_port').strip():
            args.extend(['-p', config['target_port']])

        if config.get('keep_retrying'):
            args.append('-r')

        return args

    def find_natter(self):
        """查找 natter 可执行文件"""
        # 在当前目录查找
        current_dir = os.path.dirname(os.path.abspath(__file__))
        natter_exe = os.path.join(current_dir, 'natter.exe')
        if os.path.isfile(natter_exe):
            return natter_exe

        # 在系统 PATH 中查找
        paths = os.environ.get('PATH', '').split(os.pathsep)
        for path in paths:
            natter_exe = os.path.join(path, 'natter.exe')
            if os.path.isfile(natter_exe):
                return natter_exe

        return None