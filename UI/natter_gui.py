import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import threading
import time
import os
import datetime
from natter_service import NatterService
from config_manager import ConfigManager

class NatterGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Natter 服务管理器")
        self.root.geometry("700x500")
        self.root.minsize(700, 500)

        # 初始化服务和管理器
        self.natter_service = NatterService()
        self.config_manager = ConfigManager()

        # 加载配置
        self.config = self.config_manager.load_config()

        # 创建界面
        self.create_widgets()
        self.update_display()

        # 启动状态检查线程
        self.running = True
        self.status_thread = threading.Thread(target=self.status_monitor, daemon=True)
        self.status_thread.start()

        # NAT 检测线程控制
        self.nat_check_thread = None
        self.nat_check_running = False

    def create_widgets(self):
        # 创建菜单栏
        self.create_menu()

        # 创建主框架
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # 配置网格权重
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(2, weight=1)

        # 状态显示
        status_frame = ttk.LabelFrame(main_frame, text="服务状态", padding="5")
        status_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        status_frame.columnconfigure(1, weight=1)

        ttk.Label(status_frame, text="状态:").grid(row=0, column=0, sticky=tk.W)
        self.status_label = ttk.Label(status_frame, text="未运行", foreground="red")
        self.status_label.grid(row=0, column=1, sticky=tk.W, padx=(5, 0))

        # 控制按钮
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))

        self.start_button = ttk.Button(button_frame, text="启动服务", command=self.start_service)
        self.start_button.pack(side=tk.LEFT, padx=(0, 5))

        self.stop_button = ttk.Button(button_frame, text="停止服务", command=self.stop_service, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=(0, 5))

        ttk.Button(button_frame, text="配置管理", command=self.show_config_dialog).pack(side=tk.LEFT, padx=(0, 5))
        self.nat_check_button = ttk.Button(button_frame, text="检测 NAT 类型", command=self.check_nat_type)
        self.nat_check_button.pack(side=tk.LEFT, padx=(0, 5))

        # 日志显示
        log_frame = ttk.LabelFrame(main_frame, text="运行日志", padding="5")
        log_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)

        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD)
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # 日志按钮框架
        log_button_frame = ttk.Frame(log_frame)
        log_button_frame.grid(row=1, column=0, pady=(5, 0), sticky=(tk.W, tk.E))

        ttk.Button(log_button_frame, text="清空日志", command=self.clear_log).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(log_button_frame, text="导出日志", command=self.export_log).pack(side=tk.LEFT)

    def create_menu(self):
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        # 文件菜单
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="文件", menu=file_menu)
        file_menu.add_command(label="导出日志", command=self.export_log)
        file_menu.add_separator()
        file_menu.add_command(label="退出", command=self.on_closing)

        # 设置菜单
        settings_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="设置", menu=settings_menu)
        settings_menu.add_command(label="配置管理", command=self.show_config_dialog)

        # 日志菜单
        log_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="日志", menu=log_menu)
        log_menu.add_command(label="清空日志", command=self.clear_log)
        log_menu.add_command(label="导出日志", command=self.export_log)

        # 工具菜单
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="工具", menu=tools_menu)
        tools_menu.add_command(label="检测 NAT 类型", command=self.check_nat_type)

        # 帮助菜单
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="帮助", menu=help_menu)
        help_menu.add_command(label="关于", command=self.show_about)

    def update_display(self):
        """更新界面显示"""
        # 更新按钮状态
        is_running = self.natter_service.is_running()
        self.start_button.config(state=tk.NORMAL if not is_running else tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL if is_running else tk.DISABLED)

        # 更新状态显示
        if is_running:
            self.status_label.config(text="运行中", foreground="green")
        else:
            self.status_label.config(text="未运行", foreground="red")

    def start_service(self):
        """启动服务"""
        try:
            self.natter_service.start(self.config)
            self.update_display()
            self.log("Natter 服务已启动")
        except Exception as e:
            messagebox.showerror("错误", f"启动服务失败: {str(e)}")

    def stop_service(self):
        """停止服务"""
        try:
            self.natter_service.stop()
            self.update_display()
            self.log("Natter 服务已停止")
        except Exception as e:
            messagebox.showerror("错误", f"停止服务失败: {str(e)}")

    def check_nat_type(self):
        """异步检测 NAT 类型"""
        if self.nat_check_running:
            messagebox.showinfo("提示", "NAT 类型检测正在进行中，请稍候...")
            return

        self.nat_check_running = True
        self.nat_check_button.config(state=tk.DISABLED, text="检测中...")
        self.log("开始检测 NAT 类型...")

        # 启动异步检测线程
        self.nat_check_thread = threading.Thread(target=self._nat_check_worker, daemon=True)
        self.nat_check_thread.start()

    def _nat_check_worker(self):
        """NAT 检测工作线程"""
        try:
            result = self.natter_service.check_nat_type()
            self.root.after(0, lambda: self._nat_check_complete(result, None))
        except Exception as e:
            self.root.after(0, lambda: self._nat_check_complete(None, str(e)))

    def _nat_check_complete(self, result, error):
        """NAT 检测完成回调"""
        self.nat_check_running = False
        self.nat_check_button.config(state=tk.NORMAL, text="检测 NAT 类型")

        if error:
            self.log(f"检测 NAT 类型失败: {error}")
            messagebox.showerror("错误", f"检测 NAT 类型失败: {error}")
        else:
            self.log(f"NAT 类型检测结果:\n{result}")
            messagebox.showinfo("NAT 类型检测", f"检测完成:\n\n{result}")

    def show_config_dialog(self):
        """显示配置对话框"""
        config_dialog = ConfigDialog(self.root, self.config, self.config_manager)
        self.root.wait_window(config_dialog.dialog)

        if config_dialog.result:
            self.config = config_dialog.config
            self.config_manager.save_config(self.config)
            self.update_display()
            self.log("配置已更新")

    def clear_log(self):
        """清空日志"""
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state=tk.DISABLED)

    def export_log(self):
        """导出日志到文件"""
        try:
            # 获取日志内容
            log_content = self.log_text.get(1.0, tk.END)
            if not log_content.strip():
                messagebox.showinfo("提示", "日志内容为空，无需导出")
                return

            # 生成默认文件名
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            default_filename = f"natter_log_{timestamp}.txt"

            # 选择保存位置
            filename = filedialog.asksaveasfilename(
                title="导出日志",
                initialfile=default_filename,
                defaultextension=".txt",
                filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")]
            )

            if filename:
                # 写入文件
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(log_content)

                self.log(f"日志已导出到: {filename}")
                messagebox.showinfo("成功", f"日志已成功导出到:\n{filename}")

        except Exception as e:
            messagebox.showerror("错误", f"导出日志失败: {str(e)}")

    def log(self, message):
        """添加日志消息"""
        log_message = f"{message}\n"

        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, log_message)
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)

    def status_monitor(self):
        """状态监控线程"""
        while self.running:
            try:
                if self.natter_service.is_running():
                    # 检查进程状态
                    if not self.natter_service.process_alive():
                        self.natter_service.set_running(False)
                        self.root.after(0, self.update_display)
                        self.root.after(0, lambda: self.log("Natter 进程异常退出"))

                    # 获取最新输出
                    output = self.natter_service.get_output()
                    if output:
                        self.root.after(0, lambda: self.log(output.strip()))

                time.sleep(1)
            except Exception:
                time.sleep(5)

    def show_about(self):
        """显示关于对话框"""
        about_text = """Natter 服务管理器 v1.0

基于 Natter 的图形化端口映射工具

作者: Droid-MAX
License: MIT"""

        messagebox.showinfo("关于", about_text)

    def on_closing(self):
        """程序关闭时的处理"""
        self.running = False

        # 停止 NAT 检测
        self.nat_check_running = False

        # 停止服务并清理进程
        if hasattr(self, 'natter_service') and self.natter_service:
            self.natter_service.stop()
            # 额外清理确保没有残留
            self.natter_service.cleanup_all_natter_processes()

        self.root.destroy()


class ConfigDialog:
    def __init__(self, parent, config, config_manager):
        self.parent = parent
        self.config = config.copy()
        self.config_manager = config_manager
        self.result = False

        self.create_dialog()

    def create_dialog(self):
        """创建配置对话框"""
        self.dialog = tk.Toplevel(self.parent)
        self.dialog.title("配置管理")
        self.dialog.geometry("500x400")
        self.dialog.resizable(True, True)
        self.dialog.transient(self.parent)
        self.dialog.grab_set()

        # 创建笔记本控件（标签页）
        notebook = ttk.Notebook(self.dialog)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # 基本设置标签页
        basic_frame = ttk.Frame(notebook, padding="10")
        notebook.add(basic_frame, text="基本设置")
        self.create_basic_tab(basic_frame)

        # 绑定设置标签页
        bind_frame = ttk.Frame(notebook, padding="10")
        notebook.add(bind_frame, text="绑定设置")
        self.create_bind_tab(bind_frame)

        # 转发设置标签页
        forward_frame = ttk.Frame(notebook, padding="10")
        notebook.add(forward_frame, text="转发设置")
        self.create_forward_tab(forward_frame)

        # 脚本设置标签页
        script_frame = ttk.Frame(notebook, padding="10")
        notebook.add(script_frame, text="脚本设置")
        self.create_script_tab(script_frame)

        # 按钮框架
        button_frame = ttk.Frame(self.dialog)
        button_frame.pack(fill=tk.X, padx=10, pady=10)

        ttk.Button(button_frame, text="确定", command=self.on_ok).pack(side=tk.RIGHT, padx=(5, 0))
        ttk.Button(button_frame, text="取消", command=self.on_cancel).pack(side=tk.RIGHT)

    def create_basic_tab(self, parent):
        """创建基本设置标签页"""
        # UDP 模式
        self.udp_mode = tk.BooleanVar(value=self.config.get('udp_mode', False))
        ttk.Checkbutton(parent, text="UDP 模式 (-u)", variable=self.udp_mode).grid(row=0, column=0, sticky=tk.W, pady=2)

        # UPnP
        self.enable_upnp = tk.BooleanVar(value=self.config.get('enable_upnp', False))
        ttk.Checkbutton(parent, text="启用 UPnP/IGD 发现 (-U)", variable=self.enable_upnp).grid(row=1, column=0, sticky=tk.W, pady=2)

        # 详细模式
        self.verbose = tk.BooleanVar(value=self.config.get('verbose', False))
        ttk.Checkbutton(parent, text="详细模式 (-v)", variable=self.verbose).grid(row=2, column=0, sticky=tk.W, pady=2)

        # 退出条件
        self.exit_on_change = tk.BooleanVar(value=self.config.get('exit_on_change', False))
        ttk.Checkbutton(parent, text="映射地址改变时退出 (-q)", variable=self.exit_on_change).grid(row=3, column=0, sticky=tk.W, pady=2)

        # STUN 服务器
        ttk.Label(parent, text="STUN 服务器地址:").grid(row=4, column=0, sticky=tk.W, pady=(10, 2))
        self.stun_server = tk.StringVar(value=self.config.get('stun_server', ''))
        ttk.Entry(parent, textvariable=self.stun_server, width=40).grid(row=5, column=0, sticky=(tk.W, tk.E), pady=2)

        # 保活间隔
        ttk.Label(parent, text="保活间隔(秒):").grid(row=6, column=0, sticky=tk.W, pady=(10, 2))
        self.keep_alive = tk.StringVar(value=self.config.get('keep_alive', ''))
        ttk.Entry(parent, textvariable=self.keep_alive, width=20).grid(row=7, column=0, sticky=tk.W, pady=2)

        parent.columnconfigure(0, weight=1)

    def create_bind_tab(self, parent):
        """创建绑定设置标签页"""
        # 网络接口
        ttk.Label(parent, text="网络接口/IP (-i):").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.bind_interface = tk.StringVar(value=self.config.get('bind_interface', ''))
        ttk.Entry(parent, textvariable=self.bind_interface, width=40).grid(row=1, column=0, sticky=(tk.W, tk.E), pady=2)

        # 绑定端口
        ttk.Label(parent, text="绑定端口 (-b):").grid(row=2, column=0, sticky=tk.W, pady=(10, 2))
        self.bind_port = tk.StringVar(value=self.config.get('bind_port', ''))
        ttk.Entry(parent, textvariable=self.bind_port, width=20).grid(row=3, column=0, sticky=tk.W, pady=2)

        parent.columnconfigure(0, weight=1)

    def create_forward_tab(self, parent):
        """创建转发设置标签页"""
        # 转发方法
        ttk.Label(parent, text="转发方法 (-m):").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.forward_method = tk.StringVar(value=self.config.get('forward_method', ''))
        method_combo = ttk.Combobox(parent, textvariable=self.forward_method, width=20)
        method_combo['values'] = ('', 'iptables', 'nftables', 'socat', 'gost', 'socket')
        method_combo.grid(row=1, column=0, sticky=tk.W, pady=2)

        # 目标地址
        ttk.Label(parent, text="目标 IP 地址 (-t):").grid(row=2, column=0, sticky=tk.W, pady=(10, 2))
        self.target_address = tk.StringVar(value=self.config.get('target_address', ''))
        ttk.Entry(parent, textvariable=self.target_address, width=40).grid(row=3, column=0, sticky=(tk.W, tk.E), pady=2)

        # 目标端口
        ttk.Label(parent, text="目标端口 (-p):").grid(row=4, column=0, sticky=tk.W, pady=(10, 2))
        self.target_port = tk.StringVar(value=self.config.get('target_port', ''))
        ttk.Entry(parent, textvariable=self.target_port, width=20).grid(row=5, column=0, sticky=tk.W, pady=2)

        # 持续重试
        self.keep_retrying = tk.BooleanVar(value=self.config.get('keep_retrying', False))
        ttk.Checkbutton(parent, text="持续重试直到目标端口打开 (-r)", variable=self.keep_retrying).grid(row=6, column=0, sticky=tk.W, pady=(10, 2))

        parent.columnconfigure(0, weight=1)

    def create_script_tab(self, parent):
        """创建脚本设置标签页"""
        # 脚本路径
        ttk.Label(parent, text="脚本路径 (-e):").grid(row=0, column=0, sticky=tk.W, pady=2)

        script_frame = ttk.Frame(parent)
        script_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=2)
        script_frame.columnconfigure(0, weight=1)

        self.script_path = tk.StringVar(value=self.config.get('script_path', ''))
        script_entry = ttk.Entry(script_frame, textvariable=self.script_path)
        script_entry.grid(row=0, column=0, sticky=(tk.W, tk.E))

        ttk.Button(script_frame, text="浏览", command=self.browse_script).grid(row=0, column=1, padx=(5, 0))

        # 脚本说明
        ttk.Label(parent, text="说明: 此脚本将在映射地址变化时执行，用于通知新的映射地址。").grid(
            row=2, column=0, sticky=tk.W, pady=(10, 2))

        ttk.Label(parent, text="脚本将接收以下环境变量:").grid(row=3, column=0, sticky=tk.W, pady=(5, 2))

        script_info = """NATTER_EXTERNAL_IP - 外部IP地址
NATTER_EXTERNAL_PORT - 外部端口
NATTER_INTERNAL_IP - 内部IP地址
NATTER_INTERNAL_PORT - 内部端口
NATTER_PROTOCOL - 协议类型 (TCP/UDP)"""

        script_text = scrolledtext.ScrolledText(parent, height=6, wrap=tk.WORD, width=50)
        script_text.grid(row=4, column=0, sticky=(tk.W, tk.E), pady=2)
        script_text.insert(1.0, script_info)
        script_text.config(state=tk.DISABLED)

        parent.columnconfigure(0, weight=1)

    def browse_script(self):
        """浏览脚本文件"""
        filename = filedialog.askopenfilename(
            title="选择脚本文件",
            filetypes=[("可执行文件", "*.exe;*.bat;*.cmd;*.sh;*.py"), ("所有文件", "*.*")]
        )
        if filename:
            self.script_path.set(filename)

    def on_ok(self):
        """确定按钮处理"""
        try:
            # 验证端口号（如果设置了）
            if self.bind_port.get():
                int(self.bind_port.get())
            if self.target_port.get():
                int(self.target_port.get())
            if self.keep_alive.get():
                int(self.keep_alive.get())
        except ValueError:
            messagebox.showerror("错误", "端口号和保活间隔必须是数字")
            return

        # 检查绑定模式和转发模式是否同时使用
        if (self.bind_port.get() and self.forward_method.get()) or \
           (self.bind_interface.get() and self.forward_method.get()):
            messagebox.showerror("错误", "绑定模式和转发模式参数不能同时使用")
            return

        # 保存配置
        self.config.update({
            'udp_mode': self.udp_mode.get(),
            'enable_upnp': self.enable_upnp.get(),
            'verbose': self.verbose.get(),
            'exit_on_change': self.exit_on_change.get(),
            'stun_server': self.stun_server.get(),
            'keep_alive': self.keep_alive.get(),
            'bind_interface': self.bind_interface.get(),
            'bind_port': self.bind_port.get(),
            'forward_method': self.forward_method.get(),
            'target_address': self.target_address.get(),
            'target_port': self.target_port.get(),
            'keep_retrying': self.keep_retrying.get(),
            'script_path': self.script_path.get()
        })

        self.result = True
        self.dialog.destroy()

    def on_cancel(self):
        """取消按钮处理"""
        self.dialog.destroy()


def main():
    """主函数"""
    root = tk.Tk()
    app = NatterGUI(root)

    # 设置关闭事件处理
    root.protocol("WM_DELETE_WINDOW", app.on_closing)

    # 启动主循环
    root.mainloop()


if __name__ == "__main__":
    main()