import subprocess
import os

import psutil


def monitor_process(pid, post_action):
    process = psutil.Process(pid)

    # 等待进程结束
    process.wait()

    # 进程结束后执行后续动作
    if callable(post_action):
        post_action()

# 示例后续动作函数
def post_action():
    os.system("./run.sh")

# 要监视的PID
pid_to_monitor = 2420

# 启动监视进程
monitor_process(pid_to_monitor, post_action)
