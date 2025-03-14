import os
import importlib
import pkgutil

# 获取当前包的路径
__path__ = [os.path.dirname(__file__)]

# 动态导入所有模块
for _, name, _ in pkgutil.iter_modules(__path__):
    if name != '__init__':
        try:
            importlib.import_module(f'.{name}', __package__)
        except ImportError as e:
            print(f"[*] Error importing probe module {name}: {e}")

# 导出所有模块名称
#__all__ = [name for _, name, _ in pkgutil.iter_modules(__path__) if name != '__init__']
