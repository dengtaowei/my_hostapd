# ========== 配置部分 ==========
KERNEL_VERSION := $(shell uname -r)
KERNEL_DIR ?= /lib/modules/$(KERNEL_VERSION)/build
MAKE := make
JOBS := 4  # 自动检测CPU核心数

# 模块列表和依赖关系
MODULES := cfg80211 mac80211 mac80211_hwsim
MODULE_DEPS := cfg80211 mac80211  # mac80211_hwsim依赖前两个

# 输出控制
QUIET := @
ifneq ($(V),)
  QUIET :=
endif

.PHONY: all clean install uninstall help $(MODULES)

# ========== 主要目标 ==========
help:
	@echo "可用目标:"
	@echo "  all        - 编译所有模块（默认）"
	@echo "  clean      - 清理编译文件"
	@echo "  install    - 安装所有模块"
	@echo "  uninstall  - 卸载所有模块"
	@echo "  check      - 检查编译环境"
	@echo ""
	@echo "选项:"
	@echo "  V=1        - 显示详细输出"
	@echo "  JOBS=N     - 指定并行任务数"

# 默认目标
all: $(MODULES)
	$(QUIET)echo "✅ 所有内核模块编译完成"

# 检查环境
check:
	@echo "检查编译环境..."
	@test -d $(KERNEL_DIR) || { echo "错误: 内核目录不存在: $(KERNEL_DIR)"; exit 1; }
	@echo "✓ 内核目录: $(KERNEL_DIR)"
	@echo "✓ 内核版本: $(KERNEL_VERSION)"
	@echo "✓ 并行任务: $(JOBS)"

# ========== 模块编译 ==========
# 方法1：顺序编译（确保依赖关系）
cfg80211: check
	$(QUIET)echo "📦 编译 cfg80211..."
	$(MAKE) -C cfg80211 KERNEL_DIR=$(KERNEL_DIR) -j$(JOBS)

mac80211: cfg80211
	$(QUIET)echo "📦 编译 mac80211..."
	$(MAKE) -C mac80211 KERNEL_DIR=$(KERNEL_DIR) -j$(JOBS)

mac80211_hwsim: mac80211
	$(QUIET)echo "📦 编译 mac80211_hwsim..."
	$(MAKE) -C mac80211_hwsim KERNEL_DIR=$(KERNEL_DIR) -j$(JOBS)

# 方法2：使用模式规则（如果模块间无依赖）
# %:
# 	$(QUIET)echo "编译 $@..."
# 	$(MAKE) -C $@ KERNEL_DIR=$(KERNEL_DIR) -j$(JOBS)

# ========== 安装和卸载 ==========
install: all
	$(QUIET)echo "🔧 安装模块..."
	$(QUIET)sudo $(MAKE) -C cfg80211 install
	$(QUIET)sudo $(MAKE) -C mac80211 install
	$(QUIET)sudo $(MAKE) -C mac80211_hwsim install
	$(QUIET)echo "✅ 模块安装完成"

uninstall:
	$(QUIET)echo "🗑️  卸载模块..."
	-$(QUIET)sudo rmmod mac80211_hwsim 2>/dev/null || true
	-$(QUIET)sudo rmmod mac80211 2>/dev/null || true
	-$(QUIET)sudo rmmod cfg80211 2>/dev/null || true
	$(QUIET)echo "✅ 模块卸载完成"

# ========== 清理 ==========
clean:
	$(QUIET)echo "🧹 清理编译文件..."
	$(QUIET)for dir in $(MODULES); do \
		$(MAKE) -C $$dir clean; \
	done
	$(QUIET)find . -name "*.ko" -delete
	$(QUIET)find . -name "*.o" -delete
	$(QUIET)find . -name "*.mod.c" -delete
	$(QUIET)find . -name "Module.symvers" -delete
	$(QUIET)find . -name "modules.order" -delete
	$(QUIET)echo "✅ 清理完成"

# ========== 测试目标 ==========
test: all
	$(QUIET)echo "🧪 测试模块..."
	$(QUIET)sudo insmod cfg80211/cfg80211.ko
	$(QUIET)sudo insmod mac80211/mac80211.ko
	$(QUIET)sudo insmod mac80211_hwsim/mac80211_hwsim.ko
	$(QUIET)echo "✅ 模块加载测试完成"

load: test  # 别名

# 查看模块信息
info:
	@for dir in $(MODULES); do \
		if [ -f $$dir/*.ko ]; then \
			echo "=== $$dir ==="; \
			modinfo $$dir/*.ko | head -5; \
		fi; \
	done