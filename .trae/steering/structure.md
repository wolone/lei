# 项目结构：Trae AI 工作流程系统

## 目录结构概览

### 🏗️ **完整项目结构**
```
项目根目录/
├── .trae/                      # Trae AI 工作流程系统核心目录
│   ├── steering/               # 项目指导文档
│   │   ├── product.md          # 产品愿景和目标
│   │   ├── tech.md             # 技术架构文档
│   │   └── structure.md        # 项目结构说明（本文件）
│   ├── specs/                  # 功能规格管理
│   │   ├── [feature-name]/     # 具体功能目录
│   │   │   ├── requirements.md # 需求文档
│   │   │   ├── design.md       # 设计文档
│   │   │   ├── tasks.md        # 任务分解
│   │   │   └── implementation.md # 实现记录
│   │   └── ...
│   ├── bugs/                   # Bug 管理
│   │   ├── [bug-id]/           # 具体 Bug 目录
│   │   │   ├── report.md       # Bug 报告
│   │   │   ├── analysis.md     # 问题分析
│   │   │   ├── fix.md          # 修复方案
│   │   │   └── verification.md # 验证结果
│   │   └── ...
│   ├── templates/              # 模板文件
│   │   ├── spec-template.md    # 规格模板
│   │   ├── bug-template.md     # Bug 模板
│   │   ├── task-template.md    # 任务模板
│   │   └── ...
│   ├── workflows/              # 工作流程定义
│   │   ├── spec-workflow.md    # 规格开发流程
│   │   ├── bug-workflow.md     # Bug 修复流程
│   │   ├── refactor-workflow.md # 重构流程
│   │   └── ...
│   ├── guides/                 # 使用指南
│   │   ├── getting-started.md  # 快速开始
│   │   ├── best-practices.md   # 最佳实践
│   │   ├── troubleshooting.md  # 故障排除
│   │   └── ...
│   └── trae-config.json        # 系统配置文件
├── src/                        # 源代码目录
│   ├── components/             # 组件目录
│   ├── services/               # 服务层
│   ├── utils/                  # 工具函数
│   ├── types/                  # 类型定义
│   └── ...
├── docs/                       # 项目文档
├── tests/                      # 测试文件
├── package.json                # 项目依赖
├── README.md                   # 项目说明
└── ...
```

## 核心目录详解

### 📋 **steering/ - 项目指导**
项目的核心指导文档，为整个开发过程提供方向和原则。

#### 文件说明
- **product.md**: 产品愿景、目标用户、核心功能和发展路线图
- **tech.md**: 技术架构、核心组件、数据流设计和性能优化
- **structure.md**: 项目结构说明和目录组织原则

#### 使用场景
- 新团队成员了解项目背景
- 重大决策时的参考依据
- 项目方向调整时的指导文档

### 🎯 **specs/ - 功能规格管理**
管理所有功能开发的完整生命周期，从需求到实现。

#### 目录结构
```
specs/
├── user-authentication/        # 用户认证功能
│   ├── requirements.md         # 用户故事和验收标准
│   ├── design.md              # 架构设计和接口定义
│   ├── tasks.md               # 具体实现任务
│   └── implementation.md      # 实现记录和测试结果
├── dashboard-ui/              # 仪表板界面
│   ├── requirements.md
│   ├── design.md
│   ├── tasks.md
│   └── implementation.md
└── ...
```

#### 工作流程
1. **需求阶段**: 创建 requirements.md，定义用户故事
2. **设计阶段**: 创建 design.md，设计技术方案
3. **任务阶段**: 创建 tasks.md，分解具体任务
4. **实现阶段**: 更新 implementation.md，记录实现过程

### 🐛 **bugs/ - Bug 管理**
系统化管理 Bug 的发现、分析、修复和验证过程。

#### 目录结构
```
bugs/
├── bug-001-login-failure/      # 登录失败问题
│   ├── report.md              # Bug 报告和重现步骤
│   ├── analysis.md            # 根因分析
│   ├── fix.md                 # 修复方案和代码变更
│   └── verification.md        # 测试验证结果
├── bug-002-memory-leak/       # 内存泄漏问题
│   ├── report.md
│   ├── analysis.md
│   ├── fix.md
│   └── verification.md
└── ...
```

#### 命名规范
- **格式**: `bug-{序号}-{简短描述}`
- **示例**: `bug-001-login-failure`, `bug-002-memory-leak`
- **序号**: 三位数字，从 001 开始

### 📄 **templates/ - 模板文件**
提供标准化的文档模板，确保一致性和完整性。

#### 模板类型
- **spec-template.md**: 功能规格模板
- **bug-template.md**: Bug 报告模板
- **task-template.md**: 任务定义模板
- **design-template.md**: 设计文档模板
- **test-template.md**: 测试计划模板

#### 模板使用
```bash
# 创建新功能规格
cp .trae/templates/spec-template.md .trae/specs/new-feature/requirements.md

# 创建 Bug 报告
cp .trae/templates/bug-template.md .trae/bugs/bug-003-new-issue/report.md
```

### 🔄 **workflows/ - 工作流程定义**
定义标准化的工作流程，指导开发活动的执行。

#### 工作流程类型
- **spec-workflow.md**: 功能开发流程
- **bug-workflow.md**: Bug 修复流程
- **refactor-workflow.md**: 代码重构流程
- **release-workflow.md**: 发布流程
- **review-workflow.md**: 代码审查流程

#### 流程特点
- **标准化**: 统一的执行步骤
- **可追溯**: 每个阶段都有明确的输出
- **可验证**: 每个阶段都有验收标准
- **可优化**: 基于实践持续改进

### 📚 **guides/ - 使用指南**
提供详细的使用说明和最佳实践指导。

#### 指南内容
- **getting-started.md**: 快速开始指南
- **best-practices.md**: 开发最佳实践
- **troubleshooting.md**: 常见问题解决
- **advanced-usage.md**: 高级使用技巧
- **integration.md**: 工具集成指南

## 配置文件说明

### ⚙️ **trae-config.json**
系统的核心配置文件，控制工作流程的行为。

#### 配置结构
```json
{
  "trae_workflow": {
    "version": "1.0.0",
    "auto_create_directories": true,
    "default_feature_prefix": "feature-",
    "default_bug_prefix": "bug-",
    "workflow_types": {
      "spec": {
        "enabled": true,
        "phases": ["requirements", "design", "tasks", "implementation"]
      },
      "bug": {
        "enabled": true,
        "phases": ["report", "analyze", "fix", "verify"]
      }
    }
  }
}
```

#### 配置说明
- **version**: 工作流程系统版本
- **auto_create_directories**: 自动创建目录结构
- **default_feature_prefix**: 功能目录前缀
- **default_bug_prefix**: Bug 目录前缀
- **workflow_types**: 支持的工作流程类型

## 命名规范

### 📝 **文件命名**
- **小写字母**: 所有文件名使用小写字母
- **连字符分隔**: 使用连字符 `-` 分隔单词
- **描述性**: 文件名应该清楚描述内容
- **扩展名**: 统一使用 `.md` 扩展名

#### 示例
```
✅ 正确:
user-authentication-requirements.md
bug-001-login-failure-report.md
dashboard-ui-design.md

❌ 错误:
UserAuthentication.md
bug_001_LoginFailure.md
DashboardUI_Design.MD
```

### 📁 **目录命名**
- **功能目录**: 使用功能名称，连字符分隔
- **Bug 目录**: `bug-{序号}-{简短描述}`
- **版本目录**: `v{主版本}.{次版本}.{修订版本}`

#### 示例
```
✅ 正确:
user-authentication/
bug-001-login-failure/
v1.2.3/

❌ 错误:
UserAuthentication/
Bug_001_LoginFailure/
Version1.2.3/
```

## 版本控制集成

### 🔄 **Git 集成**
```gitignore
# .gitignore 建议配置

# 临时文件
*.tmp
*.temp

# 编辑器文件
.vscode/
.idea/
*.swp
*.swo

# 系统文件
.DS_Store
Thumbs.db

# 保留 .trae 目录
# .trae/ 目录应该被版本控制
```

### 📋 **提交规范**
```
# 功能开发提交
feat(user-auth): add login functionality

# Bug 修复提交
fix(bug-001): resolve login failure issue

# 文档更新提交
docs(spec): update user authentication requirements

# 工作流程更新提交
workflow: update spec development process
```

## 最佳实践

### ✅ **目录管理**
1. **保持整洁**: 定期清理不需要的文件和目录
2. **及时更新**: 项目变更时及时更新相关文档
3. **版本控制**: 所有重要文档都应纳入版本控制
4. **备份策略**: 定期备份重要的工作流程文档

### 📊 **文档管理**
1. **模板使用**: 始终使用标准模板创建新文档
2. **内容完整**: 确保每个阶段的文档都完整填写
3. **链接维护**: 保持文档间链接的有效性
4. **定期审查**: 定期审查和更新过时的文档

### 🔄 **工作流程**
1. **严格执行**: 严格按照定义的工作流程执行
2. **持续改进**: 基于实践经验持续优化流程
3. **团队协作**: 确保团队成员都理解和遵循流程
4. **质量保证**: 每个阶段都要有质量检查点

## 扩展和自定义

### 🔧 **自定义模板**
可以根据项目需要创建自定义模板：

```bash
# 创建自定义模板目录
mkdir .trae/templates/custom

# 添加项目特定的模板
cp project-specific-template.md .trae/templates/custom/
```

### 📋 **自定义工作流程**
可以定义项目特定的工作流程：

```bash
# 创建自定义工作流程
touch .trae/workflows/custom-workflow.md

# 在配置文件中启用
# 编辑 trae-config.json 添加新的工作流程类型
```

### 🎯 **集成外部工具**
可以集成外部工具和服务：

- **项目管理**: Jira, Trello, Asana
- **代码托管**: GitHub, GitLab, Bitbucket
- **CI/CD**: Jenkins, GitHub Actions, GitLab CI
- **监控**: Sentry, DataDog, New Relic

## 故障排除

### 🔍 **常见问题**
1. **目录权限**: 确保有足够的文件系统权限
2. **配置错误**: 检查 trae-config.json 语法
3. **模板缺失**: 确保所需模板文件存在
4. **路径问题**: 使用绝对路径避免路径错误

### 🛠️ **调试方法**
1. **日志检查**: 查看系统日志了解错误详情
2. **配置验证**: 验证配置文件的正确性
3. **权限检查**: 确认文件和目录权限设置
4. **依赖检查**: 确认所有依赖都已正确安装