# 安全漏洞报告邮件

## 英文版本 (正式发送)

保存位置: `/Users/wooluo/DEV/openclaw/docs/security/REPORT-EMAIL.md`

---

## 中文参考 (理解用意)

**主题**: 安全漏洞报告：OpenClaw 命令混淆检测绕过 (CVSS 8.6)

**收件人**: security@openclaw.ai

---

### 邮件正文要点

**开头**:
```
你好 OpenClaw 安全团队，

我发现了 OpenClaw 命令混淆检测机制中的一个安全漏洞。
该漏洞允许攻击者绕过安全控制并执行任意命令。
```

**关键信息**:
- **漏洞类型**: 命令混淆检测绕过
- **严重程度**: 严重 (CVSS 8.6)
- **影响版本**: OpenClaw <= 2026.3.10
- **绕过率**: 90% (20个攻击向量中18个可绕过)

**主要发现**:
```
关键问题：OpenClaw 有 stripInvisibleUnicode() 函数
(src/security/external-content.ts)，但仅用于 Web 内容清理，
未应用于命令检测！
```

**我可以提供**:
- [x] 详细漏洞分析
- [x] 可运行的 PoC 代码
- [x] 修复补丁实现
- [x] 独立验证结果

**披露时间线**:
```
2026-03-12: 初始报告（今天）
2026-03-19: 厂商确认（7天）
2026-04-11: 补丁发布（30天）
2026-06-10: 公开披露（90天）
```

---

## 发送前检查清单

- [ ] 填写 [Your Name] 和 [Your Email]
- [ ] 附上 PGP 公钥（如果有）
- [ ] 确认邮箱地址正确: security@openclaw.ai
- [ ] 检查附件大小（如果有）

---

## 预期厂商响应

### 场景 1: 积极响应 ✅ (理想)

```
收件: 1-3 天内

回复内容：
- 确认收到报告
- 感谢你的发现
- 提供 PGP 密钥
- 开始调查
- 讨论 CVE 分配
```

### 场景 2: 需要更多信息

```
如果他们要求更多信息：
- 发送完整的技术报告
- 提供 PoC 演示
- 解释复现步骤
```

### 场景 3: 无响应

```
7天后未响应：
- 发送提醒邮件
- 联系 GitHub Security
- 考虑负责任披露延期
```

---

## 后续步骤

### 1. 发送邮件后

```
Day 1: 发送初始报告
Day 3: 如无响应，发送提醒
Day 7: 厂商响应截止
Day 30: 修复补丁预计完成
Day 90: 公开披露截止
```

### 2. 记录通信

```bash
# 创建通信记录目录
mkdir -p ~/security-disclosure/openclaw-2026-03-12

# 保存邮件副本
cp REPORT-EMAIL.md ~/security-disclosure/openclaw-2026-03-12/

# 记录时间线
echo "2026-03-12: 初始报告已发送" > ~/security-disclosure/openclaw-2026-03-12/timeline.txt
```

### 3. 准备后续材料

如果厂商响应后，你可能需要提供：

1. **完整技术报告** - `docs/security/DISCLOSURE-ARTICLE.md`
2. **修复补丁代码** - `docs/security/SRECOMMENDATIONS.md`
3. **PoC 测试套件** - `test/poc-security-audit.test.ts`

---

## 紧急联系（备用）

如果主要邮箱无响应：

### GitHub Security Advisories
```
URL: https://github.com/openclaw/openclaw/security/advisories
创建: New Draft Security Advisory
```

### 联系维护者
```
查看 MAINTAINERS 或 SECURITY.md
找到项目负责人的联系方式
```

### Discord（如果有）
```
OpenClaw Discord 服务器
联系安全负责人或核心开发者
```

---

## 重要提醒

### ⚠️ 不要

- ❌ 在公开论坛讨论此漏洞
- ❌ 在社交媒体发布 PoC
- ❌ 向第三方透露漏洞详情
- ❌ 在厂商修复前公开披露

### ✅ 应该

- ✅ 保持与厂商的私下沟通
- ✅ 给予足够的修复时间（90天）
- ✅ 协调公开披露时间
- ✅ 记录所有通信

---

## 邮件模板使用说明

1. **打开** `docs/security/REPORT-EMAIL.md`
2. **填写** 你的信息
3. **复制** 全文到邮件客户端
4. **发送** 到 security@openclaw.ai
5. **保存** 发送记录

---

## 成功案例参考

类似的漏洞报告：
- Node.js npm 漏洞报告
- GitHub Actions 安全披露
- OWASP 负责任披露指南

参考这些案例可以帮助你了解：
- 邮件应该包含哪些信息
- 如何与厂商沟通
- 预期的响应时间
