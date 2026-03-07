# Kernel Recipes 2024

** Kernel Recipes 2024 - CVEs are alive, but no not panic!**

## 会议视频

* <https://www.youtube.com/watch?v=bf3MYWtI4E4&t=1329s>

## 会议纪要

![](./images/6315047516300.png)

![](./images/6373748202800.png)

**CNA**

**kernel.org（Linux 内核官方基础设施团队）现在正式成为了一家 CNA。**

1. 什么是 CNA？

**CNA** 全称是 **CVE Numbering Authority**（CVE 编号授权机构）。

背景知识：CVE 是什么？
*   **CVE** (Common Vulnerabilities and Exposures) 是全球通用的网络安全漏洞标识符系统。
*   每个被公开的漏洞都有一个唯一的 ID，格式为 `CVE-年份-序列号`（例如 `CVE-2024-1234`）。
*   这个系统由美国的 **CISA** (网络安全和基础设施安全局) 管理，具体运营由 **MITRE** 公司负责。

CNA 的角色
由于 MITRE 一家机构无法处理全球所有的漏洞编号，因此他们授权给各个主要的软件厂商、开源项目组织和安全研究机构，让它们拥有**直接分配 CVE 编号的权力**。这些被授权的机构就是 **CNA**。

**成为 CNA 意味着：**
1.  **自主权**：该机构可以直接为自己的产品或负责的项目分配 CVE 编号，不需要再向 MITRE 申请。
2.  **责任**：该机构负责定义漏洞的范围、分配编号、撰写初步描述，并确保信息及时公开。
3.  **权威性**：它是该领域漏洞信息的“官方源头”。

**常见的 CNA 包括：**
*   厂商类：Microsoft, Google, Apple, Red Hat, Cisco.
*   开源/社区类：Mozilla, Apache Software Foundation, **Linux Kernel (kernel.org)**.
*   协调类：GitHub, GitLab.

---

2. "kernel.org is now a CNA" 的具体含义

在此之前，Linux 内核的漏洞编号流程比较曲折：
*   **过去**：当发现一个内核漏洞时，报告者通常需要联系某个特定的下游厂商（如 Red Hat 或 Debian），或者通过非正式的渠道请求 MITRE 分配编号。这导致编号分配有时滞后，或者不同厂商对同一个漏洞使用了不同的描述，甚至出现编号冲突。
*   **现在**：**kernel.org 团队（代表 Linux 内核社区）直接成为了 CNA。**
    *   这意味着 Linux 内核安全团队（通常由 Greg Kroah-Hartman 等核心维护者领导）现在有权**直接签发** Linux 内核相关的 CVE 编号。
    *   他们是 Linux 内核漏洞信息的**唯一官方权威来源**。

---

3. 为什么这很重要？（深远影响）

这一变化标志着 Linux 内核安全响应机制的**成熟化**和**正规化**。

A. 更快的响应速度
不再需要等待第三方分配编号。一旦内核团队确认了一个漏洞，可以立即分配 CVE ID 并启动修复流程，缩短了从“发现”到“公开”的时间窗口。

B. 统一的事实来源 (Single Source of Truth)
以前，Red Hat 可能给某个漏洞定为 `CVE-2023-XXXX`，而 Debian 可能还在等编号，导致信息混乱。
现在，**kernel.org 分配的 CVE 是标准**。所有下游发行版（Ubuntu, SUSE, Android 等）都将引用 kernel.org 发布的官方 CVE 信息和修复状态。这极大地减少了混淆。

C. 更好的数据质量
作为 CNA，kernel.org 必须遵循严格的 CVE 记录标准（包括 CVSS 评分、受影响版本范围、修复提交哈希等）。这将迫使内核社区提供更结构化、更机器可读的漏洞数据（这就解释了你之前看到的 `dyad` 格式或其他自动化数据的来源趋势——社区正在构建自动化工具来配合 CNA 的工作）。

D. 提升生态系统的信任度
成为 CNA 表明 Linux 内核社区已经建立了一套成熟、可信赖的内部安全披露和修复流程，足以承担国家级基础设施的安全责任。

---

4. 对你之前问题的关联

你之前询问的 `dyad` 文件格式（`vulnerable:fixed pairs`），正是这种**CNA 时代**的产物。

*   **作为 CNA**，kernel.org 不仅要给出一个 CVE 编号，还要精确地告诉全世界：
    *   哪个版本开始受影响？
    *   哪个 Git Commit 修复了它？
    *   这个修复被回移植（backport）到了哪些 LTS 分支（5.10, 5.15, 6.1...）？
*   `dyad` 这种格式就是为了**机器自动化处理**这些精确的 CNA 数据而设计的。它让自动化工具能瞬间判断：“我的系统是 5.10.200，官方 CNA 数据显示 5.10.251 才修复，所以我现在是不安全的。”

**"kernel.org is now a CNA"** 意味着：
**Linux 内核社区正式拿回了漏洞定义的“话语权”和“发证权”。** 从此，Linux 内核的漏洞编号、描述和修复状态将由内核官方团队直接、统一、高效地发布，不再依赖外部机构。这是 Linux 安全生态走向高度成熟的重要里程碑。


![](./images/6581492313700.png)

* <https://docs.kernel.org/process/cve.html>
* <https://lore.kernel.org/linux-cve-announce>
* <https://git.kernel.org/pub/scm/linux/security/vulns.git>


![](./images/6702322831100.png)

![](./images/6718488284400.png)

kernel cve类型定义

边界检查（错误或者不存在）也定义为CVE！

![](./images/6756035607700.png)

WARNNING 标记为CVE ？

![](./images/6794699275200.png)

非CVE得边界定义

* 数据丢失并不是CVE？
* 性能问题不是CVE？


![](./images/7021493937200.png)

延迟发布，带修复补丁发布

![](./images/7073659886500.png)

不建议cherry pick补丁

![](./images/7085970495200.png)


![](./images/7148150127300.png)

硬件问题，不归属kernel cve，由硬件厂家找到对应内核分支修复。厂家偷懒不修复咋办？

![](./images/7196634331900.png)

![](./images/7301059203300.png)

分配CVE编号的流程

![](./images/7377825429300.png)

大概每周55个CVE

![](./images/7471488419200.png)


kernel的cve数量并不是nomber 1，参与挖掘的人少了？

![](./images/7656143691800.png)

持续增加是正常现象

![](./images/7726902838600.png)

![](./images/8967341738700.png)

不修复cve就违反政府规定

![](./images/8986861948500.png)


![](./images/9003889613500.png)

不更新，系统就是不稳定、不安全。

![](./images/9022912212600.png)


![](./images/9064516771600.png)


云服务器厂家无法周期性重启

![](./images/9110613533700.png)


![](./images/9141413043500.png)

![](./images/9193079872400.png)

![](./images/9208357617800.png)

![](./images/9214176303000.png)

![](./images/9270690116500.png)

让程序接受更新，让应用接受更新，让用户接受更新

1. 未修复问题无CVE编号
2. 数据丢失不是CVE，非社区规定


![](./images/9471051973900.png)

![](./images/9767954059600.png)


![](./images/9821076185000.png)


bippy 工具


![](./images/9842132092400.png)

strak 工具，显示目标版本受影响的CVE列表


![](./images/9899613610200.png)

![](./images/9925878591100.png)

同步生态

![](./images/9959218530900.png)

社区审计CVE，降低提交失败情况

![](./images/11417694543600.png)

企业版本承诺100年运维，没苦硬吃

![](./images/11582208691700.png)

红帽对kernel cve贡献巨大

完全按照cve.org来操作

因为部分法律约束，社区开始遵循cve.org的要求，对内核进行修复，但看现状是选择了部分lts版本进行修复

并非所有内核版本都会有cve修复 - 工作量巨大

















