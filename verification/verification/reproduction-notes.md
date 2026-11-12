# 冻结DER解码器复现说明

产物提交：fcccf013af6648e6b0fe11d57964205f09f17075。Windows，实际Python 3.14.3，未用容器，无运行期服务或网络。完整依赖和实际import路径在environment-reviewed.json。

检出产物提交；用同版Python建环境，安装environment-reviewed.json所列测试依赖，PYTHONPATH指向检出目录。verification各目录command.json保留真实argv，原机路径替换为检出位置及相应用例目录，保留所有断言。所有调用均针对冻结源码，演示控制台和demo_der.py为独立验证辅助工具，不是模型产品界面。

acceptance-r1包含DER包119通过和独立55通过。high-tag-header-r2为额外独立精确反例：1通过、2失败，分别为合法编码误拒、倒序漏拒。该fixture先断言官方未改encoder输出等于合法字节。两条失败为同一根因，不重复计分。

full-regression-r2真实结果1313 passed、6 failed、175 subtests passed；6项均在固定初始提交e24fa719428229db5efeb8aee74ce6d03329df5d独立复现，原件见initial-io-baseline-r1。上游mkstemp留下打开的fd，Windows删除文件产生WinError32，此范围不能称全部通过，也不计为本次新增缺陷。

原轨模型39项严格测试、聚合1319与本目录独立验收范围分开。12KB不可seek输入已独立验收；原轨167KB大流旧限制未由本次独立复现，不作为新缺陷。coverage/sphinx/bandit未运行。

recorded-runtime-r1保存75秒连续录屏中三个命令的实际argv、完成时间、原始输出和退出码[0,0,1]；全部在片内完成。原始JSONL只保存在飞书唯一轨迹附件，不另附公开轨迹。
