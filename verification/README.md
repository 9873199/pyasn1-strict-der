本目录保存冻结产物的独立验收原件。实际环境Windows、Python 3.14.3，未容器化，无运行期外部服务或网络。完整依赖、实际模块路径见environment-reviewed.json，复现步骤和测试范围见verification/reproduction-notes.md。检出frozen_commit，用同版Python建立环境并安装已记录测试依赖，PYTHONPATH指向检出目录。各子目录保留原始argv、输出、JUnit、退出码与用例；原机绝对路径需替换为本次检出位置，断言不改。原轨模型测试和独立验收分开；6项Windows回归错误已在固定初始提交复现，不计为模型新增缺陷。演示helper与控制台为独立验证工具。原始JSONL和75秒视频各一个保存在飞书字段，本公开目录不另放轨迹。

冻结产物提交：https://github.com/9873199/pyasn1-strict-der/commit/fcccf013af6648e6b0fe11d57964205f09f17075
这些独立验收文件在模型首轮结束后生成，不是模型原轨中的测试。
