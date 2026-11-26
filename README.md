用户把密码改了五次又改回原来那个，历史校验一次都没拦住，复用直接成功：历史必须保留最近若干次口令的哈希；新口令不得与历史中任何一条相同；历史长度必须有上限并按先进先出淘汰；比较必须基于哈希且恒时；历史变更必须与口令更新同时生效；批量校验各请求独立。不变量：历史窗口内的口令永远无法被复用；历史条数不超过上限。

## 数据结构契约

store 是字典，键为账号名，值为一条记录。记录包含两个字段：digest 保存当前口令的摘要，history 保存最近若干次口令的摘要，按从旧到新的顺序排列，最新一条与当前摘要相同。

params 是哈希参数，包含 algo（算法名）、iterations（迭代次数）和 salt（盐字符串）。

policy 是口令策略，包含 algo、min_iterations、max_history、require_salt 和 allow_plaintext。

摘要为自描述字符串，包含算法名、迭代次数、盐和十六进制摘要，四段之间以美元符号分隔，例如 pbkdf2_sha256$120000$some-salt$9f86d081884c7d65。

## 接口

- hash_password(password, salt, params) -> str
- load_history(store, account, limit) -> list
- check_reuse(password, history) -> bool
- push_history(store, account, digest, limit) -> dict
- check_params(params, policy) -> bool
- change_password(store, account, new_password, params, limit) -> dict
- validate_policy(policy) -> list[str]
- history_batch(requests, store) -> dict

history_batch 接收请求列表，每个请求包含 account、password 和 limit 三个字段，返回结果包含 results 列表，每项含有 account 和 reuse。

## 测试

    python -m pytest tests -q

公开测试当前全部失败。除公开测试之外还有未公开的验收测试，接口与数据结构契约保持不变。

## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |

