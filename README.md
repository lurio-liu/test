# GM0016 OpenSSL Engine

该示例实现了一个 OpenSSL Engine，用智能密码钥匙 **GM0016** 的厂商接口替换 OpenSSL 中的：

- SM2（签名/验签、加密/解密）
- SM3（摘要）
- SM4（示例中实现 `SM4-CBC`）
- RAND（随机数生成）

## 文件说明

- `gm0016_api.h`：GM0016 厂商 SDK 接口声明（需与真实 SDK 对齐）。
- `gm0016_engine.c`：Engine 实现，注册 SM2/SM3/SM4/RAND 到 OpenSSL。

## 编译（动态 Engine）

> 需要 OpenSSL 开发头文件与库。

```bash
gcc -fPIC -shared -O2 -Wall -Wextra -pedantic \
  gm0016_engine.c -o gm0016_engine.so \
  -I/usr/include -lcrypto
```

## 使用示例

```bash
export OPENSSL_ENGINES=$(pwd)
openssl engine -t -c gm0016_engine
```

## 对接说明

1. 将 `gm0016_api.h` 中的函数签名替换为你的 GM0016 SDK 实际签名。
2. 在 `gm0016_engine.c` 中把当前回调内的调用映射到真实设备会话、密钥句柄和错误码。
3. 按需扩展更多 SM4 模式（ECB/CTR/GCM 等）和更完整的 SM2 控制参数流程。

## 注意

- Engine 接口在 OpenSSL 3.x 中已进入兼容层，生产环境建议评估 Provider 方案。
- 本示例重点演示“替换入口”和回调绑定结构。实际落地需要补全设备登录、会话管理、并发、错误码映射和资源回收。
