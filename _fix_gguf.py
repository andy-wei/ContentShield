"""二进制 patch 修复 Llama-Guard-4 GGUF 的 MoE 元数据错误。

GGUF 元数据 KV 存储格式（小端）：
  [key_len:u64][key_bytes][value_type:u32][value_bytes]

问题：转换工具把稠密模型错误写入了
  expert_count=0, expert_used_count=1
触发：
  - GGML_ASSERT(n_expert_used <= n_expert)  → 1 <= 0 失败
  - "llama4 model cannot have zero experts"  → expert_count=0

修复策略：把两个字段都改为 1（满足 MoE 约束：1 个专家，激活 1 个）。
llama.cpp 会把它当单专家 MoE 处理，数学上等价于稠密 FFN。
"""
import struct
import sys

SRC = "/Users/wayne/ZCodeProject/models/meta-llama.Llama-Guard-4-12B.f16.gguf"
DST = "/Users/wayne/ZCodeProject/models/meta-llama.Llama-Guard-4-12B.f16.fixed.gguf"

# 要 patch 的 (key_bytes, new_value_u32)
PATCHES = [
    (b"llama4.expert_count", 1),          # 0 → 1
    (b"llama4.expert_used_count", 1),     # 已经是 1，保持（确保一致）
]


def find_kv_value_offset(data: bytes, key: bytes) -> int | None:
    """定位某个 KV 的 value 起始偏移。"""
    key_len = len(key)
    key_len_bytes = struct.pack("<Q", key_len)
    pattern = key_len_bytes + key
    idx = data.find(pattern)
    if idx == -1:
        return None
    value_type_offset = idx + len(pattern)
    value_type = struct.unpack("<I", data[value_type_offset:value_type_offset + 4])[0]
    assert value_type == 4, f"expected UINT32(4) for {key!r}, got {value_type}"
    return value_type_offset + 4


def main():
    print(f"读取 {SRC} ...")
    with open(SRC, "rb") as f:
        data = bytearray(f.read())
    print(f"文件大小: {len(data) / 1e9:.2f} GB\n")

    for key, new_value in PATCHES:
        offset = find_kv_value_offset(data, key)
        if offset is None:
            print(f"❌ 未找到 key: {key!r}")
            sys.exit(1)
        old_value = struct.unpack("<I", data[offset:offset + 4])[0]
        print(f"  {key.decode():35} @ {offset:6}  {old_value} → {new_value}", end="")
        struct.pack_into("<I", data, offset, new_value)
        verify = struct.unpack("<I", data[offset:offset + 4])[0]
        assert verify == new_value, "patch verify failed"
        print("  ✅")

    print(f"\n写入 {DST} ...")
    with open(DST, "wb") as f:
        f.write(data)
    print(f"✅ 完成。{len(data) / 1e9:.2f} GB")
    print("\n下一步测试：")
    print(f"  llama-server --model {DST} --gpu-layers 999 --port 8082 --jinja --fit off")


if __name__ == "__main__":
    main()
