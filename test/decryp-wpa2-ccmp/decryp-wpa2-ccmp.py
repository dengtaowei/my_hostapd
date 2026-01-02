import struct
import binascii
from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor


def decrypt_ccmp_python(h80211, caplen, TK1):
    """
    Python版本的CCMP解密算法
    """

    # 参数检查
    if h80211 is None or len(h80211) < caplen:
        return False

    # 判断是否为A4格式（To DS和From DS都为1）
    is_a4 = (h80211[1] & 3) == 3
    # 判断是否为QoS帧（Type=Data, Subtype=QoS Data）
    is_qos = (h80211[0] & 0x8C) == 0x88

    # 计算802.11头部长度
    z = 24 + 6 * is_a4  # 基本头部24字节 + 可选的A4字段
    z += 2 * is_qos  # QoS控制字段

    # 提取PN（Packet Number），注意字节序
    PN = bytearray(6)
    PN[0] = h80211[z + 7]
    PN[1] = h80211[z + 6]
    PN[2] = h80211[z + 5]
    PN[3] = h80211[z + 4]
    PN[4] = h80211[z + 1]
    PN[5] = h80211[z + 0]

    # 计算数据长度
    data_len = caplen - z - 8 - 8  # 总长度 - 头部 - CCMP头部 - MIC

    # 构造B0块
    B0 = bytearray(16)
    B0[0] = 0x59  # Flags: Adata=1, M=4(8字节MIC), L=1(2字节长度字段)
    B0[1] = 0  # Nonce flags (会被后续设置)

    # 复制A2地址（发送者地址）
    B0[2:8] = h80211[10:16]  # A2地址
    # 复制PN
    B0[8:14] = PN
    # 设置数据长度（大端序）
    B0[14] = (data_len >> 8) & 0xFF
    B0[15] = data_len & 0xFF

    # 构造AAD（Additional Authenticated Data）
    AAD = bytearray(32)
    # AAD[0..1] = l(a) 会在后面设置
    AAD[2] = h80211[0] & 0x8F  # FC字段的一部分
    AAD[3] = h80211[1] & 0xC7  # FC字段的另一部分

    # 复制地址字段 A1, A2, A3
    AAD[4:22] = h80211[4:22]
    AAD[22] = h80211[22] & 0x0F  # Sequence Control字段

    if is_a4:
        # 复制A4地址
        AAD[24:30] = h80211[24:30]

        if is_qos:
            # QoS情况
            qos_offset = z - 2
            AAD[30] = h80211[qos_offset] & 0x0F  # QoS控制字段
            AAD[31] = 0
            B0[1] = AAD[30]  # 设置Nonce flags
            # l(a) 设置
            aad_len = 22 + 2 + 6  # 22 + QC(2) + A4(6)
            AAD[0] = (aad_len >> 8) & 0xFF
            AAD[1] = aad_len & 0xFF
        else:
            # 非QoS但有A4
            AAD[30] = 0
            AAD[31] = 0
            B0[1] = 0
            # l(a) 设置
            aad_len = 22 + 6  # 22 + A4(6)
            AAD[0] = (aad_len >> 8) & 0xFF
            AAD[1] = aad_len & 0xFF
    else:
        # 没有A4
        if is_qos:
            qos_offset = z - 2
            AAD[24] = h80211[qos_offset] & 0x0F
            AAD[25] = 0
            B0[1] = AAD[24]
            # l(a) 设置
            aad_len = 22 + 2  # 22 + QC(2)
            AAD[0] = (aad_len >> 8) & 0xFF
            AAD[1] = aad_len & 0xFF
        else:
            # 既没有A4也没有QoS
            AAD[24] = 0
            AAD[25] = 0
            B0[1] = 0
            # l(a) 设置
            aad_len = 22  # 只有基本字段
            AAD[0] = (aad_len >> 8) & 0xFF
            AAD[1] = aad_len & 0xFF

    # 初始化AES加密上下文
    cipher = AES.new(TK1, AES.MODE_ECB)

    # 计算MIC: X_1 = E(K, B_0)
    MIC = bytearray(cipher.encrypt(bytes(B0)))

    # X_2 = E(K, X_1 XOR B_1) - B_1是AAD的前16字节
    for i in range(16):
        MIC[i] ^= AAD[i]
    MIC = bytearray(cipher.encrypt(bytes(MIC)))

    # X_3 = E(K, X_2 XOR B_2) - B_2是AAD的后16字节
    for i in range(16):
        MIC[i] ^= AAD[16 + i]
    MIC = bytearray(cipher.encrypt(bytes(MIC)))

    # 计算S_0用于解密MIC
    B0[0] &= 0x07  # 清除Adata位
    B0[14] = 0
    B0[15] = 0
    S0 = cipher.encrypt(bytes(B0))

    # 解密MIC（从报文中提取的MIC与S0异或）
    received_mic = h80211[caplen - 8:caplen]
    decrypted_mic = strxor(received_mic, S0[:8])

    # 解密数据部分
    blocks = (data_len + 15) // 16  # 向上取整
    last = data_len % 16
    offset = z + 8  # 加密数据的起始位置

    for i in range(1, blocks + 1):
        n = last if (last > 0 and i == blocks) else 16

        # 更新计数器
        B0[14] = (i >> 8) & 0xFF
        B0[15] = i & 0xFF

        # 计算S_i
        Si = cipher.encrypt(bytes(B0))

        # 解密数据块
        data_start = offset
        data_end = offset + n
        encrypted_block = h80211[data_start:data_end]
        decrypted_block = strxor(encrypted_block, Si[:n])

        # 将解密后的数据写回原位置
        h80211[data_start:data_end] = decrypted_block

        # 更新MIC计算
        for j in range(n):
            MIC[j] ^= decrypted_block[j]
        MIC = bytearray(cipher.encrypt(bytes(MIC)))

        offset += n

    # 比较计算出的MIC和解密出的MIC
    calculated_mic = MIC[:8]
    return calculated_mic == decrypted_mic


def decrypt_wpa2_packet(packet_data, TK1):
    """
    解密WPA2加密的802.11数据包
    packet_data: 完整的802.11数据包字节
    TK1: Temporal Key (16字节)
    """
    caplen = len(packet_data)

    # 将数据转换为bytearray以便修改
    packet = bytearray(packet_data)

    # 调用解密函数
    success = decrypt_ccmp_python(packet, caplen, TK1)

    if success:
        # 解密成功，返回解密后的数据
        # 移除CCMP头部和MIC
        is_a4 = (packet[1] & 3) == 3
        is_qos = (packet[0] & 0x8C) == 0x88
        header_len = 24 + 6 * is_a4 + 2 * is_qos

        # 解密后的数据从header_len开始，到caplen-8结束
        decrypted_data = packet[header_len:caplen - 8]
        return decrypted_data
    else:
        # 解密失败
        return None


# 测试代码
if __name__ == "__main__":
    # 测试数据 - 这里使用你的示例数据
    # 注意：你需要提供实际的加密数据包和TK

    # 示例TK（临时密钥）- 16字节
    TK1_hex = "30273eed9c521a1ca4b2513eb6c5d3e3"  # PTK的最后16字节
    TK1 = binascii.unhexlify(TK1_hex)

    # 示例加密数据包（这里需要实际的加密802.11帧）
    # 格式：802.11头部 + CCMP头部 + 加密数据 + MIC
    encrypted_packet_hex = (
        "884200000200000001000200000000000200000000000000000001000020000000007f92b3bd4d7782ddedaaad857d7bf3cacbb365ac27d8300a0d068e4e0b1b61f2b51e45f328390031d0b6f2062037ae252fac9d6663b5"  # MIC（这里需要实际MIC）
    )

    # 清理hex字符串
    encrypted_packet_hex = encrypted_packet_hex.replace(" ", "").replace("\n", "")

    try:
        encrypted_packet = binascii.unhexlify(encrypted_packet_hex)
        print(f"数据包长度: {len(encrypted_packet)} 字节")
        print(f"TK1: {TK1_hex}")

        # 解密
        decrypted = decrypt_wpa2_packet(encrypted_packet, TK1)

        if decrypted:
            print("解密成功!")
            print(f"解密数据 (hex): {binascii.hexlify(decrypted).decode()}")

            # 尝试解析为IP数据包
            if len(decrypted) >= 20:
                # 检查是否是IP数据包（以太网类型0x0800）
                if len(decrypted) >= 14 and decrypted[12:14] == b'\x08\x00':
                    ip_header = decrypted[14:]
                    print(f"IP数据包长度: {len(ip_header)} 字节")
        else:
            print("解密失败!")

    except Exception as e:
        print(f"错误: {e}")
        import traceback

        traceback.print_exc()