import hashlib
import hmac
import os
import struct
import binascii
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def decrypt_ccmp_auth(tk, nonce, aad, ciphertext, received_mic):
    """
    使用AES-CCM解密并验证MIC
    """
    backend = default_backend()

    # 注意：cryptography库的CCM需要tag在密文前面
    # 所以我们需要重新构造数据

    # 合并密文和MIC
    ciphertext_with_tag = ciphertext + received_mic

    try:
        # 创建解密器
        cipher = Cipher(algorithms.AES(tk), modes.CCM(nonce, tag=received_mic), backend=backend)
        decryptor = cipher.decryptor()

        # 添加关联数据
        decryptor.authenticate_additional_data(aad)

        # 解密
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        print("\n✓ 解密成功!")
        print(f"✓ MIC验证通过")

        return plaintext

    except Exception as e:
        print(f"\n✗ 解密失败: {e}")

        # 尝试诊断问题
        print("\n诊断信息:")
        print(f"TK长度: {len(tk)} 字节")
        print(f"Nonce长度: {len(nonce)} 字节")
        print(f"AAD长度: {len(aad)} 字节")
        print(f"密文长度: {len(ciphertext)} 字节")
        print(f"MIC长度: {len(received_mic)} 字节")

        # 常见问题检查
        if len(tk) != 16:
            print("错误: TK应该是16字节")
        if len(nonce) != 13:
            print("错误: CCMP Nonce应该是13字节")

        return None

def decrypt_ccmp_payload(frame_hex, msg1_hex, msg2_hex, ssid, password, sta_mac,
            ap_mac):
    """
    解密Wireshark抓取的完整802.11帧
    """
    # 转换完整帧
    frame_bytes = bytes.fromhex(frame_hex.replace(' ', '').replace('\n', ''))

    # 1. 解析Radiotap头部
    radiotap_len = struct.unpack('<H', frame_bytes[2:4])[0]
    print(f"Radiotap头部长度: {radiotap_len} 字节")

    # 2. 解析802.11头部
    wifi_header_start = radiotap_len
    wifi_header = frame_bytes[wifi_header_start:wifi_header_start + 24]

    # 解析802.11头部字段
    frame_control = struct.unpack('<H', wifi_header[0:2])[0]
    duration = struct.unpack('<H', wifi_header[2:4])[0]

    # 地址字段
    address1 = wifi_header[4:10]  # RA (接收方)
    address2 = wifi_header[10:16]  # TA (发送方)
    address3 = wifi_header[16:22]  # BSSID
    seq_ctrl = struct.unpack('<H', wifi_header[22:24])[0]

    # 序列号从序列控制字段提取
    sequence_number = (seq_ctrl >> 4) & 0xFFF

    print(f"帧控制: 0x{frame_control:04x}")
    print(f"地址1 (RA): {address1.hex(':')}")
    print(f"地址2 (TA): {address2.hex(':')}")
    print(f"地址3 (BSSID): {address3.hex(':')}")
    print(f"序列号: {sequence_number}")

    # 3. 检查是否有QoS字段
    if frame_control & 0x0080:  # QoS数据帧
        qos_ctrl = struct.unpack('<H', frame_bytes[wifi_header_start + 24:wifi_header_start + 26])[0]
        tid = qos_ctrl & 0x000F  # 流量标识符
        print(f"QoS TID: {tid}")
        ccmp_start = wifi_header_start + 26
    else:
        ccmp_start = wifi_header_start + 24

    # 4. 提取CCMP头部和加密数据
    ccmp_data = frame_bytes[ccmp_start:]

    # CCMP头部: [PN(6)][ExtIV(1)][KeyID(1)]
    if len(ccmp_data) < 8:
        raise ValueError("CCMP数据太短")

    pn = ccmp_data[:6]  # 包编号
    ext_iv = ccmp_data[6]
    key_id = ccmp_data[7] & 0x03

    print(f"\nCCMP头部:")
    print(f"  PN: {pn.hex()} (小端序)")
    print(f"  Ext IV: 0x{ext_iv:02x}")
    print(f"  Key ID: {key_id}")

    # 加密数据 + MIC
    encrypted_with_mic = ccmp_data[8:]

    # MIC是最后8字节
    if len(encrypted_with_mic) < 8:
        raise ValueError("加密数据太短，无法包含MIC")

    ciphertext = encrypted_with_mic[:-8]
    received_mic = encrypted_with_mic[-8:]

    print(f"密文长度: {len(ciphertext)} 字节")
    print(f"接收到的MIC: {received_mic.hex()}")

    # 5. 从握手推导TK

    tk = derive_tk_from_handshake(msg1_hex, msg2_hex, ssid, password, sta_mac, ap_mac)
    print(f"\n推导出的TK: {tk.hex()}")

    # 6. 构造CCMP解密参数
    # 对于FromDS=1的数据帧：
    # A1 = RA = STA地址
    # A2 = TA = AP地址
    # A3 = BSSID = AP地址

    # CCMP Nonce构造
    # Flag字节: 优先级(3 bits) + 保留(1 bit) + A2类型(1 bit) + A4类型(1 bit) + 保留(2 bits)
    # 对于QoS数据帧，Flag = 0x01 (优先级0) 或根据TID调整

    priority = tid if (frame_control & 0x0080) else 0
    flag = 0x01 | (priority << 3)  # 设置优先级位

    # PN需要转换为大端序用于Nonce
    pn_be = pn[::-1]  # 小端转大端

    # CCMP Nonce: [Flag(1)][A2(6)][PN(6)][优先级(1)]
    ccmp_nonce = bytes([flag]) + address2 + pn_be + bytes([priority])
    print(f"CCMP Nonce: {ccmp_nonce.hex()}")

    # 7. 构造AAD (Additional Authenticated Data)
    # 对于受保护的数据帧，AAD包括802.11头部但不包括CCMP头部

    # 构造帧控制字段（清除Protected位用于AAD）
    fc_aad = frame_control & ~0x4000  # 清除Protected位

    if frame_control & 0x0080:  # QoS帧
        # AAD: FC(2) | Dur | A1 | A2 | A3 | Seq | QoS(2)
        aad = (
                struct.pack('<H', fc_aad) +
                struct.pack('<H', duration) +
                address1 +  # RA
                address2 +  # TA
                address3 +  # BSSID
                struct.pack('<H', seq_ctrl) +
                struct.pack('<H', qos_ctrl)
        )
    else:
        # 非QoS帧
        aad = (
                struct.pack('<H', fc_aad) +
                struct.pack('<H', duration) +
                address1 +  # RA
                address2 +  # TA
                address3 +  # BSSID
                struct.pack('<H', seq_ctrl)
        )

    print(f"AAD长度: {len(aad)} 字节")
    print(f"AAD: {aad.hex()}")

    # 8. 解密数据
    plaintext = decrypt_ccmp_auth(tk, ccmp_nonce, aad, ciphertext, received_mic)

    return plaintext, {
        'pn': pn,
        'sequence_number': sequence_number,
        'address1': address1,
        'address2': address2,
        'address3': address3,
        'tk': tk
    }
def derive_tk_from_handshake(msg1_hex, msg2_hex, ssid, password, sta_mac, ap_mac):
    """从握手消息推导TK（临时密钥）"""
    # 解析Msg1获取AP Nonce
    msg1_bytes = bytes.fromhex(msg1_hex.replace(' ', '').replace('\n', ''))
    ap_nonce = msg1_bytes[0x11:0x11 + 32]  # 从0x11开始，32字节
    replay_counter = msg1_bytes[0x09:0x09 + 8]

    # 解析Msg2获取STA Nonce
    msg2_bytes = bytes.fromhex(msg2_hex.replace(' ', '').replace('\n', ''))
    sta_nonce = msg2_bytes[0x11:0x11 + 32]

    # 计算PMK
    pmk = hashlib.pbkdf2_hmac('sha1',
                              password.encode('utf-8'),
                              ssid.encode('utf-8'),
                              4096,
                              32)

    # 计算PTK
    ptk = calculate_ptk(pmk, ap_mac, sta_mac, binascii.hexlify(ap_nonce).decode(), binascii.hexlify(sta_nonce).decode())

    # TK是PTK的第33-48字节（从0开始计数）
    tk = ptk[32:48]
    return tk


def predict_handshake(msg1_hex, msg2_hex, ssid, password, sta_mac, ap_mac):
    """
    从Msg1预测Msg2, Msg3, Msg4
    """
    # 解析Msg1
    msg1_bytes = bytes.fromhex(msg1_hex.replace(' ', '').replace('\n', ''))

    # 提取AP Nonce (从偏移量0x13开始，32字节)
    ap_nonce = msg1_bytes[0x11:0x11 + 32]
    replay_counter = msg1_bytes[0x09:0x09 + 8]

    # 1. 计算Pairwise Master Key (PMK)
    pmk = pbkdf2_sha1(password, ssid, 4096, 32)

    # 解析Msg2获取STA Nonce和实际MIC
    msg2_bytes = bytes.fromhex(msg2_hex.replace(' ', '').replace('\n', ''))
    sta_nonce = msg2_bytes[0x11:0x11 + 32]

    # 3. 计算Pairwise Transient Key (PTK)
    ptk = calculate_ptk(pmk, ap_mac, sta_mac, binascii.hexlify(ap_nonce).decode(), binascii.hexlify(sta_nonce).decode())

    # PTK分解
    kck = ptk[0:16]  # Key Confirmation Key (用于计算MIC)
    kek = ptk[16:32]  # Key Encryption Key (用于加密Key Data)
    tk = ptk[32:48]  # Temporal Key (实际加密数据的密钥)

    # 4. 构造Msg2
    msg2 = construct_msg2(sta_nonce, replay_counter, kck, ap_mac, sta_mac)

    # 5. 构造Msg3
    gtk = os.urandom(32)  # 实际中GTK由AP生成
    encrypted_gtk = encrypt_gtk_simple(gtk, kek)
    msg3 = construct_msg3(ap_nonce, int.from_bytes(replay_counter, 'big') + 1,
                          kck, encrypted_gtk, ap_mac, sta_mac)

    # 6. 构造Msg4
    msg4 = construct_msg4(int.from_bytes(replay_counter, 'big') + 1,
                          kck, ap_mac, sta_mac)

    return msg2, msg3, msg4, sta_nonce, kck


def pbkdf2_sha1(password, ssid, iterations, key_len):
    """计算PMK = PBKDF2(HMAC-SHA1, password, ssid, 4096, 256)"""
    return hashlib.pbkdf2_hmac('sha1',
                               password.encode('utf-8'),
                               ssid.encode('utf-8'),
                               iterations,
                               key_len)

def _ensure_bytes_mac(mac):
    if isinstance(mac, str):
        return binascii.unhexlify(mac.replace(':', '').replace(' ', ''))
    return mac
def calculate_ptk(pmk, ap_mac, sta_mac, anonce_hex, snonce_hex):

    anonce_hex = anonce_hex.replace(' ', '').replace(':', '').lower()
    snonce_hex = snonce_hex.replace(' ', '').replace(':', '').lower()

    anonce = binascii.unhexlify(anonce_hex)
    snonce = binascii.unhexlify(snonce_hex)

    """计算PTK"""
    # 确定MAC地址顺序
    ap_mac_bytes = _ensure_bytes_mac(ap_mac)
    client_mac_bytes = _ensure_bytes_mac(sta_mac)
    if ap_mac_bytes < client_mac_bytes:
        min_mac, max_mac = ap_mac_bytes, client_mac_bytes
    else:
        min_mac, max_mac = client_mac_bytes, ap_mac_bytes

    # 确定Nonce顺序
    if anonce < snonce:
        min_nonce, max_nonce = anonce, snonce
    else:
        min_nonce, max_nonce = snonce, anonce

    # 构造种子
    seed = b"Pairwise key expansion" + b'\x00'

    # 构造数据
    data = min_mac + max_mac + min_nonce + max_nonce

    print(f"data: {binascii.hexlify(data).decode()}")

    # 使用PRF计算PTK
    ptk = b''
    i = 0
    for i in range(4):
        h = hmac.new(pmk, seed + data + bytes([i]), hashlib.sha1)
        ptk += h.digest()

    return ptk[:48]


def construct_msg2(sta_nonce, replay_counter, kck, ap_mac, sta_mac):
    """构造Msg2 EAPOL-Key帧"""
    # EAPOL头部
    eapol_version = b'\x01\x03'
    eapol_type = b'\x00\x75'  # 长度117

    # Key Descriptor
    key_desc_type = b'\x02'
    key_info = b'\x01\x0a'  # MIC=1, Ack=1, Encrypted=1

    # Key Data (RSN IE)
    key_data = bytes.fromhex('30140100000fac040100000fac040100000fac020000')

    # 构造未签名的Msg2
    msg2_no_mic = (
            eapol_version + eapol_type +
            key_desc_type + key_info +
            b'\x00\x00' +  # Key Length (16)
            replay_counter +  # Replay Counter
            sta_nonce +  # STA Nonce
            b'\x00' * 16 +  # Key IV (全0)
            b'\x00' * 8 +  # Key RSC (全0)
            b'\x00' * 8 +  # Key ID (全0)
            b'\x00' * 16 +  # MIC占位符
            struct.pack('>H', len(key_data)) +  # Key Data Length
            key_data
    )

    print(f"msg2_no_mic: {binascii.hexlify(msg2_no_mic).decode()}")

    # 计算MIC
    mic = calculate_mic(kck, msg2_no_mic, ap_mac, sta_mac)

    # 替换MIC
    msg2 = bytearray(msg2_no_mic)
    mic_offset = 81  # MIC在Msg2中的偏移量
    msg2[mic_offset:mic_offset + 16] = mic

    return bytes(msg2)


def calculate_mic(kck, eapol_frame, src_mac, dst_mac):

    # 计算MIC (HMAC-SHA1)
    h = hmac.new(kck, eapol_frame, hashlib.sha1)
    return h.digest()[:16]


def encrypt_gtk_simple(gtk, kek):
    """简化版GTK加密 (仅用于演示)"""
    # 实际应使用AES Key Wrap (RFC 3394)
    # 这里使用AES-ECB简单加密
    backend = default_backend()
    cipher = Cipher(algorithms.AES(kek), modes.ECB(), backend=backend)
    encryptor = cipher.encryptor()

    # GTK需要填充到16字节边界
    if len(gtk) % 16 != 0:
        padding = 16 - (len(gtk) % 16)
        gtk += bytes([padding] * padding)

    return encryptor.update(gtk) + encryptor.finalize()


def construct_msg3(ap_nonce, replay_counter_inc, kck, encrypted_gtk, ap_mac, sta_mac):
    """构造Msg3 EAPOL-Key帧"""
    # EAPOL头部
    eapol_version = b'\x02\x03'
    eapol_type = b'\x00\x97'  # 长度151

    # Key Descriptor
    key_desc_type = b'\x02'
    key_info = b'\x13\xca'  # MIC=1, Secure=1, Install=1, Ack=1

    encrypted_gtk = bytes.fromhex('5422b315c194cd17a04d49dab0243170ff5b8ca5ec7f51a98a34b94b924c22933a45538f163e4d57f56d56af7198dd7c152076b8ca6f7ec3')

    # 构造未签名的Msg3
    msg3_no_mic = (
            eapol_version + eapol_type +
            key_desc_type + key_info +
            b'\x00\x10' +  # Key Length
            struct.pack('>Q', replay_counter_inc) +  # Replay Counter
            ap_nonce +  # AP Nonce (与Msg1相同)
            b'\x00' * 16 +  # Key IV
            b'\x00' * 8 +  # Key RSC
            b'\x00' * 8 +  # Key ID (全0)
            b'\x00' * 16 +  # MIC占位符
            struct.pack('>H', len(encrypted_gtk)) +  # Key Data Length
            encrypted_gtk
    )

    print(f"msg3_no_mic: {binascii.hexlify(msg3_no_mic).decode()}")

    # 计算MIC
    mic = calculate_mic(kck, msg3_no_mic, ap_mac, sta_mac)

    # 替换MIC
    msg3 = bytearray(msg3_no_mic)
    mic_offset = 81  # MIC在Msg3中的偏移量
    msg3[mic_offset:mic_offset + 16] = mic

    return bytes(msg3)


def construct_msg4(replay_counter_inc, kck, ap_mac, sta_mac):
    """构造Msg4 EAPOL-Key帧"""
    # EAPOL头部
    eapol_version = b'\x01\x03'
    eapol_type = b'\x00\x5f'  # 长度95

    # Key Descriptor
    key_desc_type = b'\x02'
    key_info = b'\x03\x0a'  # MIC=1, Secure=1, Ack=1

    # 构造未签名的Msg4
    msg4_no_mic = (
            eapol_version + eapol_type +
            key_desc_type + key_info +
            b'\x00\x00' +  # Key Length
            struct.pack('>Q', replay_counter_inc) +  # Replay Counter
            b'\x00' * 32 +  # WPA Key Nonce (全0)
            b'\x00' * 16 +  # Key IV
            b'\x00' * 8 +  # Key RSC
            b'\x00' * 8 +  # Key ID (全0)
            b'\x00' * 16 +  # MIC占位符
            b'\x00\x00'  # Key Data Length (0)
    )

    print(f"msg4_no_mic: {binascii.hexlify(msg4_no_mic).decode()}")

    # 计算MIC
    mic = calculate_mic(kck, msg4_no_mic, ap_mac, sta_mac)

    # 替换MIC
    msg4 = bytearray(msg4_no_mic)
    mic_offset = 81  # MIC在Msg4中的偏移量
    msg4[mic_offset:mic_offset + 16] = mic

    return bytes(msg4)


def verify_password_from_capture(msg1_hex, msg2_hex, ssid, password, sta_mac, ap_mac):
    """验证密码是否正确"""
    # 解析Msg1获取AP Nonce
    msg1_bytes = bytes.fromhex(msg1_hex.replace(' ', '').replace('\n', ''))
    ap_nonce = msg1_bytes[0x11:0x11 + 32]
    replay_counter = msg1_bytes[0x09:0x09 + 8]

    # 解析Msg2获取STA Nonce和实际MIC
    msg2_bytes = bytes.fromhex(msg2_hex.replace(' ', '').replace('\n', ''))
    sta_nonce = msg2_bytes[0x11:0x11 + 32]
    actual_mic = msg2_bytes[81:97]

    # 计算PMK
    pmk = pbkdf2_sha1(password, ssid, 4096, 32)
    print(f"PMK: {binascii.hexlify(pmk).decode()}")

    # 计算PTK
    ptk = calculate_ptk(pmk, ap_mac, sta_mac, binascii.hexlify(ap_nonce).decode(), binascii.hexlify(sta_nonce).decode())
    kck = ptk[0:16]
    print(f"PTK: {binascii.hexlify(ptk).decode()}")
    print(f"KCK: {binascii.hexlify(kck).decode()}")

    # 重新构造Msg2（使用捕获的STA Nonce）
    test_msg2 = construct_msg2(sta_nonce, replay_counter, kck, ap_mac, sta_mac)
    predicted_mic = test_msg2[81:97]

    # 比较MIC
    return actual_mic == predicted_mic, actual_mic.hex(), predicted_mic.hex()


# 主程序
if __name__ == "__main__":
    # 输入参数
    ssid = "TestAP"
    password = "testpassword123"
    sta_mac = bytes.fromhex("020000000100")
    ap_mac = bytes.fromhex("020000000000")

    # Msg1十六进制
    msg1_hex = """
    02 03 00 5f 02 00 8a 00 10 00 00 00 00 00 00 00
    01 e5 d1 4c 5e cf a8 21 ab 61 a7 e2 48 f7 c9 6e
    1b 07 03 c6 ef fe 8a 35 eb 2d ce a9 bb ea 1f 2d
    d5 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00
    """

    # Msg2十六进制（用于验证）
    msg2_hex = """
    01 03 00 75 02 01 0a 00 00 00 00 00 00 00 00 00
    01 ca d1 22 a5 4a 6f 31 c8 d3 a4 6b 34 ca 5e b2
    ee 09 ba 7f 60 5b 66 93 61 c9 97 a6 eb e2 b9 b9
    67 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 c3 38 03 7a a7 71 a0 ba 43 84 75 95 c5 2c 8e
    53 00 16 30 14 01 00 00 0f ac 04 01 00 00 0f ac
    04 01 00 00 0f ac 02 00 00
    """

    print("=== WPA2握手预测与验证 ===\n")

    # 1. 验证密码
    is_valid, actual_mic, predicted_mic = verify_password_from_capture(
        msg1_hex, msg2_hex, ssid, password, sta_mac, ap_mac
    )

    print(f"密码验证结果: {'正确' if is_valid else '错误'}")
    print(f"实际MIC:   {actual_mic}")
    print(f"预测MIC:   {predicted_mic}")

    if is_valid:
        print("\n✓ 密码正确，可以预测后续消息\n")

        # 2. 预测完整握手
        msg2_pred, msg3_pred, msg4_pred, sta_nonce_pred, kck_pred = predict_handshake(
            msg1_hex, msg2_hex, ssid, password, sta_mac, ap_mac
        )

        print(f"预测的STA Nonce: {sta_nonce_pred.hex()[:16]}...")
        print(f"预测的KCK: {kck_pred.hex()[:16]}...")
        print(f"\nMsg2长度: {len(msg2_pred)} 字节")
        print(f"Msg3长度: {len(msg3_pred)} 字节")
        print(f"Msg4长度: {len(msg4_pred)} 字节")

        # 3. 显示预测的MIC
        print(f"\n预测Msg2 MIC: {msg2_pred[81:97].hex()}")
        print(f"预测Msg3 MIC: {msg3_pred[81:97].hex()}")
        print(f"预测Msg4 MIC: {msg4_pred[81:97].hex()}")
    else:
        print("\n✗ 密码错误，无法预测后续消息")
        print("提示：请检查SSID和密码是否正确")