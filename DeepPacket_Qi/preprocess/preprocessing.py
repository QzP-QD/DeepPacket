# 将原始数据集按照论文步骤转化

# 移除报头
# 用0填充UDP，使其包头长度到20字节，和TCP等长
# 掩盖IP包头中的IP地址
# 移除不相关的包（无负载，DNS包等）
# 原始数据包转化为字节向量
# 截断、填充0，将包大小调整为1500字节
# 将每个元素除以255规范字节向量

from pathlib import Path
from re import A

import click
import numpy as np
import pandas as pd
from joblib import Parallel, delayed

from scapy.compat import raw
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Padding
from scipy import sparse

from utils import should_omit_packet , PREFIX_TO_APP_ID, PREFIX_TO_TRAFFIC_ID

def remove_ether_header(packet):
    if Ether in packet:
        return packet[Ether].payload
    
    return packet

def mask_ip(packet):
    if IP in packet:
        packet[IP].src = '0.0.0.0'
        packet[IP].dst = '0.0.0.0'
    
    return packet

def pad_udp(packet):
    if UDP in packet:
        # 获取UDP下一层的数据
        layer_after = packet[UDP].payload.copy()

        # 创建一个填充层
        pad = Padding()
        pad.load = '\x00' * 12

        layer_before = packet.copy()
        layer_before[UDP].remove_payload()
        packet = layer_before / pad / layer_after

        return packet
    
    return packet

def packet_to_sparse_array(packet, max_length=1500):
    arr = np.frombuffer(raw(packet), dtype = np.uint8)[0: max_length]
    if len(arr) < max_length:
        pad_width = max_length - len(arr)
        arr = np.pad(arr, pad_width=(0, pad_width), constant_values = 0)
    
    arr = sparse.csr_matrix(arr)
    return arr

def transform_packet(packet):
    if should_omit_packet(packet):
        return None
    
    packet = remove_ether_header(packet)
    packet = pad_udp(packet)
    packet = mask_ip(packet)

    arr = packet_to_sparse_array(packet)

    return arr