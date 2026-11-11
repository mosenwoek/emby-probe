#!/usr/bin/env bash
# Emby 反代节点综合体检 — 一键版 v3.1
# 用法:
#   bash emby-probe.sh                                    # 交互: 逐个输入 Emby 地址
#   bash emby-probe.sh "http://a:8096" "https://b" ...    # 参数: 一次测多个地址
#   EMBY_LIST="http://a:8096 https://b" bash emby-probe.sh
# 可选: PROBE_MEDIA="https://.../file.mkv"  用真实媒体测带宽（对所有地址生效）
set -u
C_G=$'\033[32m'; C_R=$'\033[31m'; C_Y=$'\033[33m'; C_B=$'\033[36m'; C_0=$'\033[0m'; C_BD=$'\033[1m'
LINE="$(printf '%.0s─' {1..50})"
MEDIA="${PROBE_MEDIA:-}"
PY=python3

# 数值比较辅助: num_lt A B  → A < B 时返回 0
num_lt() { awk -v a="$1" -v b="$2" 'BEGIN{exit !(a+0 < b+0)}'; }

# ---------- 收集地址列表 ----------
ADDRS=()
if [ $# -gt 0 ]; then ADDRS=("$@"); fi
if [ ${#ADDRS[@]} -eq 0 ] && [ -n "${EMBY_LIST:-}" ]; then ADDRS=($EMBY_LIST); fi
if [ ${#ADDRS[@]} -eq 0 ]; then
  # curl|bash 时 stdin 是脚本自身, 交互输入必须改从 /dev/tty 读
  if exec 3</dev/tty 2>/dev/null; then
    echo -e "${C_BD}Emby 反代节点体检${C_0} — 输入 Emby 地址（空行开始测试, q 退出）"
    i=1
    while :; do
      read -r -p "  地址 #$i: " a <&3 || break
      a=$(printf '%s' "$a" | tr -d '\r')
      [ -z "$a" ] && break
      [ "$a" = q ] && exit 0
      ADDRS+=("$a"); i=$((i+1))
    done
    exec 3<&-
  else
    echo "交互输入不可用(无终端), 请用参数形式: curl -fsSL <本脚本URL> | bash -s \"http://emby:8096\""
    exit 1
  fi
fi
[ ${#ADDRS[@]} -eq 0 ] && { echo "没有地址, 退出"; exit 1; }

# ---------- 单地址完整体检 ----------
probe_one() {
  local EMBY="$1"
  echo; echo -e "${C_BD}${LINE}${C_0}"
  echo -e "${C_BD}◈ $EMBY${C_0}"
  echo "${LINE}"

  local SCORE_OK=0

  # 0. 本机身份
  echo -e "${C_B}◆ 出口身份${C_0}"
  local IPINFO=$(curl -s --max-time 6 https://ipinfo.io/json 2>/dev/null)
  if [ -n "$IPINFO" ]; then
    printf '%s' "$IPINFO" | $PY -c "
import json,sys
d=json.load(sys.stdin)
print(f\"  IP: {d.get('ip')}  ({d.get('city','')}, {d.get('country')})  {d.get('org','')}\")" 2>/dev/null || \
      echo "  (身份解析失败)"
  else
    echo "  出口 IP: $(curl -s --max-time 6 https://api.ipify.org 2>/dev/null || echo 未知)"
  fi

  # 1. TCP/TLS
  echo -e "${C_B}◆ 握手延迟（3次取最优）${C_0}"
  local BEST_TCP=99
  for i in 1 2 3; do
    local T=$(curl -o /dev/null -s -w "%{time_connect}" --max-time 6 "$EMBY/emby/system/info/public" 2>/dev/null) || T=99
    [ -z "$T" ] && T=99
    num_lt "$T" "$BEST_TCP" && BEST_TCP=$T
  done
  if num_lt "$BEST_TCP" 90; then
    echo "  TCP: ${BEST_TCP}s"
    num_lt "$BEST_TCP" 0.1 && echo -e "  ${C_G}✓ 链路延迟优秀${C_0}"
  else
    echo -e "  ${C_R}✗ TCP 握手失败 — 端口不通或被墙${C_0}"
    echo -e "  ${C_BD}结论: ✗ 不可用${C_0}"; return 1
  fi

  # 2. API 连通 / 封禁检测
  echo -e "${C_B}◆ API 连通 + 封禁检测（5次）${C_0}"
  local OK=0; local BEST_TTFB=99
  local BODY=/tmp/probe_body.$$
  # 部分源站有 WAF/防护, 会拦 curl 默认 UA（"请求携带恶意参数已被拦截"）— 用浏览器 UA 试探
  for i in 1 2 3 4 5; do
    local R=$(curl -o "$BODY" -s -w "%{http_code} %{time_starttransfer}" \
      -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0.0.0 Safari/537.36" \
      -L --max-redirs 3 --max-time 8 "$EMBY/emby/system/info/public" 2>/dev/null)
    local CODE=${R%% *}; local TTFB=${R##* }
    if [ "$CODE" = 200 ]; then
      OK=$((OK+1))
      num_lt "$TTFB" "$BEST_TTFB" && BEST_TTFB=$TTFB
    fi
  done
  echo "  成功率: $OK/5   最优 TTFB: ${BEST_TTFB}s"
  if [ $OK -eq 0 ]; then
    if rg -qi '请求拦截|已被拦截|Just a moment|challenge' "$BODY" 2>/dev/null; then
      echo -e "  ${C_Y}⚠ 源站 WAF 拦截探测请求（页面: 请求拦截/challenge）${C_0}"
      echo -e "  ${C_Y}  → 不代表封地区; 真实 Emby 客户端带正常 UA/参数可能可过${C_0}"
    else
      echo "  响应体: $(head -c 120 "$BODY" 2>/dev/null)"
      echo -e "  ${C_R}✗ 全部失败: 地区封禁 / 服务异常${C_0}"
    fi
    echo -e "  ${C_BD}结论: ⚠ 受限/不可用${C_0}"; rm -f "$BODY"; return 2
  elif [ $OK -lt 5 ]; then
    echo -e "  ${C_Y}⚠ 有失败采样, 链路不稳定${C_0}"
  fi
  rm -f "$BODY"
  SCORE_OK=1
  if num_lt "$BEST_TTFB" 0.5; then
    SCORE_OK=2; echo -e "  ${C_G}✓ 源站可达且响应快${C_0}"
  else
    echo -e "  ${C_Y}⚠ 可达但响应偏慢${C_0}"
  fi

  # 3. 媒体带宽
  if [ -n "$MEDIA" ]; then
    echo -e "${C_B}◆ 媒体带宽（8秒采样）${C_0}"
    local SP=$(curl -o /dev/null -s -w "%{speed_download}" --max-time 8 -r 0-60000000 "$MEDIA" 2>/dev/null)
    if [ -n "$SP" ] && num_lt 0 "$SP"; then
      $PY -c "
sp=$SP; mbps=sp*8/1e6; mbs=sp/1e6
print(f'  {mbps:.1f} Mbps ({mbs:.1f} MB/s)')
if   mbps>=120: print('  ${C_G}✅ 4K/HDR 无压力${C_0}')
elif mbps>=50:  print('  ${C_G}✅ 4K 可用${C_0}')
elif mbps>=25:  print('  ${C_Y}⚠ 1080p 稳, 4K 勉强${C_0}')
elif mbps>=8:   print('  ${C_Y}⚠ 1080p 勉强${C_0}')
else:           print('  ${C_R}❌ 只能 720p 以下${C_0}')"
    else
      echo -e "  ${C_Y}⚠ 带宽测速失败（URL 失效或无大文件）${C_0}"
    fi
  fi

  # 4. 本机资源
  echo -e "${C_B}◆ 本机资源${C_0}"
  echo "  CPU: $(nproc 2>/dev/null || echo '?') 核   负载: $(cut -d' ' -f1 /proc/loadavg 2>/dev/null)"
  awk '/MemTotal/{t=$2}/MemAvailable/{a=$2} END{if(t)printf "  内存: %.0fMB 可用 / %.0fMB\n",a/1024,t/1024}' /proc/meminfo 2>/dev/null
  df -h / | awk 'NR==2{print "  磁盘: "$4" 可用 ("$5" 用)"}'

  local VERDICT="✗ 不可用"
  [ $SCORE_OK -ge 1 ] && VERDICT="✓ 可用"
  [ $SCORE_OK -ge 2 ] && VERDICT="✓ 可用 (优秀)"
  echo -e "${C_BD}结论: ${VERDICT}  TTFB=${BEST_TTFB}s  TCP=${BEST_TCP}s${C_0}"
  return 0
}

# ---------- 主循环 + 汇总 ----------
declare -a RESULTS=()
for EMBY in "${ADDRS[@]}"; do
  probe_one "$EMBY"
  R=$?
  TTFB=$(curl -o /dev/null -s -w "%{time_starttransfer}" --max-time 8 "$EMBY/emby/system/info/public" 2>/dev/null)
  RESULTS+=("$R|$TTFB|$EMBY")
done

echo; echo -e "${C_BD}${LINE}${C_0}"
echo -e "${C_BD}◈ 汇总排名（可用优先, TTFB 小者优）${C_0}"
echo "$LINE"
printf "%s\n" "${RESULTS[@]}" | sort -t'|' -k1,1n -k2,2g | while IFS='|' read -r code ttfb url; do
  if [ "$code" = "0" ]; then
    echo -e "  ${C_G}✓${C_0} $url  TTFB=${ttfb}s"
  elif [ "$code" = "2" ]; then
    echo -e "  ${C_Y}⚠${C_0} $url  WAF 拦截探测（客户端可能可用）"
  else
    echo -e "  ${C_R}✗${C_0} $url  不可用"
  fi
done
echo "$LINE"
echo -e "  提示: 带真实媒体测带宽加  export PROBE_MEDIA=\"https://.../file.mkv\""
