#!/bin/bash
# setup-wireguard-test.sh

# 기존 인터페이스 정리
echo "Cleaning up..."
sudo ip link delete wg0 2>/dev/null
sudo ip link delete wg1 2>/dev/null

# 키 생성 (파일로 저장)
echo "Generating keys..."
wg genkey | tee /tmp/server.key | wg pubkey > /tmp/server.pub
wg genkey | tee /tmp/client.key | wg pubkey > /tmp/client.pub

SERVER_PUB=$(cat /tmp/server.pub)
CLIENT_PUB=$(cat /tmp/client.pub)

echo "Server Public Key: $SERVER_PUB"
echo "Client Public Key: $CLIENT_PUB"

# 서버 설정
echo "Setting up server..."
sudo ip link add dev wg0 type wireguard
sudo wg set wg0 listen-port 51820 private-key /tmp/server.key
sudo wg set wg0 peer "$CLIENT_PUB" allowed-ips 10.0.0.2/32
sudo ip addr add 10.0.0.1/24 dev wg0
sudo ip link set wg0 up

# 클라이언트 설정
echo "Setting up client..."
sudo ip link add dev wg1 type wireguard
sudo wg set wg1 private-key /tmp/client.key
sudo wg set wg1 peer "$SERVER_PUB" endpoint 127.0.0.1:51820 allowed-ips 0.0.0.0/0
sudo ip addr add 10.0.0.2/24 dev wg1
sudo ip link set wg1 up

# 테스트
sleep 1
echo "Testing connection..."
ping -c 2 10.0.0.1

# 상태 확인
echo -e "\n=== WireGuard Status ==="
sudo wg show

# 정리
rm -f /tmp/server.key /tmp/client.key /tmp/server.pub /tmp/client.pub
