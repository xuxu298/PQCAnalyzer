# Huong dan Su dung (Tieng Viet)

## Cai dat

### Yeu cau

- Python 3.10 tro len
- pip

### Cai dat co ban

```bash
git clone https://github.com/xuxu298/PQCAnalyzer.git
cd PQCAnalyzer
pip install -e .
```

### Cai dat day du

```bash
pip install -e ".[all]"
```

### Phu thuoc tuy chon

```bash
pip install -e ".[dev]"        # Cong cu phat trien (pytest, ruff, mypy)
pip install -e ".[web]"        # FastAPI backend
pip install -e ".[report]"     # Bao cao PDF (WeasyPrint)
pip install -e ".[benchmark]"  # Benchmark PQC (liboqs)
```

## Lenh CLI

### Quet he thong

```bash
# Quet TLS endpoint
pqc-analyzer scan tls example.vn --port 443 --output ketqua.json

# Quet cau hinh SSH
pqc-analyzer scan ssh /etc/ssh/sshd_config

# Quet cau hinh VPN
pqc-analyzer scan vpn /etc/openvpn/server.conf
pqc-analyzer scan vpn /etc/wireguard/wg0.conf

# Quet source code
pqc-analyzer scan code ./src --output ketqua_code.json

# Quet cau hinh web server (nginx, apache, haproxy)
pqc-analyzer scan config /etc/nginx/nginx.conf
```

### Benchmark

```bash
# Benchmark KEM (Kyber vs RSA/ECDH)
pqc-analyzer benchmark kem --iterations 1000

# Benchmark chu ky so (Dilithium vs RSA/ECDSA)
pqc-analyzer benchmark sign --iterations 1000

# Tat ca benchmark
pqc-analyzer benchmark all

# Thong tin phan cung
pqc-analyzer benchmark hardware
```

### Tao lo trinh chuyen doi

```bash
# Tao lo trinh tu ket qua quet
pqc-analyzer roadmap generate --findings ketqua.json --org "Cong ty ABC"

# Xuat tieng Viet
pqc-analyzer roadmap generate --findings ketqua.json --language vi
```

### Tao bao cao

```bash
# Bao cao HTML
pqc-analyzer report html --findings ketqua.json -o baocao.html

# Xuat JSON
pqc-analyzer report json --findings ketqua.json -o baocao.json

# SARIF cho CI/CD
pqc-analyzer report sarif --findings ketqua.json -o baocao.sarif

# Tom tat dieu hanh
pqc-analyzer report summary --findings ketqua.json --language vi
```

## API Server

```bash
# Khoi dong server
uvicorn src.api.main:app --reload --port 8000

# Tai lieu API tai http://localhost:8000/docs
```

## Giao dien Web

```bash
cd web
npm install
npm run dev
# Mo http://localhost:5173
```

## Docker

```bash
# Chi API
docker compose up

# API + Giao dien Web
docker compose --profile web up
```

## Hieu ket qua

### Muc do rui ro

| Muc | Y nghia |
|-----|---------|
| CRITICAL | Thuat toan bi luong tu tan cong, dich vu internet-facing. Can xu ly ngay. |
| HIGH | Bi luong tu tan cong hoac thuat toan co dien da yeu. Uu tien cao. |
| MEDIUM | Yeu nhung chua bi pha. Nang cap khi co co hoi. |
| LOW | Chap nhan duoc nhung chua toi uu. Theo doi. |
| SAFE | An toan truoc luong tu hoac ma hoa doi xung manh (AES-256). |

### Cac giai doan chuyen doi

| Giai doan | Thoi gian | Noi dung |
|-----------|-----------|----------|
| 0: Danh gia | 0-3 thang | Kiem ke va danh gia rui ro |
| 1: Hanh dong nhanh | 3-6 thang | Bat hybrid KEX, nang cap cipher yeu |
| 2: Chuyen doi chinh | 6-18 thang | VPN, code, chuan bi chung chi |
| 3: PQC toan dien | 18-36 thang | Chuyen doi chung chi hoan toan sang PQC |

## Xu ly loi

**"ModuleNotFoundError: No module named 'liboqs'"**
Cai dat: `pip install -e ".[benchmark]"`

**"Connection refused" khi goi API**
Dam bao API dang chay: `uvicorn src.api.main:app --port 8000`

**"WeasyPrint not found"**
Cai dat: `pip install -e ".[report]"` va `apt install libpango-1.0-0 libharfbuzz0b`
