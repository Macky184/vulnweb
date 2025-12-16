# vulnweb

C 言語で実装した **意図的に脆弱な Web サーバ** を用いて、
**PIE / ASLR / Stack Canary** の挙動を

* 実際のメモリアドレス
* `/proc/self/maps`
* gdb による実体確認
* クラッシュログ

を通して学習・検証するための教材プロジェクトです。

本リポジトリは、脆弱性理解を目的として作成されています。

---

## 特徴

* Docker により **環境依存なく再現可能**
* `/debug` エンドポイントで

  * 関数アドレス
  * stack / heap / global の配置
  * ASLR 状態
  * `/proc/self/maps`
    を可視化
* `/smash` エンドポイントで

  * Stack Buffer Overflow を意図的に発生
  * **Canary OFF / ON の挙動差**を実体験
* **PIE / non-PIE / Canary** を比較可能

---

## 検証環境

* macOS (Apple Silicon)
* Docker / Docker Compose
* Ubuntu 22.04 (aarch64)
* gcc

---

## ディレクトリ構成

```
vulnweb/
├── backend/
│   ├── Dockerfile
│   ├── src/
│   │   └── main.c
│   └── pages/
│       └── index.html
├── docker-compose.yml
└── README.md
```

---

## 起動方法

```bash
docker compose build --no-cache
docker compose up
```

起動後、以下のポートでアクセスできます。

| ポート  | 構成                                        |
| ---- | ----------------------------------------- |
| 8080 | non-PIE / Canary OFF                      |
| 8081 | PIE / Canary OFF                          |
| 8082 | PIE / Canary ON (`-fstack-protector-all`) |

---

## `/debug` : メモリ配置の可視化

```bash
curl http://localhost:8080/debug
```

### 表示内容

* `main`, `debug_dump` の関数アドレス
* グローバル変数のアドレスと値
* スタックローカル変数のアドレス
* ヒープ領域のアドレス
* ASLR 状態 (`/proc/sys/kernel/randomize_va_space`)
* `/proc/self/maps` 抜粋

### 観察ポイント

* **no-PIE** では `/app/vuln_server` が `0x00400000` 付近に固定
* **PIE** では `/app/vuln_server` のベースアドレスが毎回変化
* stack / heap / libc は ASLR により高位アドレスに配置

---

## `/smash` : Stack Canary の検証

```bash
curl "http://localhost:8082/smash?len=200"
```

### 実装概要

```c
__attribute__((noinline))
static void smash(int len) {
    volatile char buf[64];
    memset((void*)buf, 'A', (size_t)len);
}
```

* 固定長バッファ `buf[64]` を意図的に越えて書き込み
* Stack Canary を破壊

### 挙動比較

| 構成         | 結果                                         |
| ---------- | ------------------------------------------ |
| Canary OFF | 挙動不定 / 通過することもある                           |
| Canary ON  | `*** stack smashing detected ***` で即 abort |

クライアント側では以下のようになります。

```text
curl: (52) Empty reply from server
```

---

## Stack Canary の実体確認（gdb）

### gdb のインストール（コンテナ内）

```bash
apt-get update
apt-get install -y gdb
```

### Canary の値を確認

```gdb
(gdb) break main
(gdb) run
(gdb) p/x __stack_chk_guard
```

例:

```text
0x43d07816b4df4200
```

* これは **TLS (Thread Local Storage)** に保存されている比較用 canary
* スタック上にはこの **コピー** が配置される

### 重要事項

* `&__stack_chk_guard` が示すアドレスは TLS 記述子
* 実行時の実メモリアドレスとは一致しない（正常な挙動）

---

## 技術的ポイント

* Stack Canary は **スタックに本体があるわけではない**
* 比較用の値は TLS に保存される
* スタック破壊自体は防げないが、**制御フロー破壊前に検知して abort** する
* `-fstack-protector-strong` では挿入されない関数が存在する
* 教材用途では `-fstack-protector-all` が確実

---

## 注意事項

* 本リポジトリは **学習目的専用**です
* 実運用環境や第三者システムに対して使用しないでください

---

## まとめ

* PIE / ASLR / Canary はそれぞれ役割が異なる
* 多層防御で初めて意味を持つ
* **実際に壊して、落ちて、アドレスを見る**ことで理解が深まる

---

## ライセンス

Educational Use Only
