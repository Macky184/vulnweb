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

* Docker により 環境依存なく再現可能
* `/debug` エンドポイントで

  * 関数アドレス
  * stack / heap / global の配置
  * ASLR 状態
  * `/proc/self/maps`
    を可視化
* `/smash` エンドポイントで

  * Stack Buffer Overflow を意図的に発生
  * Canary OFF / ON の挙動差を実体験
* PIE / non-PIE / Canary を比較可能

---

## 検証環境

* macOS (Apple Silicon)
* Docker / Docker Compose
* Ubuntu 22.04 (aarch64)

---

## 起動方法

```bash
docker compose build --no-cache
docker compose up
```

起動後、以下のポートでアクセスできます。

| ポート  | 構成                                        |
| ---- | ----------------------------------------- |
| 8080 | ASLR OFF / PIE OFF / Canary OFF                      |
| 8081 | ASLR ON / PIE OFF / Canary OFF                          |
| 8081 | ASLR ON / PIE ON / Canary OFF                          |
| 8083 | PIE / Canary ON (`-fstack-protector-all`) |

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

## `/canary` : Stack Canary の検証

```bash
curl http://localhost:8082/canary
```


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


## 注意事項

* 本リポジトリは 学習目的専用です
* 実運用環境や第三者システムに対して使用しないでください

---

## まとめ

* PIE / ASLR / Canary はそれぞれ役割が異なる
* 多層防御で初めて意味を持つ
* 実際に壊して、落ちて、アドレスを見ることで理解が深まる

---

## ライセンス

Educational Use Only
