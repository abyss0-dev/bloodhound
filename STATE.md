# Trusted static USDT collectors: 作業状態

最終更新: 2026-08-01  
対象 PR: [#40](https://github.com/abyss0-dev/bloodhound/pull/40)  
ブランチ: `agent/trusted-static-usdt-collectors`

このファイルは再開時のための事実メモである。推測を確定事項として扱わない。

## Goal

信頼する静的 USDT プローブだけを in-tree レジストリから収集する。対象 ELF のパス・アーキテクチャ・Build ID と `.note.stapsdt` ABI を検証し、許可済み static probe のイベントを eBPF の `EVENTS` ring buffer から userspace の `deserialize()` を経て NDJSON まで届ける。

完了条件は以下である。

- `training-shell-v3` と独立した `training-peer-v1` が期待する USDT NDJSON を出す。
- semaphore 付き `training-shell-v3` が attach され、probe 発火後に NDJSON を出す。
- 非許可 Build ID、欠落 probe、未対応 ABI／アーキテクチャ、必須引数読出し失敗を構造化診断で扱う。
- 複数 static location を `attach_point_id` 付きで扱う。
- 通常 CI、USDT unit/replay、KVM E2E が current PR head で成功する。

## 解決した問題

### Ring buffer consumer readiness

`BPF programs loaded and attached` は BPF attach 直後、ring buffer consumer が Tokio reactor に登録される前に出ていた。E2E はこの marker を readiness boundary として fixture を実行するため、再起動直後の singleton event が次の発火まで userspace に届かない場合があった。

修正後は consumer が `AsyncFd` を生成したことを oneshot で main に通知し、その後に marker を出す。consumer は待機前にも ring buffer を drain し、登録前後に入った pending record を回収する。

### E2E NDJSON observation load

通常 reader は polling 1回ごとに NDJSON 全体を SCP して全行を parse していた。長い suite では約11 MB／5.8万行を100 ms間隔で読み直し、観測処理自身が I/O 負荷と timeout を作っていた。

修正後は test 開始時の line baseline 以降だけを remote `tail` で読む。service の出力は再起動後も offset を保つ `StandardOutput=append:` とし、baseline と追記位置を一致させる。

### Semaphore fixture ELF layout

semaphore symbol は `.bss` にあり ELF の file-backed 範囲外だったため、kernel の `ref_ctr_offset` に登録できなかった。symbol を writable な `.probes` `PROGBITS` section に置き、実ファイル offset を持たせた。

## ローカル検証結果

2026-08-01 の最終差分に対して以下を確認した。

- Docker release build: 成功。
- focused USDT E2E: `11 passed`。
- `shutdown -> automatic restart -> training-shell-v3` 反復: 5/5 成功。
- 全 KVM E2E: `53 passed in 464.95s`。
- USDT unit: `9 passed; 0 failed`。
- 変更した Rust file の rustfmt check: 成功。
- `git diff --check`: 成功。

workspace 全体の `cargo fmt --check` は今回触っていない既存 Rust file が現 toolchain の rustfmt と一致せず失敗するため、差分外を一括整形していない。

## 残作業

- 最終差分を commit/push する。
- PR #40 の current head で通常 CI、USDT unit/replay、KVM E2E がすべて成功することを確認する。

## 実装上の境界

- 設定から BPF/native code、任意 offset、provider/probe、operand、field mapping を与えない。選択できるのは登録済み collector ID と `enabled` だけである。
- static USDT operand は通常の関数 ABI ではなく GAS operand として扱う。
- fixture → static probe → `EVENTS` → `deserialize()` → NDJSON の E2E を成功条件とし、attach log や unit test だけで完了としない。
- VM の fixture 差替え・service restart を行うテストは並列実行しない。失敗時にも canonical fixture、service、backup 不在を `finally` で復旧する。
- BPF `run_cnt` は guest の `kernel.bpf_stats_enabled` に依存するため acceptance evidence に使わない。
