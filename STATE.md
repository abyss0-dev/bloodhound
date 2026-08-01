# Trusted static USDT collectors: 作業状態

最終更新: 2026-08-01  
対象 PR: [#40](https://github.com/abyss0-dev/bloodhound/pull/40)  
ブランチ: `agent/trusted-static-usdt-collectors`  
基準コミット: `5a7170a` (`docs: update USDT goal status`)

このファイルは再開時のための事実メモである。推測を確定事項として扱わない。

## Goal

信頼する静的 USDT プローブだけを in-tree レジストリから収集する。対象 ELF のパス・アーキテクチャ・Build ID と `.note.stapsdt` ABI を検証し、許可済み static probe のイベントを eBPF の `EVENTS` ring buffer から userspace の `deserialize()` を経て NDJSON まで届ける。

完了には少なくとも以下が必要である。

- `training-shell-v3` と独立した `training-peer-v1` がそれぞれ期待する USDT NDJSON を E2E で出す。
- semaphore 付き `training-shell-v3` が attach され、実際に probe を発火して NDJSON を出す。
- 非許可 Build ID、欠落 probe、未対応 ABI／アーキテクチャ、必須引数読出し失敗を構造化診断で扱う。
- 複数 static location を `attach_point_id` 付きで扱う。
- GitHub-hosted の通常 CI、USDT unit/replay、KVM 専用 E2E がすべて成功する。

## 現在の検証結果

最新の GitHub Actions（2026-07-30、`5a7170a`）:

| workflow | 結果 | 根拠 |
| --- | --- | --- |
| CI | 成功 | run `30510779772` |
| USDT Unit and Replay Tests | 成功 | run `30510779774` |
| KVM E2E Tests | 失敗 | run `30510779775`: 51 passed, 2 failed |

通常の `training-shell-v3`、診断、複数 location、Build ID／ABI 検証を含む 51 E2E は通っている。未達は以下の二経路だけである。

### Blocker 1: `training-peer-v1` の userspace 到達

確定した観測:

- collector は attach 済みで、fixture 実行後に peer uprobe の `USDT_HIT_COUNT` slot 1 が増える。
- 同じ実行で `EVENTS.output()` 成功を記録する slot 3 も増える。
- その後 15 秒待っても `abyss0_peer.task_finished` の NDJSON がない。

したがって、現時点の blocker は peer の attach または ring buffer への eBPF 出力ではない。ring buffer の userspace 消費、`deserialize()`、または NDJSON 出力・観測のどこで peer event が失われるかを実データで特定する必要がある。

まだ未確定の事項:

- ring buffer consumer が peer record を受け取っていないのか。
- consumer は受け取るが、event header/payload の整合性で deserialize が失敗しているのか。
- deserialize は成功するが、出力先または E2E の fresh NDJSON reader で失われるのか。

次の作業は、この経路に限って受信・deserialize・出力の境界を観測できるようにすることである。semaphore の実装修正と同時には行わない。

### Blocker 2: semaphore 付き static probe が発火しない

確定した観測:

- semaphore fixture に差し替えて daemon を再起動すると、`BPF programs loaded and attached` が出る。
- fixture 実行後も shell collector の `USDT_HIT_COUNT` slot 0 は全 CPU で 0 のままである。
- したがって NDJSON や deserialize より前、semaphore 用 perf-event uprobe attach 経路が実際の probe 発火につながっていない。

現在の実装は `bloodhound/src/usdt.rs` の `attach_uprobe_with_semaphore()` で `perf_event_open`、`PERF_EVENT_IOC_SET_BPF`、`PERF_EVENT_IOC_ENABLE` を使う。次は peer を解決後、この経路の perf event 属性、semaphore file offset、カーネルが登録した event の順に一項目ずつ検証する。

## 既に試し、結論が出たこと

- `bpftool` の BPF `run_cnt` で発火を測る案: 使用不可。guest で `kernel.bpf_stats_enabled` を設定しようとすると exclusivity flag により変更できず、`run_cnt` が出なかった。現在は guest グローバル設定に依存しない `USDT_HIT_COUNT` を使用する。
- semaphore perf event attribute を小さな独自構造体で渡す案: 不十分だった。Aya と同じ 128 byte の `perf_event_attr` ABI に修正したが、semaphore probe はなお発火しない。
- peer が ring buffer に書けないという仮説: 否定された。slot 3 が増えるため `EVENTS.output()` は成功している。
- peer attach 失敗という仮説: 否定された。slot 1 が増えるため、静的 probe の uprobe は実行されている。

## 過去の勘違いと訂正

- **`systemctl is-active` を daemon 準備完了と見なした。** `Type=simple` では process 起動しか保証しない。現在のE2Eは current daemon PID の journal に正確な `BPF programs loaded and attached` が出るまで待つ。
- **再起動後も通常の NDJSON 行数基準を再利用した。** `StandardOutput=file:` の再起動で捕捉状態が壊れる。現在は fixture 差替えごとに空の NDJSON を用意し、fresh reader で待つ。
- **BPF program `run_cnt` を普遍的な観測手段と考えた。** guest の BPF stats 設定に依存するため、このVMでは使えない。
- **peer のイベント不達を attach／ring buffer 出力の失敗と推定した。** collector 内の二段階カウンタにより、両方成功していると判明した。
- **semaphore の attach 完了ログを発火の証拠と扱った。** 現在の hit counter は、attach success と実際の uprobe 実行が別であることを示している。

## 実装上の留意点

- 設定から BPF/native code、任意 offset、provider/probe、operand、field mapping を与えない。選択できるのは登録済み collector ID と `enabled` だけである。
- static USDT operand は通常の関数 ABI ではなく GAS operand として扱う。
- fixture → static probe → `EVENTS` → `deserialize()` → NDJSON の E2E を成功条件とし、attach ログや unit test だけで完了としない。
- VM の fixture 差替え・service restart を行うテストは並列実行しない。失敗時にも canonical fixture、service、backup 不在を `finally` で復旧する。
