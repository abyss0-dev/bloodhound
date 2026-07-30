# Trusted static USDT collectors: 現状とゴール

対象 PR: [#40](https://github.com/abyss0-dev/bloodhound/pull/40)  
作業ブランチ: `agent/trusted-static-usdt-collectors`

## 達成すべきゴール

信頼する静的 USDT プローブだけを in-tree のレジストリから収集し、対象バイナリの Build ID と `.note.stapsdt` の ABI を検証したうえで、イベントを ring buffer から NDJSON まで安全に届ける。

完了条件は次のとおり。

- `training-shell-v3` と独立した `training-peer-v1` の両方が、対応する USDT イベントを E2E で出力する。
- semaphore を持つ `training-shell-v3` の静的プローブも、添付とイベント出力を E2E で確認できる。
- 不許可 Build ID、欠落プローブ、未対応 ABI、未対応アーキテクチャ、読み出せない必須引数は、イベントを部分出力せず構造化した診断として扱う。
- 複数の一致する静的ロケーションは、それぞれの `attach_point_id` を保って出力する。
- GitHub-hosted runner で通常 CI と USDT ユニット／リプレイを実行し、KVM が必要な E2E は専用 workflow に分離する。
- PR #40 の CI、USDT ユニット／リプレイ、KVM E2E がすべて成功する。

## 現状

実装、fixture、USDT ユニット／リプレイ、通常 CI は揃っている。GitHub-hosted runner への移行と、KVM E2E workflow の分離も完了している。

直前の KVM E2E では 51 件が成功し、残る peer と semaphore の 2 件はイベント不達を調べるために追加した BPF 実行回数診断が不完全だったため失敗した。

- peer: `bpftool` の出力に `run_cnt` がなかった。VM で `kernel.bpf_stats_enabled` を有効化していなかった。
- semaphore: 診断が `usdt_training_s` を探していたが、ロードされるプログラム名は `usdt_training_shell_v3_0` である。

このため、この時点では peer／semaphore のイベント不達が実装に起因するかをまだ断定しない。診断自身の失敗を先に除去した。

## 現在進行中の試行

`4febe20` (`test(usdt): enable BPF execution diagnostics`) を push 済み。

- E2E VM の `bloodhound.service` 起動前に `kernel.bpf_stats_enabled=1` を設定する。
- `bpftool -j prog show` から peer と semaphore の BPF プログラム実行回数を、実際のプログラム名で取得する。
- fixture 実行前後の実行回数を比較する。増えなければ attach／perf event／semaphore 経路を調べ、増えるのに NDJSON がなければ eBPF のイベント組み立て・ring buffer・デシリアライズ経路を調べる。

GitHub Actions run `30504329636` の KVM E2E がこの診断変更を実行中。通常 CI (`30504329635`) と USDT ユニット／リプレイ (`30504329639`) は成功している。

## 次の判断

この E2E のログに基づき、一度に一つの経路だけを修正して再実行する。すべての完了条件を満たすまでは、CI の結果と失敗ログを監視する。
