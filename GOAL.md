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

通常 CI と USDT ユニット／リプレイは成功している。KVM E2E では通常の `training-shell-v3` イベントは成功し、残る peer と semaphore の 2 件でイベント不達を調査中である。

- peer: uprobe の実行回数は増えるため attach 自体はできている。しかし NDJSON が得られない。今回、eBPF 内の collector hit と `EVENTS.output()` の成功回数を別スロットで記録し、ring buffer への出力成功か、その後の経路かを判別する。
- semaphore: fixture の静的プローブを発火しても collector hit が増えない。通常の uprobe の ABI と分離した semaphore 付き perf event attach 経路に原因を絞っている。

以前試した `bpftool` の `run_cnt` は、VM が BPF 実行統計を排他的に設定できず観測手段として使えなかった。そのため、ゲストのグローバル設定に依存しない collector 内カウンタへ置き換えた。

## 現在進行中の試行

`212c20f` (`test(usdt): distinguish peer ring buffer output`) を push 済み。これが現在 GitHub Actions で検証中である。

- `USDT_HIT_COUNT` map の slot 1 で peer uprobe の実行を、slot 3 で peer の `EVENTS.output()` 成功を、fixture 実行前後で比較する。
- slot 3 が増えなければ peer のイベント組み立て／ring buffer 出力を調べる。増えるのに NDJSON がなければ userspace の ring buffer 消費・デシリアライズ経路を調べる。
- semaphore は peer の判定を終えてから、hit が増えない attach／perf event／semaphore 経路だけを一つずつ検証する。

この試行の CI、USDT ユニット／リプレイ、KVM E2E を監視し、失敗した経路だけを次に修正する。

## 次の判断

この E2E のログに基づき、一度に一つの経路だけを修正して再実行する。すべての完了条件を満たすまでは、CI の結果と失敗ログを監視する。
