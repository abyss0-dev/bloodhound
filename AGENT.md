# Repository agent contract

このリポジトリを変更するエージェントは、変更対象に必要なコマンドを非対話 shell から実行できる状態に保ってください。

## GitHub Actions

`.github/workflows/` 配下を作成または変更する前に、`.github/workflows/AGENT.md` を読んで従ってください。

外部 Action と reusable workflow の参照は、mise で管理する pinact を使って40文字の commit SHAに固定します。
tag、branch、短縮SHAをチェックインしてはいけません。

## Repository settings

GitHub 上の設定を適用する場合は、リポジトリのルートで次を実行します。

```sh
./setup-repository.sh
```

設定ドリフトだけを確認する場合は、次を実行します。

```sh
./setup-repository.sh --check
```

スクリプトが拒否した owner、visibility、default branch を推測で変更してはいけません。

## Project commands

テンプレートから生成したリポジトリは、実装を追加するときに Setup、Build、Test、Check の正規コマンドをこの節へ記録してください。
