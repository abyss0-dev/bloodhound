# システム設計と不変条件（System Design）

本ディレクトリでは、システムアーキテクチャおよびドメインモデルの長期的な破綻を抑止するための**構造設計および不変条件に関する基本原則**を定義する。

## 原則一覧

* [現在の確実性のレベルで設計する (Design at the Current Level of Certainty)](design-at-current-certainty.md)  
  確定済みの既知事実には厳格に対処し、未確定の事項には寛容に対処する。
  早期の過度な解釈を避け情報の保存（来歴）を優先し、将来要件のための余白を意図して維持する。
* [要件と不変条件 (Requirements and Invariants)](requirements-and-invariants.md)  
  機能要件および非機能要件を、システムが常時保護すべき「不変条件」へと変換して設計を確立する。
* [唯一の事実源 (Single Source of Truth)](single-source-of-truth.md)  
  すべての宣言的事実と解釈に唯一の所有者を割り当て、並行した第2の権威や重複コピーの作成を排除する。
* [あるべき姿を宣言し、自律的に差分を収束させる (Declarative and Reconciliation)](declarative-and-reconciliation.md)  
  命令的な逐次手順を排し、目標状態をデータとして宣言してシステム自身に継続的な差分解消を実行させる。
* [疎結合と高凝集 (Loose Coupling and High Cohesion)](loose-coupling-and-high-cohesion.md)  
  密接に関連する責務を集約し、外部コンポーネントが依存すべき公開契約を最小限に限定する。
* [削除と意図的な不在 (Deletion and Deliberate Absence)](deletion-and-deliberate-absence.md)  
  重複した機構を削除して責任の連鎖を明確化し、あえて実装しなかった根拠（意図的な不在）を記録する。
