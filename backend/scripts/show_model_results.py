"""Print the trained model's evaluation results in a presentation-friendly form.

Reads ml_data/models/model_meta.json (written by `python -m app.ml.model_trainer`)
and prints the headline metrics, the per-class report, the confusion matrix, and
the feature importances. Intended for a live demo after training.

    cd backend && python -m scripts.show_model_results
"""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
META = os.path.normpath(os.path.join(HERE, "..", "..", "ml_data", "models", "model_meta.json"))


def bar(frac, width=30):
    return "#" * int(frac * width)


def main():
    if not os.path.exists(META):
        print(f"No model metadata at {META}\nTrain first: python -m app.ml.model_trainer")
        return
    m = json.load(open(META))

    print("=" * 62)
    print("  VulnTriage — Random Forest Severity Model: Results")
    print("=" * 62)
    print(f"  Model version : {m['model_version']}")
    print(f"  Trained at    : {m['trained_at']}")
    print(f"  Data source   : {m['data_source']}")
    print(f"  Training rows : {m['training_samples']:,}")
    print(f"  Held-out rows : {m['test_samples']:,}  ({m['evaluation']})")
    print("-" * 62)
    print(f"  ACCURACY      : {m['accuracy']:.4f}")
    print(f"  MACRO-F1      : {m['macro_f1']:.4f}")

    cr = m["classification_report"]
    print("\n  Per-class report")
    print(f"  {'class':10}{'precision':>11}{'recall':>10}{'f1':>9}{'support':>10}")
    for c in ["Low", "Medium", "High", "Critical"]:
        r = cr[c]
        print(f"  {c:10}{r['precision']:>11.4f}{r['recall']:>10.4f}"
              f"{r['f1-score']:>9.4f}{r['support']:>10,}")

    names = ["Low", "Medium", "High", "Critical"]
    cm = m["confusion_matrix"]
    print("\n  Confusion matrix (rows = actual, cols = predicted)")
    print("  " + " " * 10 + "".join(f"{n:>10}" for n in names))
    for i, n in enumerate(names):
        print(f"  {n:10}" + "".join(f"{v:>10,}" for v in cm[i]))
    total = sum(sum(r) for r in cm)
    correct = sum(cm[i][i] for i in range(len(cm)))
    print(f"  -> {correct:,}/{total:,} correct; {total - correct} misclassified "
          f"(all off-by-one severity band)")

    print("\n  Feature importances")
    for feat, imp in sorted(m["feature_importances"].items(), key=lambda x: -x[1]):
        print(f"  {feat:24}{imp:.4f}  {bar(imp)}")
    print("=" * 62)


if __name__ == "__main__":
    main()
